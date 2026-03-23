package p2p

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/consensus"
	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/rpc"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

/* -------------------------------------------------------------------------- */
/*                              PEER MANAGER                                   */
/* -------------------------------------------------------------------------- */

const (
	MaxPeers          = 200
	HeartbeatInterval = 30 * time.Second
	PeerTimeout       = 10 * time.Second
	SyncBatchSize     = 100   // blocks per sync request
	MaxSyncRetries    = 3
	DeadPeerThreshold = 3     // consecutive failures before removal
)

// PeerInfo tracks peer status.
type PeerInfo struct {
	Addr     string        `json:"addr"`
	Height   int           `json:"height"`
	LastSeen time.Time     `json:"last_seen"`
	Failures int           `json:"failures"`
	Latency  time.Duration `json:"latency_ms"`
	BanScore int           `json:"ban_score"`
	Version  int           `json:"version"`
}

// PeerManager handles peer discovery, heartbeat, and removal.
type PeerManager struct {
	mu         sync.RWMutex
	peers      map[string]*PeerInfo
	ns         *rpc.NodeState
	client     *http.Client
	seeds      []string // seed node addresses
	stopCh     chan struct{}
	SeenBlocks *SeenCache // dedup block broadcasts
	SeenTxs    *SeenCache // dedup TX broadcasts
}

// NewPeerManager creates and starts the peer manager.
func NewPeerManager(ns *rpc.NodeState, seeds []string) *PeerManager {
	pm := &PeerManager{
		peers:      make(map[string]*PeerInfo),
		ns:         ns,
		client:     &http.Client{Timeout: PeerTimeout},
		seeds:      seeds,
		stopCh:     make(chan struct{}),
		SeenBlocks: NewSeenCache(10 * time.Minute),
		SeenTxs:    NewSeenCache(30 * time.Minute),
	}

	// Load existing peers from chain
	ns.Mu.Lock()
	for _, addr := range ns.Chain.Peers {
		pm.peers[addr] = &PeerInfo{Addr: addr}
	}
	ns.Mu.Unlock()

	return pm
}

// Start begins background goroutines for heartbeat and sync.
func (pm *PeerManager) Start() {
	go pm.heartbeatLoop()
	go pm.syncLoop()
	go pm.discoveryLoop()
	slog.Info("peer manager started", "known_peers", len(pm.peers), "seeds", len(pm.seeds))
}

// Stop gracefully stops the peer manager.
func (pm *PeerManager) Stop() {
	close(pm.stopCh)
}

// AddPeer registers a new peer.
func (pm *PeerManager) AddPeer(addr string) bool {
	pm.mu.Lock()
	if len(pm.peers) >= MaxPeers {
		pm.mu.Unlock()
		return false
	}
	if _, exists := pm.peers[addr]; exists {
		pm.mu.Unlock()
		return false
	}

	pm.peers[addr] = &PeerInfo{Addr: addr, LastSeen: time.Now()}
	peerList := pm.peerListLocked()
	total := len(pm.peers)
	pm.mu.Unlock()

	// Persist outside pm.mu to avoid lock ordering issues (pm.mu → ns.Mu)
	pm.ns.Mu.Lock()
	pm.ns.Chain.Peers = peerList
	pm.ns.Mu.Unlock()

	if pm.ns.DB != nil {
		pm.ns.DB.AddPeer(addr)
	}

	slog.Info("peer added", "addr", addr, "total", total)
	return true
}

// RemovePeer unregisters a peer.
func (pm *PeerManager) RemovePeer(addr string) {
	pm.mu.Lock()
	delete(pm.peers, addr)
	pm.mu.Unlock()

	pm.ns.Mu.Lock()
	newPeers := make([]string, 0)
	for _, p := range pm.ns.Chain.Peers {
		if p != addr {
			newPeers = append(newPeers, p)
		}
	}
	pm.ns.Chain.Peers = newPeers
	pm.ns.Mu.Unlock()

	slog.Info("peer removed", "addr", addr)
}

// GetPeers returns a snapshot of all active peers.
func (pm *PeerManager) GetPeers() []PeerInfo {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make([]PeerInfo, 0, len(pm.peers))
	for _, p := range pm.peers {
		out = append(out, *p)
	}
	return out
}

// GetActivePeerAddrs returns addresses of peers seen recently.
func (pm *PeerManager) GetActivePeerAddrs() []string {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	out := make([]string, 0, len(pm.peers))
	cutoff := time.Now().Add(-5 * time.Minute)
	for _, p := range pm.peers {
		if p.LastSeen.After(cutoff) || p.Failures == 0 {
			out = append(out, p.Addr)
		}
	}
	return out
}

func (pm *PeerManager) peerListLocked() []string {
	out := make([]string, 0, len(pm.peers))
	for addr := range pm.peers {
		out = append(out, addr)
	}
	return out
}

/* -------------------------------------------------------------------------- */
/*                              HEARTBEAT                                      */
/* -------------------------------------------------------------------------- */

// PeerStatus is returned by /peer/status endpoint.
type PeerStatus struct {
	Height          int      `json:"height"`
	Network         string   `json:"network"`
	Version         string   `json:"version"`
	ProtocolVersion int      `json:"protocol_version"`
	Peers           []string `json:"peers,omitempty"`
}

func (pm *PeerManager) heartbeatLoop() {
	ticker := time.NewTicker(HeartbeatInterval)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			pm.pingAllPeers()
		}
	}
}

func (pm *PeerManager) pingAllPeers() {
	pm.mu.RLock()
	addrs := make([]string, 0, len(pm.peers))
	for addr := range pm.peers {
		addrs = append(addrs, addr)
	}
	pm.mu.RUnlock()

	for _, addr := range addrs {
		go pm.pingPeer(addr)
	}
}

func (pm *PeerManager) pingPeer(addr string) {
	url := addr + "/peer/status"
	start := time.Now()

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		pm.recordFailure(addr)
		return
	}
	if pm.ns.Cfg.P2PToken != "" {
		req.Header.Set(core.P2PAuthHeader, pm.ns.Cfg.P2PToken)
	}

	resp, err := pm.client.Do(req)
	if err != nil {
		pm.recordFailure(addr)
		return
	}
	defer resp.Body.Close()

	latency := time.Since(start)

	var status PeerStatus
	if err := json.NewDecoder(resp.Body).Decode(&status); err != nil {
		pm.recordFailure(addr)
		return
	}

	// Verify same network
	if status.Network != "" && status.Network != core.NetworkName {
		slog.Warn("peer on different network, removing", "addr", addr, "network", status.Network)
		pm.AddBanScore(addr, ScoreWrongNetwork, "wrong_network")
		return
	}

	// Check protocol version compatibility
	if status.ProtocolVersion > 0 && !IsCompatibleVersion(status.ProtocolVersion) {
		slog.Warn("peer protocol incompatible", "addr", addr,
			"peer_version", status.ProtocolVersion, "min_compat", MinCompatVersion)
		pm.RemovePeer(addr)
		return
	}

	pm.mu.Lock()
	if p, ok := pm.peers[addr]; ok {
		p.Height = status.Height
		p.LastSeen = time.Now()
		p.Latency = latency
		p.Failures = 0
		p.Version = status.ProtocolVersion
	}
	pm.mu.Unlock()

	// Discover new peers from this peer's peer list
	for _, newPeer := range status.Peers {
		if core.ValidatePeerAddr(newPeer) {
			pm.AddPeer(newPeer)
		}
	}
}

func (pm *PeerManager) recordFailure(addr string) {
	pm.mu.Lock()
	p, ok := pm.peers[addr]
	if ok {
		p.Failures++
		if p.Failures >= DeadPeerThreshold {
			delete(pm.peers, addr)
			pm.mu.Unlock()
			slog.Info("dead peer removed", "addr", addr, "failures", p.Failures)
			return
		}
	}
	pm.mu.Unlock()
}

/* -------------------------------------------------------------------------- */
/*                              DISCOVERY                                      */
/* -------------------------------------------------------------------------- */

func (pm *PeerManager) discoveryLoop() {
	// Connect to seeds on startup
	pm.connectSeeds()

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			if len(pm.GetActivePeerAddrs()) < 3 {
				pm.connectSeeds()
			}
		}
	}
}

func (pm *PeerManager) connectSeeds() {
	for _, seed := range pm.seeds {
		if !core.ValidatePeerAddr(seed) {
			continue
		}
		pm.AddPeer(seed)
		go pm.pingPeer(seed)
	}
}

/* -------------------------------------------------------------------------- */
/*                              CHAIN SYNC                                     */
/* -------------------------------------------------------------------------- */

func (pm *PeerManager) syncLoop() {
	// Initial sync on startup (wait a few seconds for peers to connect)
	time.Sleep(5 * time.Second)
	pm.TrySync()

	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-pm.stopCh:
			return
		case <-ticker.C:
			pm.TrySync()
		}
	}
}

// TrySync checks if any peer has a longer chain, and syncs if needed.
func (pm *PeerManager) TrySync() {
	pm.ns.Mu.Lock()
	ourHeight := len(pm.ns.Chain.Blocks) - 1
	if ourHeight < 0 {
		ourHeight = 0
	}
	pm.ns.Mu.Unlock()

	// Find best peer
	pm.mu.RLock()
	var bestPeer string
	bestHeight := ourHeight
	for _, p := range pm.peers {
		if p.Height > bestHeight && p.Failures < DeadPeerThreshold {
			bestHeight = p.Height
			bestPeer = p.Addr
		}
	}
	pm.mu.RUnlock()

	if bestPeer == "" || bestHeight <= ourHeight {
		return // we're up to date
	}

	slog.Info("chain sync starting", "our_height", ourHeight, "peer_height", bestHeight, "peer", bestPeer)

	// First, check if we need a reorg by fetching overlapping blocks
	pm.ns.Mu.Lock()
	ourLastHash := pm.ns.Chain.Blocks[len(pm.ns.Chain.Blocks)-1].Hash
	pm.ns.Mu.Unlock()

	// Check if peer's chain at our height has same hash (no fork)
	overlapFrom := ourHeight
	if overlapFrom > 0 {
		overlapFrom = ourHeight - 5 // fetch a few blocks back to check
		if overlapFrom < 0 {
			overlapFrom = 0
		}
	}

	overlapBlocks, err := pm.fetchBlocks(bestPeer, overlapFrom, ourHeight)
	if err == nil && len(overlapBlocks) > 0 {
		lastOverlap := overlapBlocks[len(overlapBlocks)-1]
		if lastOverlap.Header.Height == ourHeight && lastOverlap.Hash != ourLastHash {
			// FORK detected! Find fork point and reorg
			slog.Warn("fork detected", "our_hash", ourLastHash[:16], "peer_hash", lastOverlap.Hash[:16])

			// Fetch more blocks to find fork point
			searchFrom := ourHeight - MaxReorgDepth
			if searchFrom < 0 {
				searchFrom = 0
			}
			peerChain, fetchErr := pm.fetchBlocks(bestPeer, searchFrom, bestHeight)
			if fetchErr != nil {
				slog.Warn("fork: fetch peer chain failed", "error", fetchErr)
				pm.recordFailure(bestPeer)
				return
			}

			pm.ns.Mu.Lock()
			forkPoint := FindForkPoint(pm.ns, peerChain)
			if forkPoint < 0 {
				pm.ns.Mu.Unlock()
				slog.Warn("fork: no common ancestor found")
				pm.recordFailure(bestPeer)
				return
			}

			// Only reorg if peer's chain is actually longer
			peerTotal := bestHeight
			ourTotal := ourHeight
			if peerTotal <= ourTotal {
				pm.ns.Mu.Unlock()
				slog.Info("fork: our chain is same length or longer, no reorg needed")
				return
			}

			// Collect new blocks (after fork point)
			var newBlocks []core.Block
			for _, b := range peerChain {
				if b.Header.Height > forkPoint {
					newBlocks = append(newBlocks, b)
				}
			}

			if err := Reorg(pm.ns, forkPoint, newBlocks); err != nil {
				pm.ns.Mu.Unlock()
				slog.Error("reorg failed", "error", err)
				pm.recordFailure(bestPeer)
				return
			}
			pm.ns.Mu.Unlock()
			slog.Info("fork resolved via reorg", "fork_point", forkPoint, "new_height", bestHeight)
			return
		}
	}

	// Normal sync (no fork) — append new blocks
	for fromH := ourHeight + 1; fromH <= bestHeight; fromH += SyncBatchSize {
		toH := fromH + SyncBatchSize - 1
		if toH > bestHeight {
			toH = bestHeight
		}

		blocks, err := pm.fetchBlocks(bestPeer, fromH, toH)
		if err != nil {
			slog.Warn("sync fetch failed", "peer", bestPeer, "from", fromH, "error", err)
			pm.recordFailure(bestPeer)
			return
		}

		pm.ns.Mu.Lock()
		applied := 0
		for _, b := range blocks {
			if consensus.ValidateBlock(pm.ns.Chain, b, pm.ns.Cfg) {
				consensus.ApplyBlock(pm.ns.Chain, b, pm.ns.Cfg)
				pm.ns.Chain.Blocks = append(pm.ns.Chain.Blocks, b)
				pm.ns.MempoolPurge(b.Txs)

				if pm.ns.DB != nil {
					pm.ns.DB.SaveBlockAndState(&b, pm.ns.Chain.State, pm.ns.Chain.TotalMinted)
				}
				applied++
			} else {
				slog.Warn("sync block rejected", "height", b.Header.Height, "peer", bestPeer)
				pm.ns.Mu.Unlock()
				pm.recordFailure(bestPeer)
				return
			}
		}
		pm.ns.Mu.Unlock()

		slog.Info("sync batch applied", "from", fromH, "to", toH, "applied", applied)
	}

	slog.Info("chain sync complete", "new_height", bestHeight)
}

// fetchBlocks requests a range of blocks from a peer.
func (pm *PeerManager) fetchBlocks(peer string, from, to int) ([]core.Block, error) {
	url := fmt.Sprintf("%s/peer/blocks?from=%d&to=%d", peer, from, to)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if pm.ns.Cfg.P2PToken != "" {
		req.Header.Set(core.P2PAuthHeader, pm.ns.Cfg.P2PToken)
	}

	resp, err := pm.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("peer returned status %d", resp.StatusCode)
	}

	var result struct {
		Blocks []core.Block `json:"blocks"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result.Blocks, nil
}

/* -------------------------------------------------------------------------- */
/*                              BROADCAST                                      */
/* -------------------------------------------------------------------------- */

// BroadcastBlock sends a new block to all active peers.
func BroadcastBlock(b core.Block, ns *rpc.NodeState) {
	// Use PeerManager if available, else fallback to old behavior
	if ns.PeerMgr != nil {
		ns.PeerMgr.(*PeerManager).broadcastBlock(b)
		return
	}

	// Legacy fallback
	data, _ := json.Marshal(b)
	ns.Mu.Lock()
	peers := make([]string, len(ns.Chain.Peers))
	copy(peers, ns.Chain.Peers)
	ns.Mu.Unlock()

	client := &http.Client{Timeout: PeerTimeout}
	for _, peer := range peers {
		peerURL := peer + "/peer/block"
		go sendToPeer(client, peerURL, data, ns.Cfg)
	}
}

func (pm *PeerManager) broadcastBlock(b core.Block) {
	data, _ := json.Marshal(b)
	addrs := pm.GetActivePeerAddrs()

	for _, addr := range addrs {
		url := addr + "/peer/block"
		go sendToPeer(pm.client, url, data, pm.ns.Cfg)
	}
}

// BroadcastTx sends a new transaction to all active peers.
func BroadcastTx(tx core.Tx, ns *rpc.NodeState) {
	if ns.PeerMgr == nil {
		return
	}
	pm := ns.PeerMgr.(*PeerManager)
	data, _ := json.Marshal(tx)
	addrs := pm.GetActivePeerAddrs()

	for _, addr := range addrs {
		url := addr + "/peer/tx"
		go sendToPeer(pm.client, url, data, pm.ns.Cfg)
	}
}

func sendToPeer(client *http.Client, url string, data []byte, cfg *core.Config) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if cfg.P2PToken != "" {
		req.Header.Set(core.P2PAuthHeader, cfg.P2PToken)
	}
	resp, err := client.Do(req)
	if err != nil {
		slog.Debug("peer send failed", "url", url, "error", err)
		return
	}
	resp.Body.Close()
}

/* -------------------------------------------------------------------------- */
/*                              P2P HANDLERS                                   */
/* -------------------------------------------------------------------------- */

func RequireP2PAuth(w http.ResponseWriter, r *http.Request, cfg *core.Config) bool {
	if cfg.P2PToken == "" {
		return true
	}
	token := r.Header.Get(core.P2PAuthHeader)
	if subtle.ConstantTimeCompare([]byte(token), []byte(cfg.P2PToken)) != 1 {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return false
	}
	return true
}

// PeerReceiveBlockHandler accepts a block from a peer.
func PeerReceiveBlockHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}
		var b core.Block
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, `{"error":"bad_json"}`, 400)
			return
		}

		// Dedup: skip already-seen blocks
		if ns.PeerMgr != nil {
			pm := ns.PeerMgr.(*PeerManager)
			if !pm.SeenBlocks.Add(b.Hash) {
				w.Write([]byte(`{"ok":true,"info":"already_seen"}`))
				return
			}
		}

		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		// Try normal append first
		if consensus.ValidateBlock(ns.Chain, b, ns.Cfg) {
			consensus.ApplyBlock(ns.Chain, b, ns.Cfg)
			ns.Chain.Blocks = append(ns.Chain.Blocks, b)
			ns.MempoolPurge(b.Txs)
			if ns.DB != nil {
				ns.DB.SaveBlockAndState(&b, ns.Chain.State, ns.Chain.TotalMinted)
			} else {
				storage.SaveChain(ns.Chain, ns.Cfg.ChainFilePath())
			}
			slog.Info("block accepted from peer", "height", b.Header.Height)
			w.Write([]byte(`{"ok":true}`))
			go BroadcastBlock(b, ns)
			return
		}

		// Block didn't validate — maybe it's on a fork?
		// Check if block height suggests a fork we should consider
		ourHeight := ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height
		if b.Header.Height > ourHeight {
			// Peer might have a longer chain — trigger sync
			slog.Info("received block at future height, triggering sync",
				"block_height", b.Header.Height, "our_height", ourHeight)
			if ns.PeerMgr != nil {
				go ns.PeerMgr.(*PeerManager).TrySync()
			}
		}

		// Ban score for invalid block
		if ns.PeerMgr != nil {
			peerAddr := r.RemoteAddr
			if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
				peerAddr = strings.Split(xff, ",")[0]
			}
			ns.PeerMgr.(*PeerManager).AddBanScore(peerAddr, ScoreInvalidBlock, "invalid_block")
		}
		http.Error(w, `{"error":"invalid_block"}`, 400)
	}
}

// PeerReceiveTxHandler accepts a transaction from a peer.
func PeerReceiveTxHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}
		var tx core.Tx
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			http.Error(w, `{"error":"bad_json"}`, 400)
			return
		}

		// Dedup via seen cache
		if ns.PeerMgr != nil {
			pm := ns.PeerMgr.(*PeerManager)
			if !pm.SeenTxs.Add(tx.Hash) {
				w.Write([]byte(`{"ok":true,"info":"already_seen"}`))
				return
			}
		}

		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		// Skip if already in mempool
		if ns.Pool != nil {
			if ns.Pool.Has(tx.Hash) {
				w.Write([]byte(`{"ok":true,"info":"known"}`))
				return
			}
		} else if rpc.MempoolHasTx(ns.Mempool, tx.Hash) {
			w.Write([]byte(`{"ok":true,"info":"known"}`))
			return
		}

		// Validate
		if !consensus.ValidateTx(ns.Chain.State, tx) {
			http.Error(w, `{"error":"rejected"}`, 400)
			return
		}

		if ns.Pool != nil {
			if !ns.Pool.Add(tx) {
				http.Error(w, `{"error":"mempool_full"}`, 503)
				return
			}
		} else {
			if len(ns.Mempool) >= ns.Cfg.MaxMempoolSize {
				http.Error(w, `{"error":"mempool_full"}`, 503)
				return
			}
			ns.Mempool = append(ns.Mempool, tx)
		}
		w.Write([]byte(`{"ok":true}`))

		// Re-broadcast to other peers (outside lock)
		go BroadcastTx(tx, ns)
	}
}

// PeerStatusHandler returns this node's status for heartbeat/discovery.
func PeerStatusHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}

		ns.Mu.Lock()
		height := 0
		if len(ns.Chain.Blocks) > 0 {
			height = ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height
		}
		// Share up to 20 peers for discovery
		peerCount := len(ns.Chain.Peers)
		if peerCount > 20 {
			peerCount = 20
		}
		sharedPeers := make([]string, peerCount)
		copy(sharedPeers, ns.Chain.Peers[:peerCount])
		ns.Mu.Unlock()

		status := PeerStatus{
			Height:          height,
			Network:         core.NetworkName,
			Version:         "2.1.0",
			ProtocolVersion: ProtocolVersion,
			Peers:           sharedPeers,
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(status)
	}
}

// PeerBlocksHandler serves a range of blocks for chain sync.
func PeerBlocksHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}

		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		var from, to int
		fmt.Sscanf(fromStr, "%d", &from)
		fmt.Sscanf(toStr, "%d", &to)

		if from < 0 || to < from || to-from > SyncBatchSize {
			http.Error(w, `{"error":"invalid_range"}`, 400)
			return
		}

		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		maxH := len(ns.Chain.Blocks) - 1
		if from > maxH {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"blocks": []core.Block{}})
			return
		}
		if to > maxH {
			to = maxH
		}

		blocks := ns.Chain.Blocks[from : to+1]

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"blocks": blocks})
	}
}

// PeerAddHandler allows adding a peer via API.
func PeerAddHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}
		addr := r.URL.Query().Get("addr")
		if addr == "" {
			http.Error(w, `{"error":"missing addr"}`, 400)
			return
		}

		if !core.ValidatePeerAddr(addr) {
			http.Error(w, `{"error":"invalid_peer_address"}`, 400)
			return
		}

		if strings.ContainsAny(addr, "\r\n") {
			http.Error(w, `{"error":"invalid addr"}`, 400)
			return
		}

		// Use PeerManager if available
		if ns.PeerMgr != nil {
			pm := ns.PeerMgr.(*PeerManager)
			if pm.AddPeer(addr) {
				go pm.pingPeer(addr)
				w.Write([]byte(`{"ok":true}`))
			} else {
				w.Write([]byte(`{"ok":true,"info":"exists_or_full"}`))
			}
			return
		}

		// Legacy fallback
		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		if len(ns.Chain.Peers) >= MaxPeers {
			http.Error(w, `{"error":"max_peers_reached"}`, 400)
			return
		}

		for _, x := range ns.Chain.Peers {
			if x == addr {
				w.Write([]byte(`{"ok":true,"info":"exists"}`))
				return
			}
		}
		ns.Chain.Peers = append(ns.Chain.Peers, addr)
		if ns.DB != nil {
			ns.DB.AddPeer(addr)
		}
		w.Write([]byte(`{"ok":true}`))
	}
}

// PeerListHandler returns the list of known peers.
func PeerListHandler(ns *rpc.NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !RequireP2PAuth(w, r, ns.Cfg) {
			return
		}

		if ns.PeerMgr != nil {
			pm := ns.PeerMgr.(*PeerManager)
			peers := pm.GetPeers()
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"peers": peers, "count": len(peers)})
			return
		}

		ns.Mu.Lock()
		peers := ns.Chain.Peers
		ns.Mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"peers": peers, "count": len(peers)})
	}
}
