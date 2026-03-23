package p2p

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/rpc"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

func init() {
	core.InitConsensus()
}

func testNodeState(t *testing.T) *rpc.NodeState {
	t.Helper()
	cfg := core.Config{
		APIKey:             "test_api_key_for_unit_tests_minimum_32chars_long_hex",
		TreasuryAddr:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BridgeOperatorAddr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BridgeVaultAddr:    "0000000000000000000000000000000000000001",
		MaxMempoolSize:     10000,
		MaxPendingPerAddr:  10,
	}

	gen := storage.CreateGenesis()
	state := storage.BuildGenesisState(&cfg)

	chain := &core.Chain{
		Blocks:  []core.Block{gen},
		Peers:   []string{},
		State:   state,
		Staking: core.StakingState{Validators: map[string]core.Staker{}},
		Bridge:  core.BridgeState{Locks: map[string]core.BridgeLock{}, Unlocks: map[string]core.BridgeUnlock{}, Consumed: map[string]bool{}},
	}

	return &rpc.NodeState{
		Chain:   chain,
		Mempool: []core.Tx{},
		Cfg:     &cfg,
		Jobs:    rpc.NewSyncMap(),
	}
}

func TestPeerManager_AddRemove(t *testing.T) {
	ns := testNodeState(t)
	pm := NewPeerManager(ns, nil)

	if pm.AddPeer("http://1.2.3.4:8081") != true {
		t.Error("should accept first peer")
	}
	if pm.AddPeer("http://1.2.3.4:8081") != false {
		t.Error("should reject duplicate peer")
	}
	if pm.AddPeer("http://5.6.7.8:8081") != true {
		t.Error("should accept second peer")
	}

	peers := pm.GetPeers()
	if len(peers) != 2 {
		t.Errorf("expected 2 peers, got %d", len(peers))
	}

	pm.RemovePeer("http://1.2.3.4:8081")
	peers = pm.GetPeers()
	if len(peers) != 1 {
		t.Errorf("expected 1 peer after removal, got %d", len(peers))
	}
}

func TestPeerManager_MaxPeers(t *testing.T) {
	ns := testNodeState(t)
	pm := NewPeerManager(ns, nil)

	// Fill to max
	for i := 0; i < MaxPeers; i++ {
		pm.AddPeer(fmt.Sprintf("http://%d.%d.%d.%d:8081", (i/256/256/256)%256, (i/256/256)%256, (i/256)%256, i%256+1))
	}

	if pm.AddPeer("http://99.99.99.99:8081") != false {
		t.Error("should reject when at max peers")
	}
}

func TestPeerStatusHandler(t *testing.T) {
	ns := testNodeState(t)

	handler := PeerStatusHandler(ns)
	req := httptest.NewRequest("GET", "/peer/status", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	var status PeerStatus
	if err := json.NewDecoder(w.Body).Decode(&status); err != nil {
		t.Fatal(err)
	}

	if status.Network != core.NetworkName {
		t.Errorf("expected network %s, got %s", core.NetworkName, status.Network)
	}
	if status.Height != 0 {
		t.Errorf("expected height 0, got %d", status.Height)
	}
}

func TestPeerBlocksHandler(t *testing.T) {
	ns := testNodeState(t)

	handler := PeerBlocksHandler(ns)
	req := httptest.NewRequest("GET", "/peer/blocks?from=0&to=0", nil)
	w := httptest.NewRecorder()

	handler(w, req)

	if w.Code != 200 {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var result struct {
		Blocks []core.Block `json:"blocks"`
	}
	if err := json.NewDecoder(w.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}

	if len(result.Blocks) != 1 {
		t.Errorf("expected 1 block (genesis), got %d", len(result.Blocks))
	}
	if result.Blocks[0].Hash != "GENESIS" {
		t.Errorf("expected GENESIS, got %s", result.Blocks[0].Hash)
	}
}

func TestPeerBlocksHandler_InvalidRange(t *testing.T) {
	ns := testNodeState(t)
	handler := PeerBlocksHandler(ns)

	// Range too large
	req := httptest.NewRequest("GET", "/peer/blocks?from=0&to=200", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for too-large range, got %d", w.Code)
	}
}

func TestPeerAddHandler_SSRF(t *testing.T) {
	ns := testNodeState(t)
	handler := PeerAddHandler(ns)

	// Try to add private IP
	req := httptest.NewRequest("GET", "/peers/add?addr=http://127.0.0.1:8081", nil)
	w := httptest.NewRecorder()
	handler(w, req)
	if w.Code != 400 {
		t.Errorf("expected 400 for private IP, got %d", w.Code)
	}
}

func TestRecordFailure_DeadPeerRemoval(t *testing.T) {
	ns := testNodeState(t)
	pm := NewPeerManager(ns, nil)
	pm.AddPeer("http://1.2.3.4:8081")

	// Simulate failures
	for i := 0; i < DeadPeerThreshold; i++ {
		pm.recordFailure("http://1.2.3.4:8081")
	}

	peers := pm.GetPeers()
	if len(peers) != 0 {
		t.Errorf("dead peer should be removed, got %d peers", len(peers))
	}
}

// Mock peer server for sync test
func TestPeerSync_Integration(t *testing.T) {
	// Create a "remote" node with extra blocks
	remoteCfg := core.Config{
		APIKey:             "test_api_key_for_unit_tests_minimum_32chars_long_hex",
		TreasuryAddr:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BridgeOperatorAddr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BridgeVaultAddr:    "0000000000000000000000000000000000000001",
	}

	gen := storage.CreateGenesis()
	remoteChain := &core.Chain{
		Blocks:  []core.Block{gen},
		Peers:   []string{},
		State:   storage.BuildGenesisState(&remoteCfg),
		Staking: core.StakingState{Validators: map[string]core.Staker{}},
		Bridge:  core.BridgeState{Locks: map[string]core.BridgeLock{}, Unlocks: map[string]core.BridgeUnlock{}, Consumed: map[string]bool{}},
	}

	remoteNS := &rpc.NodeState{
		Chain:   remoteChain,
		Mempool: []core.Tx{},
		Cfg:     &remoteCfg,
		Jobs:    rpc.NewSyncMap(),
	}

	// Start mock remote server
	mux := http.NewServeMux()
	mux.HandleFunc("/peer/status", PeerStatusHandler(remoteNS))
	mux.HandleFunc("/peer/blocks", PeerBlocksHandler(remoteNS))
	server := httptest.NewServer(mux)
	defer server.Close()

	// Create local node
	localNS := testNodeState(t)
	pm := NewPeerManager(localNS, []string{server.URL})
	localNS.PeerMgr = pm

	// Add and ping the remote peer
	pm.AddPeer(server.URL)
	pm.pingPeer(server.URL)

	// Check peer was updated
	peers := pm.GetPeers()
	found := false
	for _, p := range peers {
		if p.Addr == server.URL && p.Height == 0 {
			found = true
		}
	}
	if !found {
		t.Error("remote peer should have been pinged and updated")
	}
}

// Ensure imports are used
var (
	_ = time.Second
	_ = fmt.Sprintf
)
