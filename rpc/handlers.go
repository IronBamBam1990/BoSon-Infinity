package rpc

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/consensus"
	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
	"github.com/IronBamBam1990/BoSon-Infinity/mempool"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

// NodeState holds shared node state that handlers need access to.
type NodeState struct {
	Mu      sync.RWMutex
	Chain   *core.Chain
	Mempool []core.Tx           // legacy — kept for backward compat during migration
	Pool    *mempool.Mempool    // new indexed mempool (use this when non-nil)
	Cfg     *core.Config
	Jobs    *SyncMap
	DB          *storage.Store  // BBolt database (nil = legacy JSON mode)
	PeerMgr     any            // *p2p.PeerManager (any to avoid import cycle)
	MiningHub   any            // *MiningHub (for metrics)
	BroadcastTx func(core.Tx) // callback to broadcast TX to peers (set by cmd/node)
}

// MempoolSize returns the current mempool size.
func (ns *NodeState) MempoolSize() int {
	if ns.Pool != nil {
		return ns.Pool.Size()
	}
	return len(ns.Mempool)
}

// MempoolAll returns all transactions.
func (ns *NodeState) MempoolAll() []core.Tx {
	if ns.Pool != nil {
		return ns.Pool.All()
	}
	return ns.Mempool
}

// MempoolPurge removes block txs from mempool.
func (ns *NodeState) MempoolPurge(txs []core.Tx) {
	if ns.Pool != nil {
		ns.Pool.Purge(txs)
		return
	}
	PurgeFromMempool(&ns.Mempool, txs)
}

func WriteJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

/* -------------------------------------------------------------------------- */
/*                              MINING API                                     */
/* -------------------------------------------------------------------------- */

type Work struct {
	HeaderHex       string  `json:"header_hex"`
	Difficulty      uint32  `json:"difficulty"`
	ShareDifficulty uint32  `json:"share_difficulty"` // lower diff for pool shares
	Reads           uint32  `json:"reads"`
	MerkleRoot      string  `json:"merkle_root"`
	MinerReward     float64 `json:"miner_reward"`
	TreasuryReward  float64 `json:"treasury_reward"`
	TotalReward     float64 `json:"total_reward"`
	Fees            float64 `json:"fees"`
	JobID           string  `json:"job_id"`
	ExpiresAt       int64   `json:"expires_at"`
	TargetProb      string  `json:"target_prob"`
	DAGEpoch        int     `json:"dag_epoch"` // for DAG-based PoW
}

type JobInfo struct {
	H  string   // headerHex
	M  string   // merkle
	P  string   // prev hash
	E  int64    // expiry
	TX []core.Tx
	D  int
}

type SyncMap struct {
	mu sync.Mutex
	m  map[string]JobInfo
}

func NewSyncMap() *SyncMap {
	return &SyncMap{m: map[string]JobInfo{}}
}

func (s *SyncMap) Store(k string, v JobInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
}

func (s *SyncMap) Load(k string) (JobInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok
}

func (s *SyncMap) Cleanup() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, v := range s.m {
		if now > v.E+300 {
			delete(s.m, k)
		}
	}
}

func hmacJob(hx, merkle, prev string, exp int64, apiKey string) string {
	h := hmac.New(sha256.New, []byte(apiKey))
	h.Write([]byte(hx))
	h.Write([]byte("|"))
	h.Write([]byte(merkle))
	h.Write([]byte("|"))
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	h.Write([]byte(fmt.Sprint(exp)))
	return hex.EncodeToString(h.Sum(nil))
}

func pickTxsForBlock(ns *NodeState) []core.Tx {
	if ns.Pool != nil {
		return ns.Pool.PickForBlock(core.MaxBlockTXs)
	}
	// Legacy: random shuffle
	pool := append([]core.Tx(nil), ns.Mempool...)
	rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if len(pool) > core.MaxBlockTXs {
		pool = pool[:core.MaxBlockTXs]
	}
	return pool
}

func buildWork(ns *NodeState) Work {
	last := ns.Chain.Blocks[len(ns.Chain.Blocks)-1]
	nextHeight := last.Header.Height + 1

	nextDiff := consensus.Retarget(ns.Chain)
	txs := pickTxsForBlock(ns)

	var th []string
	var feeSum uint64
	for _, t := range txs {
		th = append(th, t.Hash)
		feeSum += t.Fee
	}

	merkle := crypto.MerkleRoot(th)

	header := fmt.Sprintf("%s:%d:%s", last.Hash, nextHeight, merkle)
	headerHex := hex.EncodeToString([]byte(header))

	expires := time.Now().Add(5 * time.Minute).Unix()
	jobID := hmacJob(headerHex, merkle, last.Hash, expires, ns.Cfg.APIKey)

	ns.Jobs.Store(jobID, JobInfo{
		H:  headerHex,
		M:  merkle,
		P:  last.Hash,
		E:  expires,
		TX: txs,
		D:  nextDiff,
	})

	brUnits := consensus.BaseRewardAt(nextHeight)
	totalRewardUnits := brUnits + feeSum
	minerUnits, treasuryUnits := consensus.SplitReward80_20(totalRewardUnits)

	return Work{
		HeaderHex:       headerHex,
		Difficulty:      uint32(nextDiff),
		ShareDifficulty: uint32(ShareDifficulty(nextDiff)),
		Reads:           core.ReadsPerTry,
		MerkleRoot:      merkle,
		MinerReward:     float64(minerUnits) / float64(core.UNIT),
		TreasuryReward:  float64(treasuryUnits) / float64(core.UNIT),
		TotalReward:     float64(totalRewardUnits) / float64(core.UNIT),
		Fees:            float64(feeSum) / float64(core.UNIT),
		JobID:           jobID,
		ExpiresAt:       expires,
		TargetProb:      fmt.Sprintf("1 / 2^%d", nextDiff),
		DAGEpoch:        crypto.DAGEpoch(nextHeight),
	}
}

func SubmitSolved(ns *NodeState, jobID, headerHex, mixHex, minerAddr string, nonce uint64, broadcastFn func(core.Block)) error {
	if !core.IsValidAddr(minerAddr) {
		return fmt.Errorf("invalid_miner_address")
	}

	j, ok := ns.Jobs.Load(jobID)
	if !ok {
		return fmt.Errorf("invalid_job")
	}
	if time.Now().Unix() > j.E {
		return fmt.Errorf("job_expired")
	}
	if j.H != headerHex {
		return fmt.Errorf("header_mismatch")
	}
	// Compute expected mix using height-appropriate PoW (legacy or DAG)
	nextHeight := ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height + 1
	wantMix := crypto.ComputeMix(headerHex, nonce, nextHeight)
	if mixHex != wantMix {
		return fmt.Errorf("invalid_mixhash")
	}
	if !crypto.CheckMask(mixHex, j.D) {
		return fmt.Errorf("invalid_difficulty")
	}

	last := ns.Chain.Blocks[len(ns.Chain.Blocks)-1]
	if !consensus.ValidTimestamp(last.Header.Timestamp, time.Now().UTC()) {
		return fmt.Errorf("bad_timestamp")
	}

	var th []string
	for _, t := range j.TX {
		th = append(th, t.Hash)
	}
	merkle := crypto.MerkleRoot(th)
	if merkle != j.M {
		return fmt.Errorf("merkle_mismatch")
	}

	nb := core.Block{
		Header: core.BlockHeader{
			Version:    1,
			PrevHash:   last.Hash,
			Merkle:     merkle,
			Timestamp:  time.Now().UTC(),
			Nonce:      nonce,
			Height:     last.Header.Height + 1,
			Difficulty: j.D,
			Miner:      minerAddr,
		},
		Txs: j.TX,
		Mix: mixHex,
	}
	nb.Hash = crypto.BlockHash(nb)

	if !consensus.ValidateBlock(ns.Chain, nb, ns.Cfg) {
		return fmt.Errorf("invalid_block")
	}

	consensus.ApplyBlock(ns.Chain, nb, ns.Cfg)
	ns.Chain.Blocks = append(ns.Chain.Blocks, nb)
	ns.MempoolPurge(nb.Txs)

	// Persist to database (BBolt) or legacy JSON
	if ns.DB != nil {
		if err := ns.DB.SaveBlockAndState(&nb, ns.Chain.State, ns.Chain.TotalMinted); err != nil {
			slog.Error("save block to database failed", "error", err)
		}
		// Index transactions + checkpoint
		ns.DB.IndexBlockTxs(&nb)
		ns.DB.MaybeCreateCheckpoint(ns.Chain, nb.Header.Height)
	} else {
		storage.SaveChain(ns.Chain, ns.Cfg.ChainFilePath())
	}

	if broadcastFn != nil {
		go broadcastFn(nb)
	}

	slog.Info("new block",
		"height", nb.Header.Height,
		"hash", nb.Hash[:16],
		"miner", core.Short(nb.Header.Miner),
		"txs", len(nb.Txs),
		"difficulty", nb.Header.Difficulty)

	return nil
}

/* -------------------------------------------------------------------------- */
/*                              MEMPOOL HELPERS                                */
/* -------------------------------------------------------------------------- */

func MempoolHasTx(mempool []core.Tx, hash string) bool {
	for _, t := range mempool {
		if t.Hash == hash {
			return true
		}
	}
	return false
}

func MempoolCountByAddr(mempool []core.Tx, addr string) int {
	cnt := 0
	for _, t := range mempool {
		if t.From == addr {
			cnt++
		}
	}
	return cnt
}

func PurgeFromMempool(mempool *[]core.Tx, txs []core.Tx) {
	if len(*mempool) == 0 {
		return
	}
	inBlock := map[string]bool{}
	for _, t := range txs {
		inBlock[t.Hash] = true
	}
	newPool := make([]core.Tx, 0, len(*mempool))
	for _, t := range *mempool {
		if !inBlock[t.Hash] {
			newPool = append(newPool, t)
		}
	}
	*mempool = newPool
}

/* -------------------------------------------------------------------------- */
/*                              HTTP HANDLERS                                  */
/* -------------------------------------------------------------------------- */

func GetWorkHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.Lock()
		defer ns.Mu.Unlock()
		work := buildWork(ns)
		WriteJSON(w, work)
	}
}

func SubmitWorkHandler(ns *NodeState, broadcastFn func(core.Block)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var sub struct {
			HeaderHex string `json:"header_hex"`
			Nonce     uint64 `json:"nonce"`
			MixHex    string `json:"mix_hex"`
			MinerAddr string `json:"miner_address"`
			JobID     string `json:"job_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
			http.Error(w, `{"error":"bad_json"}`, 400)
			return
		}
		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		if err := SubmitSolved(ns, sub.JobID, sub.HeaderHex, sub.MixHex, sub.MinerAddr, sub.Nonce, broadcastFn); err != nil {
			slog.Warn("submitWork rejected", "error", err, "miner", sub.MinerAddr, "job", sub.JobID)
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), 400)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}
}

func GetAccountHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.IsValidAddr(addr) {
			http.Error(w, `{"error":"invalid address"}`, http.StatusBadRequest)
			return
		}

		ns.Mu.RLock()
		acc := ns.Chain.State[addr]
		ns.Mu.RUnlock()

		out := map[string]any{
			"address":       addr,
			"balance_atoms": acc.Balance,
			"balance":       float64(acc.Balance) / float64(core.UNIT),
			"nonce":         acc.Nonce,
		}

		WriteJSON(w, out)
	}
}

func GetChainHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		fromStr := r.URL.Query().Get("from")
		limitStr := r.URL.Query().Get("limit")

		from := 0
		limit := 100

		if fromStr != "" {
			if v, err := strconv.Atoi(fromStr); err == nil && v >= 0 {
				from = v
			}
		}
		if limitStr != "" {
			if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
				limit = v
			}
		}
		if limit > 1000 {
			limit = 1000
		}

		blocks := ns.Chain.Blocks
		total := len(blocks)

		if from >= total {
			WriteJSON(w, map[string]any{
				"blocks": []core.Block{},
				"total":  total,
				"from":   from,
				"limit":  limit,
			})
			return
		}

		end := from + limit
		if end > total {
			end = total
		}

		WriteJSON(w, map[string]any{
			"blocks": blocks[from:end],
			"total":  total,
			"from":   from,
			"limit":  limit,
		})
	}
}

func GetBlockHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		heightStr := r.URL.Query().Get("height")
		hashStr := r.URL.Query().Get("hash")

		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		if heightStr != "" {
			h, err := strconv.Atoi(heightStr)
			if err != nil || h < 0 {
				http.Error(w, `{"error":"invalid height"}`, 400)
				return
			}
			for _, b := range ns.Chain.Blocks {
				if b.Header.Height == h {
					WriteJSON(w, b)
					return
				}
			}
			http.Error(w, `{"error":"block not found"}`, 404)
			return
		}

		if hashStr != "" {
			for _, b := range ns.Chain.Blocks {
				if b.Hash == hashStr {
					WriteJSON(w, b)
					return
				}
			}
			http.Error(w, `{"error":"block not found"}`, 404)
			return
		}

		http.Error(w, `{"error":"specify height or hash"}`, 400)
	}
}

func PoolListHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()
		WriteJSON(w, ns.MempoolAll())
	}
}

func PendingHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if addr == "" {
			http.Error(w, `{"error":"missing addr"}`, http.StatusBadRequest)
			return
		}
		if !core.IsValidAddr(addr) {
			http.Error(w, `{"error":"invalid addr"}`, http.StatusBadRequest)
			return
		}

		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		if ns.Pool != nil {
			WriteJSON(w, ns.Pool.GetForAddr(addr))
			return
		}

		var out []core.Tx
		for _, tx := range ns.Mempool {
			if tx.From == addr || tx.To == addr {
				out = append(out, tx)
			}
		}
		WriteJSON(w, out)
	}
}

type Stats struct {
	Height           int     `json:"height"`
	Window           int     `json:"window"`
	DifficultyBits   int     `json:"difficulty_bits"`
	AvgBlockSeconds  float64 `json:"avg_block_seconds"`
	EstNetworkHps    float64 `json:"est_network_hps"`
	EstNetworkPretty string  `json:"est_network_pretty"`

	TotalMintedAtoms uint64  `json:"total_minted_atoms"`
	MaxSupplyAtoms   uint64  `json:"max_supply_atoms"`
	TotalMinted      float64 `json:"total_minted"`
	MaxSupply        float64 `json:"max_supply"`

	EnergyJPerHash     float64 `json:"energy_j_per_hash"`
	EnergyPricePerKWh  float64 `json:"energy_price_per_kwh"`
	FiatCurrency       string  `json:"fiat_currency"`
	CostPerHash        float64 `json:"cost_per_hash"`
	CostPerBlock       float64 `json:"cost_per_block"`
	CostPerCoin        float64 `json:"cost_per_coin"`
	EnergyModelUpdated int64   `json:"energy_model_updated"`
}

func GetStatsHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		n := len(ns.Chain.Blocks)
		if n < 1 {
			http.Error(w, `{"error":"no_chain"}`, 500)
			return
		}

		wsize := core.RetargetWindow
		if wsize < 5 {
			wsize = 5
		}
		if n-1 < wsize {
			wsize = n - 1
		}
		if wsize < 1 {
			wsize = 1 // avoid division by zero; only genesis block exists
		}

		var totalDt float64
		for i := n - wsize; i < n; i++ {
			if i < 1 {
				continue // safety: don't access Blocks[-1]
			}
			dt := ns.Chain.Blocks[i].Header.Timestamp.Sub(ns.Chain.Blocks[i-1].Header.Timestamp).Seconds()
			if dt < 0 {
				dt = 0
			}
			totalDt += dt
		}
		avg := totalDt / float64(wsize)

		bits := ns.Chain.Blocks[n-1].Header.Difficulty
		hps := math.Exp2(float64(bits)) / math.Max(avg, 1.0)

		nextHeight := ns.Chain.Blocks[n-1].Header.Height + 1
		rewardUnits := float64(consensus.BaseRewardAt(nextHeight))

		var totalFeesUnits uint64
		for i := n - wsize; i < n; i++ {
			for _, tx := range ns.Chain.Blocks[i].Txs {
				totalFeesUnits += tx.Fee
			}
		}
		avgFeesUnits := float64(totalFeesUnits) / float64(wsize)

		totalRewardUnits := rewardUnits + avgFeesUnits
		totalRewardCoins := totalRewardUnits / float64(core.UNIT)

		var (
			energyJPerHash float64
			energyPriceKWh float64
			fiatCurrency   string
			costPerHash    float64
			costPerBlock   float64
			costPerCoin    float64
			emUpdated      int64
		)

		if em, err := storage.LoadEnergyModel(ns.Cfg.EnergyModelPath()); err == nil {
			energyJPerHash = em.AvgJoulesPerHash
			energyPriceKWh = em.AvgPricePerKWh
			fiatCurrency = em.FiatCurrency
			emUpdated = em.UpdatedAt

			costPerHash = (energyJPerHash / 3_600_000.0) * energyPriceKWh
			hashesPerBlock := math.Exp2(float64(bits))
			costPerBlock = hashesPerBlock * costPerHash

			if totalRewardCoins > 0 {
				costPerCoin = costPerBlock / totalRewardCoins
			}
		}

		out := Stats{
			Height:           ns.Chain.Blocks[n-1].Header.Height,
			Window:           wsize,
			DifficultyBits:   bits,
			AvgBlockSeconds:  avg,
			EstNetworkHps:    hps,
			EstNetworkPretty: core.FormatHashrate(hps),

			TotalMintedAtoms: ns.Chain.TotalMinted,
			MaxSupplyAtoms:   core.MAX_SUPPLY_UNITS,
			TotalMinted:      float64(ns.Chain.TotalMinted) / float64(core.UNIT),
			MaxSupply:        float64(core.MAX_SUPPLY_UNITS) / float64(core.UNIT),

			EnergyJPerHash:     energyJPerHash,
			EnergyPricePerKWh:  energyPriceKWh,
			FiatCurrency:       fiatCurrency,
			CostPerHash:        costPerHash,
			CostPerBlock:       costPerBlock,
			CostPerCoin:        costPerCoin,
			EnergyModelUpdated: emUpdated,
		}

		WriteJSON(w, out)
	}
}

func SubmitTxHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var tx core.Tx
		if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
			http.Error(w, `{"error":"bad_json"}`, 400)
			return
		}

		if tx.Hash == "" {
			payload := core.TxPayload{
				ChainID: core.NetworkName,
				From:    tx.From,
				To:      tx.To,
				Amount:  tx.Amount,
				Fee:     tx.Fee,
				Nonce:   tx.Nonce,
				PubKey:  tx.PubKey,
				Type:    tx.Type,
				Data:    tx.Data,
			}
			raw, err := json.Marshal(payload)
			if err != nil {
				http.Error(w, `{"error":"marshal_failed"}`, 500)
				return
			}
			tx.Hash = crypto.HashBytes(raw)
		}

		ns.Mu.Lock()
		defer ns.Mu.Unlock()

		if !consensus.ValidateTx(ns.Chain.State, tx) {
			http.Error(w, `{"error":"rejected"}`, 400)
			return
		}

		if ns.Pool != nil {
			// New indexed mempool
			if ns.Pool.Has(tx.Hash) {
				http.Error(w, `{"error":"duplicate_tx"}`, 400)
				return
			}
			if ns.Pool.HasNonceConflict(tx.From, tx.Nonce) {
				http.Error(w, `{"error":"nonce_conflict"}`, 400)
				return
			}
			if !ns.Pool.Add(tx) {
				http.Error(w, `{"error":"mempool_full_or_addr_limit"}`, http.StatusTooManyRequests)
				return
			}
		} else {
			// Legacy mempool
			if MempoolHasTx(ns.Mempool, tx.Hash) {
				http.Error(w, `{"error":"duplicate_tx"}`, 400)
				return
			}
			for _, m := range ns.Mempool {
				if m.From == tx.From && tx.Nonce <= m.Nonce {
					http.Error(w, `{"error":"nonce_conflict"}`, 400)
					return
				}
			}
			if MempoolCountByAddr(ns.Mempool, tx.From) >= ns.Cfg.MaxPendingPerAddr {
				http.Error(w, `{"error":"too_many_pending_from_addr"}`, http.StatusTooManyRequests)
				return
			}
			if len(ns.Mempool) >= ns.Cfg.MaxMempoolSize {
				http.Error(w, `{"error":"mempool_full"}`, http.StatusServiceUnavailable)
				return
			}
			ns.Mempool = append(ns.Mempool, tx)
		}

		slog.Debug("tx accepted", "hash", core.Short(tx.Hash), "from", core.Short(tx.From), "mempool_size", ns.MempoolSize())

		// Broadcast TX to peers
		if ns.BroadcastTx != nil {
			go ns.BroadcastTx(tx)
		}

		w.Write([]byte(`{"ok":true,"hash":"` + tx.Hash + `"}`))
	}
}

func ListBridgeLocksHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()
		WriteJSON(w, ns.Chain.Bridge.Locks)
	}
}

func ListBridgeUnlocksHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()
		WriteJSON(w, ns.Chain.Bridge.Unlocks)
	}
}
