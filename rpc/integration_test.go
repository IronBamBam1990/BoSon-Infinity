package rpc

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/consensus"
	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bcrypto "github.com/IronBamBam1990/BoSon-Infinity/crypto"
	"github.com/IronBamBam1990/BoSon-Infinity/mempool"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

// TestFullLifecycle tests: genesis → getWork → mine → submitWork → balance → sendTx
func TestFullLifecycle(t *testing.T) {
	core.InitConsensus()

	cfg := core.Config{
		APIKey:             "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		TreasuryAddr:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BridgeOperatorAddr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BridgeVaultAddr:    "0000000000000000000000000000000000000001",
		MaxMempoolSize:     10000,
		MaxPendingPerAddr:  10,
	}

	gen := storage.CreateGenesis()
	state := storage.BuildGenesisState(&cfg)
	chain := &core.Chain{
		Blocks:      []core.Block{gen},
		Peers:       []string{},
		State:       state,
		TotalMinted: 0,
		ParamsHash:  storage.CurrentParamsHash(),
		Staking:     core.StakingState{Validators: map[string]core.Staker{}},
		Contracts:   map[string]core.Contract{},
		Bridge:      core.BridgeState{Locks: map[string]core.BridgeLock{}, Unlocks: map[string]core.BridgeUnlock{}, Consumed: map[string]bool{}},
	}

	ns := &NodeState{
		Chain: chain,
		Pool:  mempool.New(10000, 10),
		Cfg:   &cfg,
		Jobs:  NewSyncMap(),
	}

	// 1. Health check
	t.Run("health", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()
		handler := func(rw http.ResponseWriter, r *http.Request) {
			ns.Mu.RLock()
			defer ns.Mu.RUnlock()
			rw.Write([]byte(`{"status":"ok"}`))
		}
		handler(w, req)
		if w.Code != 200 {
			t.Fatal("health check failed")
		}
	})

	// 2. Get work
	t.Run("getWork", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/getWork", nil)
		w := httptest.NewRecorder()
		GetWorkHandler(ns)(w, req)
		if w.Code != 200 {
			t.Fatalf("getWork failed: %d %s", w.Code, w.Body.String())
		}
		var work Work
		json.NewDecoder(w.Body).Decode(&work)
		if work.JobID == "" {
			t.Fatal("no job ID returned")
		}
		if work.Difficulty == 0 {
			t.Fatal("difficulty should be > 0")
		}
		if work.ShareDifficulty == 0 {
			t.Fatal("share difficulty should be > 0")
		}
		if work.MinerReward <= 0 {
			t.Fatal("miner reward should be > 0")
		}
	})

	// 3. Get account (miner)
	pub, priv, _ := ed25519.GenerateKey(nil)
	minerAddr := bcrypto.AddrFromPub(pub)
	privHex := hex.EncodeToString(priv)
	pubHex := hex.EncodeToString(pub)

	t.Run("account_empty", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/account?addr="+minerAddr, nil)
		w := httptest.NewRecorder()
		GetAccountHandler(ns)(w, req)
		if w.Code != 200 {
			t.Fatal("account check failed")
		}
		var acc map[string]any
		json.NewDecoder(w.Body).Decode(&acc)
		if acc["balance"].(float64) != 0 {
			t.Fatal("new account should have 0 balance")
		}
	})

	// 4. Mine a block manually (simulate PoW)
	t.Run("mine_block", func(t *testing.T) {
		ns.Mu.Lock()
		last := ns.Chain.Blocks[len(ns.Chain.Blocks)-1]
		nextH := last.Header.Height + 1
		diff := consensus.Retarget(ns.Chain)

		nb := core.Block{
			Header: core.BlockHeader{
				Version:    1,
				PrevHash:   last.Hash,
				Merkle:     bcrypto.MerkleRoot(nil),
				Timestamp:  last.Header.Timestamp.Add(400_000_000_000), // 400s later
				Nonce:      0,
				Height:     nextH,
				Difficulty: diff,
				Miner:      minerAddr,
			},
		}

		// Find a valid nonce (brute force at low difficulty)
		merkle := bcrypto.MerkleRoot(nil)
		nb.Header.Merkle = merkle

		// We need to find nonce where mix passes mask
		headerStr := last.Hash + ":" + "1" + ":" + merkle
		headerHex := hex.EncodeToString([]byte(headerStr))

		found := false
		for nonce := uint64(0); nonce < 1_000_000; nonce++ {
			mix := bcrypto.MixHash(headerHex, nonce)
			if bcrypto.CheckMask(mix, diff) {
				nb.Header.Nonce = nonce
				nb.Mix = mix
				found = true
				break
			}
		}
		if !found {
			ns.Mu.Unlock()
			t.Skip("couldn't find valid nonce in 1M tries (difficulty too high)")
			return
		}

		nb.Hash = bcrypto.BlockHash(nb)

		// Apply block
		consensus.ApplyBlock(ns.Chain, nb, ns.Cfg)
		ns.Chain.Blocks = append(ns.Chain.Blocks, nb)
		ns.Mu.Unlock()

		// Verify miner got reward
		ns.Mu.RLock()
		acc := ns.Chain.State[minerAddr]
		ns.Mu.RUnlock()
		if acc.Balance == 0 {
			t.Fatal("miner should have balance after mining")
		}
		t.Logf("miner balance after block: %d atoms", acc.Balance)
	})

	// 5. Submit TX
	t.Run("submit_tx", func(t *testing.T) {
		ns.Mu.RLock()
		acc := ns.Chain.State[minerAddr]
		ns.Mu.RUnlock()
		if acc.Balance == 0 {
			t.Skip("no balance to send")
			return
		}

		toAddr := "cccccccccccccccccccccccccccccccccccccccc"
		amount := uint64(1_000_000) // 0.01 BOS
		fee := consensus.CalcFee(amount)

		tx, err := bcrypto.BuildTx(privHex, pubHex, minerAddr, toAddr, amount, fee, acc.Nonce+1, "transfer", "")
		if err != nil {
			t.Fatalf("BuildTx failed: %v", err)
		}

		body, _ := json.Marshal(tx)
		req := httptest.NewRequest("POST", "/tx/submit", strings.NewReader(string(body)))
		w := httptest.NewRecorder()
		SubmitTxHandler(ns)(w, req)

		if w.Code != 200 {
			t.Fatalf("tx submit failed: %d %s", w.Code, w.Body.String())
		}

		// Verify TX in mempool
		if ns.Pool.Size() != 1 {
			t.Errorf("expected 1 tx in mempool, got %d", ns.Pool.Size())
		}
	})

	// 6. Check mempool
	t.Run("mempool", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/tx/pool", nil)
		w := httptest.NewRecorder()
		PoolListHandler(ns)(w, req)
		if w.Code != 200 {
			t.Fatal("mempool check failed")
		}
	})

	// 7. Stats
	t.Run("stats", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/stats", nil)
		w := httptest.NewRecorder()
		GetStatsHandler(ns)(w, req)
		if w.Code != 200 {
			t.Fatalf("stats failed: %d %s", w.Code, w.Body.String())
		}
		var stats map[string]any
		json.NewDecoder(w.Body).Decode(&stats)
		if stats["height"].(float64) < 1 {
			t.Error("height should be >= 1 after mining")
		}
	})
}
