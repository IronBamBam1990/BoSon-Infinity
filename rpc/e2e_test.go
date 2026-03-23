package rpc

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/consensus"
	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bcrypto "github.com/IronBamBam1990/BoSon-Infinity/crypto"
	"github.com/IronBamBam1990/BoSon-Infinity/mempool"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

// TestE2E_MineAndSendCoins tests the FULL lifecycle:
// 1. Mine a block (miner gets 40 BOS)
// 2. Send 1 BOS from miner to recipient
// 3. Mine another block (includes TX)
// 4. Verify recipient balance = 1 BOS
// 5. Verify miner balance = 80 - 1 - fee BOS
func TestE2E_MineAndSendCoins(t *testing.T) {
	core.InitConsensus()

	// Setup
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

	// Create miner keypair
	minerPub, minerPriv, _ := ed25519.GenerateKey(nil)
	minerAddr := bcrypto.AddrFromPub(minerPub)
	minerPrivHex := hex.EncodeToString(minerPriv)
	minerPubHex := hex.EncodeToString(minerPub)

	// Create recipient
	recipientAddr := "dddddddddddddddddddddddddddddddddddddddd"[:40]

	t.Logf("Miner address:     %s", minerAddr)
	t.Logf("Recipient address: %s", recipientAddr)

	// ================================================================
	// STEP 1: Mine first block
	// ================================================================
	t.Run("Step1_MineFirstBlock", func(t *testing.T) {
		mineBlock(t, ns, minerAddr)
	})

	// Check miner balance
	minerAcc := ns.Chain.State[minerAddr]
	t.Logf("Miner balance after block 1: %d atoms (%.2f BOS)", minerAcc.Balance, float64(minerAcc.Balance)/float64(core.UNIT))

	expectedReward := consensus.BaseRewardAt(1)
	minerShare, _ := consensus.SplitReward80_20(expectedReward)
	if minerAcc.Balance != minerShare {
		t.Fatalf("Expected miner balance %d, got %d", minerShare, minerAcc.Balance)
	}
	t.Logf("Miner balance correct: %d atoms = %.2f BOS", minerShare, float64(minerShare)/float64(core.UNIT))

	// ================================================================
	// STEP 2: Submit TX (send 1 BOS to recipient)
	// ================================================================
	sendAmount := uint64(1_00_000_000) // 1 BOS = 100,000,000 atoms
	fee := consensus.CalcFee(sendAmount)
	t.Logf("Sending %d atoms (fee: %d) to %s", sendAmount, fee, recipientAddr)

	t.Run("Step2_SubmitTX", func(t *testing.T) {
		tx, err := bcrypto.BuildTx(
			minerPrivHex, minerPubHex, minerAddr, recipientAddr,
			sendAmount, fee, 1, "transfer", "",
		)
		if err != nil {
			t.Fatalf("BuildTx failed: %v", err)
		}

		body, _ := json.Marshal(tx)
		req := httptest.NewRequest("POST", "/tx/submit", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		SubmitTxHandler(ns)(w, req)

		t.Logf("TX submit response: %d %s", w.Code, w.Body.String())
		if w.Code != 200 {
			t.Fatalf("TX submit failed: %d %s", w.Code, w.Body.String())
		}

		// Verify TX in mempool
		if ns.Pool.Size() != 1 {
			t.Fatalf("Expected 1 TX in mempool, got %d", ns.Pool.Size())
		}
		t.Logf("TX in mempool: %d", ns.Pool.Size())
	})

	// ================================================================
	// STEP 3: Mine second block (includes TX from mempool)
	// ================================================================
	t.Run("Step3_MineBlockWithTX", func(t *testing.T) {
		mineBlock(t, ns, minerAddr)
	})

	// Mempool should be empty after mining
	if ns.Pool.Size() != 0 {
		t.Errorf("Mempool should be empty after mining, got %d", ns.Pool.Size())
	}

	// ================================================================
	// STEP 4: Verify balances
	// ================================================================
	t.Run("Step4_VerifyBalances", func(t *testing.T) {
		recipientAcc := ns.Chain.State[recipientAddr]
		minerAcc := ns.Chain.State[minerAddr]
		treasuryAcc := ns.Chain.State[cfg.TreasuryAddr]

		t.Logf("Recipient balance: %d atoms (%.8f BOS)", recipientAcc.Balance, float64(recipientAcc.Balance)/float64(core.UNIT))
		t.Logf("Miner balance:     %d atoms (%.8f BOS)", minerAcc.Balance, float64(minerAcc.Balance)/float64(core.UNIT))
		t.Logf("Treasury balance:  %d atoms (%.8f BOS)", treasuryAcc.Balance, float64(treasuryAcc.Balance)/float64(core.UNIT))
		t.Logf("Chain height:      %d", ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height)
		t.Logf("Total minted:      %d atoms", ns.Chain.TotalMinted)

		// Recipient should have exactly sendAmount
		if recipientAcc.Balance != sendAmount {
			t.Errorf("Recipient balance: expected %d, got %d", sendAmount, recipientAcc.Balance)
		}

		// Miner: 2 blocks reward (80% each) - sendAmount - fee
		block1Reward, _ := consensus.SplitReward80_20(consensus.BaseRewardAt(1))
		block2Reward, _ := consensus.SplitReward80_20(consensus.BaseRewardAt(2) + fee) // block 2 includes TX fee
		expectedMinerBal := block1Reward + block2Reward - sendAmount - fee
		if minerAcc.Balance != expectedMinerBal {
			t.Errorf("Miner balance: expected %d, got %d", expectedMinerBal, minerAcc.Balance)
		}

		// Height should be 2
		lastHeight := ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height
		if lastHeight != 2 {
			t.Errorf("Expected height 2, got %d", lastHeight)
		}

		// Block 2 should contain our TX
		block2 := ns.Chain.Blocks[2]
		if len(block2.Txs) != 1 {
			t.Errorf("Block 2 should have 1 TX, got %d", len(block2.Txs))
		} else {
			t.Logf("Block 2 TX: from=%s to=%s amount=%d",
				block2.Txs[0].From[:10], block2.Txs[0].To[:10], block2.Txs[0].Amount)
		}
	})

	// ================================================================
	// STEP 5: Verify via API handlers
	// ================================================================
	t.Run("Step5_APIVerification", func(t *testing.T) {
		// Check recipient via /account handler
		req := httptest.NewRequest("GET", "/account?addr="+recipientAddr, nil)
		w := httptest.NewRecorder()
		GetAccountHandler(ns)(w, req)

		var accResp map[string]any
		json.NewDecoder(w.Body).Decode(&accResp)
		t.Logf("API /account response: %v", accResp)

		apiBalance := accResp["balance_atoms"].(float64)
		if uint64(apiBalance) != sendAmount {
			t.Errorf("API balance mismatch: expected %d, got %.0f", sendAmount, apiBalance)
		}

		// Check stats
		req2 := httptest.NewRequest("GET", "/stats", nil)
		w2 := httptest.NewRecorder()
		GetStatsHandler(ns)(w2, req2)
		var stats map[string]any
		json.NewDecoder(w2.Body).Decode(&stats)
		t.Logf("Height: %.0f, Minted: %.2f BOS", stats["height"], stats["total_minted"])
	})
}

// mineBlock creates a valid block using brute-force nonce search.
func mineBlock(t *testing.T, ns *NodeState, minerAddr string) {
	t.Helper()

	ns.Mu.Lock()
	defer ns.Mu.Unlock()

	last := ns.Chain.Blocks[len(ns.Chain.Blocks)-1]
	nextH := last.Header.Height + 1
	diff := consensus.Retarget(ns.Chain)

	// Pick TXs from mempool
	var txs []core.Tx
	if ns.Pool != nil {
		txs = ns.Pool.PickForBlock(core.MaxBlockTXs)
	}

	var th []string
	for _, tx := range txs {
		th = append(th, tx.Hash)
	}
	merkle := bcrypto.MerkleRoot(th)

	headerStr := last.Hash + ":" + string(rune('0'+nextH)) // simple for small heights
	if nextH >= 10 {
		headerStr = last.Hash + ":" + strings.Repeat("0", 0) // fallback
	}
	// Use exact same format as buildWork
	headerStr = last.Hash + ":" + intToStr(nextH) + ":" + merkle
	headerHex := hex.EncodeToString([]byte(headerStr))

	// Find valid nonce
	found := false
	var nonce uint64
	var mix string
	for n := uint64(0); n < 50_000_000; n++ {
		m := bcrypto.MixHash(headerHex, n)
		if bcrypto.CheckMask(m, diff) {
			nonce = n
			mix = m
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Could not find valid nonce for block %d (diff=%d)", nextH, diff)
	}

	nb := core.Block{
		Header: core.BlockHeader{
			Version:    1,
			PrevHash:   last.Hash,
			Merkle:     merkle,
			Timestamp:  last.Header.Timestamp.Add(400_000_000_000),
			Nonce:      nonce,
			Height:     nextH,
			Difficulty: diff,
			Miner:      minerAddr,
		},
		Txs: txs,
		Mix: mix,
	}
	nb.Hash = bcrypto.BlockHash(nb)

	if !consensus.ValidateBlock(ns.Chain, nb, ns.Cfg) {
		t.Fatalf("Block %d failed validation", nextH)
	}

	consensus.ApplyBlock(ns.Chain, nb, ns.Cfg)
	ns.Chain.Blocks = append(ns.Chain.Blocks, nb)
	ns.MempoolPurge(nb.Txs)

	t.Logf("Mined block %d: hash=%s nonce=%d txs=%d", nextH, nb.Hash[:16], nonce, len(nb.Txs))
}

func intToStr(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}
