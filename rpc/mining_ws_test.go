package rpc

import (
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/mempool"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

func init() {
	core.InitConsensus()
}

func testNS(t *testing.T) *NodeState {
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
	return &NodeState{
		Chain: chain,
		Pool:  mempool.New(10000, 10),
		Cfg:   &cfg,
		Jobs:  NewSyncMap(),
	}
}

func TestMiningHub_ClientCount(t *testing.T) {
	ns := testNS(t)
	hub := NewMiningHub(ns)

	if hub.ClientCount() != 0 {
		t.Errorf("expected 0 clients, got %d", hub.ClientCount())
	}
}

func TestBuildWork(t *testing.T) {
	ns := testNS(t)
	ns.Mu.Lock()
	work := buildWork(ns)
	ns.Mu.Unlock()

	if work.HeaderHex == "" {
		t.Error("HeaderHex should not be empty")
	}
	if work.Difficulty == 0 {
		t.Error("Difficulty should not be 0")
	}
	if work.JobID == "" {
		t.Error("JobID should not be empty")
	}
	if work.ExpiresAt == 0 {
		t.Error("ExpiresAt should not be 0")
	}
	if work.MinerReward <= 0 {
		t.Error("MinerReward should be > 0")
	}
	if work.TreasuryReward <= 0 {
		t.Error("TreasuryReward should be > 0")
	}
}

func TestMempoolMethods(t *testing.T) {
	ns := testNS(t)

	if ns.MempoolSize() != 0 {
		t.Error("empty mempool should have size 0")
	}

	ns.Pool.Add(core.Tx{Hash: "h1", From: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Amount: 100, Fee: 1, Nonce: 1})
	if ns.MempoolSize() != 1 {
		t.Errorf("expected 1, got %d", ns.MempoolSize())
	}

	all := ns.MempoolAll()
	if len(all) != 1 {
		t.Errorf("expected 1 tx, got %d", len(all))
	}

	ns.MempoolPurge([]core.Tx{{Hash: "h1"}})
	if ns.MempoolSize() != 0 {
		t.Error("should be 0 after purge")
	}
}
