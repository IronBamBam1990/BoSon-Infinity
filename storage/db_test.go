package storage

import (
	"fmt"
	"testing"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func init() {
	core.InitConsensus()
}

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestOpenStore(t *testing.T) {
	s := testStore(t)
	if s.GetHeight() != -1 {
		t.Error("empty db should have height -1")
	}
}

func TestSaveAndGetBlock(t *testing.T) {
	s := testStore(t)
	b := &core.Block{
		Header: core.BlockHeader{
			Version:    1,
			Height:     0,
			Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			Difficulty: 16,
			Miner:      "GENESIS",
		},
		Hash: "GENESIS",
	}

	if err := s.SaveBlock(b); err != nil {
		t.Fatalf("SaveBlock: %v", err)
	}

	got, err := s.GetBlock(0)
	if err != nil {
		t.Fatalf("GetBlock: %v", err)
	}
	if got.Hash != "GENESIS" {
		t.Errorf("expected GENESIS hash, got %s", got.Hash)
	}

	got2, err := s.GetBlockByHash("GENESIS")
	if err != nil {
		t.Fatalf("GetBlockByHash: %v", err)
	}
	if got2.Header.Height != 0 {
		t.Errorf("expected height 0, got %d", got2.Header.Height)
	}
}

func TestStateOperations(t *testing.T) {
	s := testStore(t)

	state := map[string]core.Account{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {Balance: 1000, Nonce: 1},
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": {Balance: 2000, Nonce: 5},
	}

	if err := s.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}

	acc, err := s.GetAccount("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if acc.Balance != 1000 || acc.Nonce != 1 {
		t.Errorf("expected balance=1000 nonce=1, got %d %d", acc.Balance, acc.Nonce)
	}

	full, err := s.LoadFullState()
	if err != nil {
		t.Fatalf("LoadFullState: %v", err)
	}
	if len(full) != 2 {
		t.Errorf("expected 2 accounts, got %d", len(full))
	}
}

func TestMetaOperations(t *testing.T) {
	s := testStore(t)

	if err := s.SetHeight(42); err != nil {
		t.Fatal(err)
	}
	if s.GetHeight() != 42 {
		t.Errorf("expected height 42, got %d", s.GetHeight())
	}

	if err := s.SetTotalMinted(5_000_000_000); err != nil {
		t.Fatal(err)
	}
	if s.GetTotalMinted() != 5_000_000_000 {
		t.Errorf("expected 5000000000, got %d", s.GetTotalMinted())
	}
}

func TestPeers(t *testing.T) {
	s := testStore(t)

	peers := []string{"http://1.2.3.4:8081", "http://5.6.7.8:8081"}
	if err := s.SavePeers(peers); err != nil {
		t.Fatal(err)
	}

	loaded := s.LoadPeers()
	if len(loaded) != 2 {
		t.Errorf("expected 2 peers, got %d", len(loaded))
	}

	if err := s.AddPeer("http://9.10.11.12:8081"); err != nil {
		t.Fatal(err)
	}
	loaded2 := s.LoadPeers()
	if len(loaded2) != 3 {
		t.Errorf("expected 3 peers, got %d", len(loaded2))
	}
}

func TestSaveBlockAndState(t *testing.T) {
	s := testStore(t)

	b := &core.Block{
		Header: core.BlockHeader{
			Version:    1,
			Height:     5,
			Timestamp:  time.Now().UTC(),
			Difficulty: 16,
			Miner:      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Hash: "abc123def456",
	}

	state := map[string]core.Account{
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": {Balance: 50_000_000_000, Nonce: 0},
	}

	if err := s.SaveBlockAndState(b, state, 50_000_000_000); err != nil {
		t.Fatalf("SaveBlockAndState: %v", err)
	}

	if s.GetHeight() != 5 {
		t.Errorf("expected height 5, got %d", s.GetHeight())
	}
	if s.GetTotalMinted() != 50_000_000_000 {
		t.Errorf("expected minted 50000000000, got %d", s.GetTotalMinted())
	}

	got, err := s.GetBlock(5)
	if err != nil {
		t.Fatal(err)
	}
	if got.Hash != "abc123def456" {
		t.Errorf("wrong hash: %s", got.Hash)
	}
}

func TestInitFromChainAndLoad(t *testing.T) {
	s := testStore(t)

	cfg := &core.Config{
		TreasuryAddr:       "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		BridgeOperatorAddr: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		BridgeVaultAddr:    "0000000000000000000000000000000000000001",
	}

	gen := CreateGenesis()
	state := BuildGenesisState(cfg)

	chain := &core.Chain{
		Blocks:      []core.Block{gen},
		Peers:       []string{"http://peer1:8081"},
		State:       state,
		TotalMinted: 0,
		ParamsHash:  "testhash",
		Params: core.ConsensusParams{
			NetworkName: core.NetworkName,
		},
		Staking: core.StakingState{
			Validators: map[string]core.Staker{},
		},
		Contracts: map[string]core.Contract{},
		Bridge: core.BridgeState{
			Locks:    map[string]core.BridgeLock{},
			Unlocks:  map[string]core.BridgeUnlock{},
			Consumed: map[string]bool{},
		},
		GenesisMessage: core.GenesisMessage,
	}

	if err := s.InitFromChain(chain); err != nil {
		t.Fatalf("InitFromChain: %v", err)
	}

	loaded, err := s.LoadToChain()
	if err != nil {
		t.Fatalf("LoadToChain: %v", err)
	}

	if len(loaded.Blocks) != 1 {
		t.Errorf("expected 1 block, got %d", len(loaded.Blocks))
	}
	if loaded.Blocks[0].Hash != "GENESIS" {
		t.Errorf("expected GENESIS, got %s", loaded.Blocks[0].Hash)
	}
	if len(loaded.Peers) != 1 {
		t.Errorf("expected 1 peer, got %d", len(loaded.Peers))
	}
	if loaded.ParamsHash != "testhash" {
		t.Errorf("expected testhash, got %s", loaded.ParamsHash)
	}
	if len(loaded.State) != 3 { // treasury, bridge operator, bridge vault
		t.Errorf("expected 3 accounts, got %d", len(loaded.State))
	}

}

func TestGetBlockRange(t *testing.T) {
	s := testStore(t)

	for i := 0; i < 10; i++ {
		b := &core.Block{
			Header: core.BlockHeader{Height: i, Timestamp: time.Now().UTC()},
			Hash:   fmt.Sprintf("hash_%d", i),
		}
		s.SaveBlock(b)
	}

	blocks, err := s.GetBlockRange(3, 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 5 {
		t.Errorf("expected 5 blocks (3-7), got %d", len(blocks))
	}
	if blocks[0].Header.Height != 3 {
		t.Errorf("expected first block height 3, got %d", blocks[0].Header.Height)
	}
	if blocks[4].Header.Height != 7 {
		t.Errorf("expected last block height 7, got %d", blocks[4].Header.Height)
	}
}
