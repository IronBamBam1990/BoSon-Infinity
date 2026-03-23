package mempool

import (
	"fmt"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func init() {
	core.InitConsensus()
}

func makeTx(from, hash string, fee uint64, nonce uint64) core.Tx {
	return core.Tx{
		From:   from,
		To:     "cccccccccccccccccccccccccccccccccccccccc",
		Amount: 1000,
		Fee:    fee,
		Nonce:  nonce,
		Hash:   hash,
	}
}

func TestAdd_And_Has(t *testing.T) {
	m := New(100, 10)
	tx := makeTx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "hash1", 10, 1)

	if !m.Add(tx) {
		t.Error("should accept first tx")
	}
	if m.Add(tx) {
		t.Error("should reject duplicate")
	}
	if !m.Has("hash1") {
		t.Error("should find tx by hash")
	}
	if m.Has("hash_nonexistent") {
		t.Error("should not find nonexistent tx")
	}
	if m.Size() != 1 {
		t.Errorf("expected size 1, got %d", m.Size())
	}
}

func TestCountByAddr(t *testing.T) {
	m := New(100, 10)
	from := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for i := 0; i < 5; i++ {
		tx := makeTx(from, fmt.Sprintf("hash_%d", i), 10, uint64(i+1))
		m.Add(tx)
	}

	if m.CountByAddr(from) != 5 {
		t.Errorf("expected 5 txs from addr, got %d", m.CountByAddr(from))
	}
	if m.CountByAddr("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb") != 0 {
		t.Error("unknown addr should have 0 txs")
	}
}

func TestPerAddrLimit(t *testing.T) {
	m := New(100, 3)
	from := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

	for i := 0; i < 3; i++ {
		m.Add(makeTx(from, fmt.Sprintf("h%d", i), 10, uint64(i+1)))
	}
	if m.Add(makeTx(from, "h_extra", 10, 4)) {
		t.Error("should reject when per-addr limit reached")
	}
	// Different address should still work
	if !m.Add(makeTx("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "h_other", 10, 1)) {
		t.Error("different addr should be accepted")
	}
}

func TestMaxSize(t *testing.T) {
	m := New(3, 100)
	for i := 0; i < 3; i++ {
		m.Add(makeTx(fmt.Sprintf("%040d", i), fmt.Sprintf("h%d", i), 10, 1))
	}
	if m.Add(makeTx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "overflow", 10, 1)) {
		t.Error("should reject when mempool full")
	}
}

func TestRemove(t *testing.T) {
	m := New(100, 10)
	from := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m.Add(makeTx(from, "h1", 10, 1))
	m.Add(makeTx(from, "h2", 20, 2))

	m.Remove("h1")
	if m.Has("h1") {
		t.Error("should not find removed tx")
	}
	if m.CountByAddr(from) != 1 {
		t.Errorf("expected 1 tx from addr, got %d", m.CountByAddr(from))
	}
	if m.Size() != 1 {
		t.Errorf("expected size 1, got %d", m.Size())
	}
}

func TestPurge(t *testing.T) {
	m := New(100, 10)
	m.Add(makeTx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "h1", 10, 1))
	m.Add(makeTx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "h2", 20, 2))
	m.Add(makeTx("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "h3", 30, 1))

	m.Purge([]core.Tx{{Hash: "h1"}, {Hash: "h3"}})

	if m.Size() != 1 {
		t.Errorf("expected 1 after purge, got %d", m.Size())
	}
	if !m.Has("h2") {
		t.Error("h2 should survive purge")
	}
}

func TestPickForBlock_FeePriority(t *testing.T) {
	m := New(100, 10)
	m.Add(makeTx("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "low", 1, 1))
	m.Add(makeTx("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "high", 100, 1))
	m.Add(makeTx("cccccccccccccccccccccccccccccccccccccccc", "mid", 50, 1))

	picked := m.PickForBlock(2)
	if len(picked) != 2 {
		t.Fatalf("expected 2 txs, got %d", len(picked))
	}
	// Highest fee first
	if picked[0].Fee != 100 {
		t.Errorf("first tx should have highest fee (100), got %d", picked[0].Fee)
	}
	if picked[1].Fee != 50 {
		t.Errorf("second tx should have second highest fee (50), got %d", picked[1].Fee)
	}
}

func TestHasNonceConflict(t *testing.T) {
	m := New(100, 10)
	from := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	m.Add(makeTx(from, "h1", 10, 5))

	if !m.HasNonceConflict(from, 5) {
		t.Error("nonce 5 should conflict with existing nonce 5")
	}
	if !m.HasNonceConflict(from, 3) {
		t.Error("nonce 3 should conflict (existing is 5, 3 <= 5)")
	}
	if m.HasNonceConflict(from, 6) {
		t.Error("nonce 6 should NOT conflict with existing 5")
	}
}

func TestGetForAddr(t *testing.T) {
	m := New(100, 10)
	from := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	m.Add(core.Tx{From: from, To: to, Hash: "h1", Fee: 10, Amount: 100, Nonce: 1})
	m.Add(core.Tx{From: to, To: from, Hash: "h2", Fee: 10, Amount: 200, Nonce: 1})

	txsFrom := m.GetForAddr(from)
	if len(txsFrom) != 2 { // h1 (sent) + h2 (received)
		t.Errorf("expected 2 txs for addr, got %d", len(txsFrom))
	}
}
