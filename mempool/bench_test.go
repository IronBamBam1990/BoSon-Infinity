package mempool

import (
	"fmt"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func BenchmarkAdd(b *testing.B) {
	core.InitConsensus()
	m := New(b.N+1, b.N+1)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Add(core.Tx{
			Hash:   fmt.Sprintf("h%d", i),
			From:   fmt.Sprintf("%040d", i%1000),
			To:     "cccccccccccccccccccccccccccccccccccccccc",
			Amount: 1000,
			Fee:    10,
			Nonce:  uint64(i),
		})
	}
}

func BenchmarkHas(b *testing.B) {
	core.InitConsensus()
	m := New(10000, 10000)
	for i := 0; i < 10000; i++ {
		m.Add(core.Tx{Hash: fmt.Sprintf("h%d", i), From: fmt.Sprintf("%040d", i%1000), Amount: 1000, Fee: 10, Nonce: uint64(i)})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.Has(fmt.Sprintf("h%d", i%10000))
	}
}

func BenchmarkPickForBlock(b *testing.B) {
	core.InitConsensus()
	m := New(10000, 10000)
	for i := 0; i < 5000; i++ {
		m.Add(core.Tx{Hash: fmt.Sprintf("h%d", i), From: fmt.Sprintf("%040d", i%1000), Amount: 1000, Fee: uint64(i), Nonce: uint64(i)})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		m.PickForBlock(2000)
	}
}
