package crypto

import (
	"encoding/hex"
	"testing"
)

func TestDAGEpoch(t *testing.T) {
	if DAGEpoch(0) != 0 {
		t.Error("height 0 = epoch 0")
	}
	if DAGEpoch(29999) != 0 {
		t.Error("height 29999 = epoch 0")
	}
	if DAGEpoch(30000) != 1 {
		t.Error("height 30000 = epoch 1")
	}
}

func TestDAGSize(t *testing.T) {
	s0 := DAGSize(0)
	if s0 != DAGSizeBase {
		t.Errorf("epoch 0 size should be %d, got %d", DAGSizeBase, s0)
	}
	s1 := DAGSize(1)
	if s1 != DAGSizeBase+DAGGrowthPerEpoch {
		t.Errorf("epoch 1 size wrong: %d", s1)
	}
}

func TestGenerateDAG_Deterministic(t *testing.T) {
	// Use a tiny size for testing (override won't work with const, so test with epoch 0)
	// We'll just check that the same epoch produces the same first bytes
	dag1 := GenerateDAG(0)
	dag2 := GenerateDAG(0)

	if dag1.Size != dag2.Size {
		t.Error("same epoch should produce same size")
	}

	// Check first 1KB is identical
	for i := 0; i < 1024 && i < dag1.Size; i++ {
		if dag1.Data[i] != dag2.Data[i] {
			t.Fatalf("DAG not deterministic at byte %d", i)
		}
	}
}

func TestMixHashDAG_Deterministic(t *testing.T) {
	dag := GenerateDAG(0)
	headerHex := hex.EncodeToString([]byte("test:1:merkle"))

	h1 := MixHashDAG(headerHex, 12345, dag)
	h2 := MixHashDAG(headerHex, 12345, dag)

	if h1 != h2 {
		t.Error("MixHashDAG should be deterministic")
	}
	if len(h1) != 128 { // SHA-512 = 128 hex
		t.Errorf("expected 128 hex chars, got %d", len(h1))
	}

	// Different nonce = different hash
	h3 := MixHashDAG(headerHex, 99999, dag)
	if h1 == h3 {
		t.Error("different nonces should produce different hashes")
	}
}

func TestMixHashDAG_DifferentFromOld(t *testing.T) {
	dag := GenerateDAG(0)
	headerHex := hex.EncodeToString([]byte("test:1:merkle"))

	dagHash := MixHashDAG(headerHex, 12345, dag)
	oldHash := MixHash(headerHex, 12345)

	if dagHash == oldHash {
		t.Error("DAG hash should differ from simple MixHash")
	}
}

func BenchmarkGenerateDAG(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GenerateDAG(0)
	}
}

func BenchmarkMixHashDAG(b *testing.B) {
	dag := GenerateDAG(0)
	headerHex := hex.EncodeToString([]byte("bench:1:merkle"))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MixHashDAG(headerHex, uint64(i), dag)
	}
}
