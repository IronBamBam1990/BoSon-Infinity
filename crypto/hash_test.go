package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func init() {
	core.InitConsensus()
}

func TestHashBytes(t *testing.T) {
	h := HashBytes([]byte("hello"))
	if len(h) != 128 { // SHA-512 = 64 bytes = 128 hex
		t.Errorf("expected 128 hex chars, got %d", len(h))
	}
	h2 := HashBytes([]byte("hello"))
	if h != h2 {
		t.Error("deterministic hash failed")
	}
	h3 := HashBytes([]byte("world"))
	if h == h3 {
		t.Error("different inputs produced same hash")
	}
}

func TestAddrFromPub(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	addr := AddrFromPub(pub)
	if len(addr) != 40 {
		t.Errorf("expected 40 char address, got %d", len(addr))
	}
	if !core.IsValidAddr(addr) {
		t.Errorf("generated address is not valid hex: %s", addr)
	}
}

func TestMerkleRootEmpty(t *testing.T) {
	root := MerkleRoot(nil)
	if root == "" {
		t.Error("empty merkle should return hash of nil, not empty string")
	}
}

func TestMerkleRootOrderMatters(t *testing.T) {
	h1 := HashBytes([]byte("tx1"))
	h2 := HashBytes([]byte("tx2"))
	root1 := MerkleRoot([]string{h1, h2})
	root2 := MerkleRoot([]string{h2, h1})
	if root1 == root2 {
		t.Error("different order should produce different merkle root")
	}
}

func TestMixHash_Deterministic(t *testing.T) {
	headerHex := hex.EncodeToString([]byte("test:1:merkle"))
	h1 := MixHash(headerHex, 12345)
	h2 := MixHash(headerHex, 12345)
	if h1 != h2 {
		t.Error("MixHash should be deterministic")
	}
	if len(h1) != 128 {
		t.Errorf("MixHash should be 128 hex chars, got %d", len(h1))
	}
	h3 := MixHash(headerHex, 99999)
	if h1 == h3 {
		t.Error("different nonces should produce different mix hashes")
	}
}

func TestCheckMask(t *testing.T) {
	allZeros := hex.EncodeToString(make([]byte, 64))
	if !CheckMask(allZeros, 16) {
		t.Error("all-zero hash should pass any mask")
	}

	nonZero := hex.EncodeToString([]byte{1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8,
		1, 2, 3, 4, 5, 6, 7, 8, 1, 2, 3, 4, 5, 6, 7, 8})
	if CheckMask(nonZero, 16) {
		t.Error("non-zero hash should fail difficulty check")
	}
}
