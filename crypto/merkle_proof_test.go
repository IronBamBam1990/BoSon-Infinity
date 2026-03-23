package crypto

import "testing"

func TestBuildAndVerifyMerkleProof(t *testing.T) {
	txHashes := []string{
		HashBytes([]byte("tx0")),
		HashBytes([]byte("tx1")),
		HashBytes([]byte("tx2")),
		HashBytes([]byte("tx3")),
	}

	root := MerkleRoot(txHashes)

	for i, txHash := range txHashes {
		proof := BuildMerkleProof(txHashes, i)
		if proof == nil {
			t.Fatalf("proof for tx %d should not be nil", i)
		}
		if !VerifyMerkleProof(txHash, root, proof) {
			t.Errorf("proof for tx %d failed verification", i)
		}
	}
}

func TestMerkleProof_WrongHash(t *testing.T) {
	txHashes := []string{
		HashBytes([]byte("tx0")),
		HashBytes([]byte("tx1")),
	}
	root := MerkleRoot(txHashes)
	proof := BuildMerkleProof(txHashes, 0)

	// Verify with wrong hash
	wrongHash := HashBytes([]byte("wrong"))
	if VerifyMerkleProof(wrongHash, root, proof) {
		t.Error("should reject wrong TX hash")
	}
}

func TestMerkleProof_SingleTx(t *testing.T) {
	txHashes := []string{HashBytes([]byte("only_tx"))}
	root := MerkleRoot(txHashes)
	proof := BuildMerkleProof(txHashes, 0)

	if !VerifyMerkleProof(txHashes[0], root, proof) {
		t.Error("single-tx proof should verify")
	}
}

func TestMerkleProof_OddCount(t *testing.T) {
	txHashes := []string{
		HashBytes([]byte("tx0")),
		HashBytes([]byte("tx1")),
		HashBytes([]byte("tx2")),
	}
	root := MerkleRoot(txHashes)

	for i, txHash := range txHashes {
		proof := BuildMerkleProof(txHashes, i)
		if !VerifyMerkleProof(txHash, root, proof) {
			t.Errorf("proof for tx %d failed (odd count)", i)
		}
	}
}
