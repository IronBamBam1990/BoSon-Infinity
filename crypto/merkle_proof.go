package crypto

import (
	"crypto/sha512"
	"encoding/hex"
)

/* -------------------------------------------------------------------------- */
/*                           MERKLE INCLUSION PROOFS                           */
/* -------------------------------------------------------------------------- */
// Allows light clients to verify that a TX is included in a block without
// downloading all TXs. The proof is a list of sibling hashes along the
// path from the TX leaf to the merkle root.

// MerkleProofNode is one step in a merkle inclusion proof.
type MerkleProofNode struct {
	Hash  string `json:"hash"`
	IsLeft bool  `json:"is_left"` // true = this hash is on the left
}

// BuildMerkleProof constructs an inclusion proof for txHashes[index].
func BuildMerkleProof(txHashes []string, index int) []MerkleProofNode {
	if len(txHashes) == 0 || index < 0 || index >= len(txHashes) {
		return nil
	}

	level := make([][]byte, len(txHashes))
	for i, h := range txHashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			level[i] = []byte(h)
		} else {
			level[i] = b
		}
	}

	var proof []MerkleProofNode
	idx := index

	for len(level) > 1 {
		var next [][]byte

		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				// Odd: hash with itself (MerkleRoot hashes single node alone)
				sum := sha512.Sum512(level[i])
				next = append(next, sum[:])

				// If our tracked idx IS this odd element, no sibling needed
				// but we must mark it as "self-hash" for verification
				if idx == i {
					// Add a special self-hash marker
					proof = append(proof, MerkleProofNode{
						Hash:   "__self__",
						IsLeft: false,
					})
				}
			} else {
				combined := make([]byte, len(level[i])+len(level[i+1]))
				copy(combined, level[i])
				copy(combined[len(level[i]):], level[i+1])
				sum := sha512.Sum512(combined)
				next = append(next, sum[:])

				if idx == i {
					proof = append(proof, MerkleProofNode{
						Hash:   hex.EncodeToString(level[i+1]),
						IsLeft: false,
					})
				} else if idx == i+1 {
					proof = append(proof, MerkleProofNode{
						Hash:   hex.EncodeToString(level[i]),
						IsLeft: true,
					})
				}
			}
		}
		idx = idx / 2
		level = next
	}

	return proof
}

// VerifyMerkleProof verifies an inclusion proof for a TX hash against the root.
func VerifyMerkleProof(txHash, merkleRoot string, proof []MerkleProofNode) bool {
	current, err := hex.DecodeString(txHash)
	if err != nil {
		return false
	}

	for _, node := range proof {
		if node.Hash == "__self__" {
			// Odd element: hash with itself (just SHA-512 of current)
			sum := sha512.Sum512(current)
			current = sum[:]
			continue
		}

		sibling, err := hex.DecodeString(node.Hash)
		if err != nil {
			return false
		}

		var combined []byte
		if node.IsLeft {
			combined = append(sibling, current...)
		} else {
			combined = append(current, sibling...)
		}
		sum := sha512.Sum512(combined)
		current = sum[:]
	}

	return hex.EncodeToString(current) == merkleRoot
}
