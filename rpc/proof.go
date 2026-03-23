package rpc

import (
	"net/http"

	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
)

// MerkleProofHandler returns a merkle inclusion proof for a TX in a block.
// GET /tx/proof?hash=<tx_hash>
func MerkleProofHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, `{"error":"missing hash"}`, 400)
			return
		}

		// Find TX location
		if ns.DB != nil {
			_, loc, err := ns.DB.GetTxByHash(hash)
			if err == nil && loc != nil {
				block, err := ns.DB.GetBlock(loc.BlockHeight)
				if err == nil && block != nil {
					var txHashes []string
					for _, tx := range block.Txs {
						txHashes = append(txHashes, tx.Hash)
					}
					proof := crypto.BuildMerkleProof(txHashes, loc.TxIndex)
					root := crypto.MerkleRoot(txHashes)

					WriteJSON(w, map[string]any{
						"tx_hash":      hash,
						"block_height": loc.BlockHeight,
						"block_hash":   block.Hash,
						"merkle_root":  root,
						"tx_index":     loc.TxIndex,
						"proof":        proof,
						"verified":     crypto.VerifyMerkleProof(hash, root, proof),
					})
					return
				}
			}
		}

		// Fallback: scan chain
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()
		for _, b := range ns.Chain.Blocks {
			for i, tx := range b.Txs {
				if tx.Hash == hash {
					var txHashes []string
					for _, t := range b.Txs {
						txHashes = append(txHashes, t.Hash)
					}
					proof := crypto.BuildMerkleProof(txHashes, i)
					root := crypto.MerkleRoot(txHashes)
					WriteJSON(w, map[string]any{
						"tx_hash":      hash,
						"block_height": b.Header.Height,
						"block_hash":   b.Hash,
						"merkle_root":  root,
						"tx_index":     i,
						"proof":        proof,
						"verified":     crypto.VerifyMerkleProof(hash, root, proof),
					})
					return
				}
			}
		}
		http.Error(w, `{"error":"tx_not_found"}`, 404)
	}
}
