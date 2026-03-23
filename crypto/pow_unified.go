package crypto

import "github.com/IronBamBam1990/BoSon-Infinity/core"

// ComputeMix returns the PoW mix hash for a given header+nonce.
// Uses DAG-based PoW for blocks at or above DAGActivationHeight,
// legacy MixHash for earlier blocks (backward compatibility).
func ComputeMix(headerHex string, nonce uint64, height int) string {
	if height >= core.DAGActivationHeight {
		epoch := DAGEpoch(height)
		dag := GetDAG(epoch)
		return MixHashDAG(headerHex, nonce, dag)
	}
	return MixHash(headerHex, nonce)
}
