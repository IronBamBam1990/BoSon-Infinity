package rpc

import (
	"net/http"
)

// StorageInfoHandler returns database storage information.
func StorageInfoHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ns.DB == nil {
			WriteJSON(w, map[string]any{"error": "no database"})
			return
		}
		info := ns.DB.Info()
		WriteJSON(w, info)
	}
}

// PruneHandler triggers manual block pruning.
// POST /admin/prune — requires API key
func PruneHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ns.DB == nil {
			WriteJSON(w, map[string]any{"error": "no database"})
			return
		}

		ns.Mu.RLock()
		height := 0
		if len(ns.Chain.Blocks) > 0 {
			height = ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height
		}
		ns.Mu.RUnlock()

		pruned, err := ns.DB.PruneBlocks(height, 10000)
		if err != nil {
			WriteJSON(w, map[string]any{"error": err.Error()})
			return
		}
		WriteJSON(w, map[string]any{
			"ok":             true,
			"pruned_blocks":  pruned,
			"current_height": height,
		})
	}
}
