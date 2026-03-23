package rpc

import (
	"net/http"
)

// CheckpointsHandler returns all known checkpoints.
func CheckpointsHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if ns.DB == nil {
			WriteJSON(w, map[string]any{"checkpoints": []any{}, "count": 0})
			return
		}
		cps := ns.DB.ListCheckpoints()
		WriteJSON(w, map[string]any{"checkpoints": cps, "count": len(cps)})
	}
}
