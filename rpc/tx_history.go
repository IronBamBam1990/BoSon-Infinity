package rpc

import (
	"net/http"
	"strconv"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

// GetTxHandler returns a transaction by hash with its block location.
// GET /tx?hash=...
func GetTxHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hash := r.URL.Query().Get("hash")
		if hash == "" {
			http.Error(w, `{"error":"missing hash"}`, 400)
			return
		}

		// Try database TX index first
		if ns.DB != nil {
			tx, loc, err := ns.DB.GetTxByHash(hash)
			if err == nil && tx != nil {
				WriteJSON(w, map[string]any{
					"tx":           tx,
					"block_height": loc.BlockHeight,
					"block_hash":   loc.BlockHash,
					"tx_index":     loc.TxIndex,
					"status":       "confirmed",
				})
				return
			}
		}

		// Fallback: check mempool
		if ns.Pool != nil {
			if tx, ok := ns.Pool.Get(hash); ok {
				WriteJSON(w, map[string]any{
					"tx":     tx,
					"status": "pending",
				})
				return
			}
		}

		// Fallback: linear scan through chain (slow but works without index)
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()
		for _, b := range ns.Chain.Blocks {
			for i, tx := range b.Txs {
				if tx.Hash == hash {
					WriteJSON(w, map[string]any{
						"tx":           tx,
						"block_height": b.Header.Height,
						"block_hash":   b.Hash,
						"tx_index":     i,
						"status":       "confirmed",
					})
					return
				}
			}
		}

		http.Error(w, `{"error":"tx_not_found"}`, 404)
	}
}

// GetAddressTxsHandler returns transaction history for an address.
// GET /address/txs?addr=...&offset=0&limit=50
func GetAddressTxsHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.IsValidAddr(addr) {
			http.Error(w, `{"error":"invalid address"}`, 400)
			return
		}

		offset := 0
		limit := 50
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		// Try database TX index
		if ns.DB != nil {
			hashes, err := ns.DB.GetTxsByAddr(addr, offset, limit)
			if err == nil {
				var txs []map[string]any
				for _, hash := range hashes {
					tx, loc, err := ns.DB.GetTxByHash(hash)
					if err == nil && tx != nil {
						txs = append(txs, map[string]any{
							"tx":           tx,
							"block_height": loc.BlockHeight,
							"block_hash":   loc.BlockHash,
						})
					}
				}
				WriteJSON(w, map[string]any{
					"address": addr,
					"txs":    txs,
					"offset": offset,
					"limit":  limit,
					"count":  len(txs),
				})
				return
			}
		}

		// Fallback: scan chain (slow)
		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		var txs []map[string]any
		// Scan newest first
		for i := len(ns.Chain.Blocks) - 1; i >= 0; i-- {
			b := ns.Chain.Blocks[i]
			for _, tx := range b.Txs {
				if tx.From == addr || tx.To == addr {
					txs = append(txs, map[string]any{
						"tx":           tx,
						"block_height": b.Header.Height,
						"block_hash":   b.Hash,
					})
				}
			}
		}

		// Apply offset+limit
		total := len(txs)
		if offset > total {
			txs = nil
		} else {
			end := offset + limit
			if end > total {
				end = total
			}
			txs = txs[offset:end]
		}

		WriteJSON(w, map[string]any{
			"address": addr,
			"txs":    txs,
			"offset": offset,
			"limit":  limit,
			"total":  total,
			"count":  len(txs),
		})
	}
}

// GetAddressBlocksHandler returns blocks mined by an address.
// GET /address/blocks?addr=...&offset=0&limit=50
func GetAddressBlocksHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		addr := r.URL.Query().Get("addr")
		if !core.IsValidAddr(addr) {
			http.Error(w, `{"error":"invalid address"}`, 400)
			return
		}

		offset := 0
		limit := 50
		if v := r.URL.Query().Get("offset"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n >= 0 {
				offset = n
			}
		}
		if v := r.URL.Query().Get("limit"); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 200 {
				limit = n
			}
		}

		ns.Mu.RLock()
		defer ns.Mu.RUnlock()

		var blocks []map[string]any
		for i := len(ns.Chain.Blocks) - 1; i >= 0; i-- {
			b := ns.Chain.Blocks[i]
			if b.Header.Miner == addr {
				blocks = append(blocks, map[string]any{
					"height":     b.Header.Height,
					"hash":       b.Hash,
					"timestamp":  b.Header.Timestamp,
					"difficulty": b.Header.Difficulty,
					"txs":        len(b.Txs),
				})
			}
		}

		total := len(blocks)
		if offset > total {
			blocks = nil
		} else {
			end := offset + limit
			if end > total {
				end = total
			}
			blocks = blocks[offset:end]
		}

		WriteJSON(w, map[string]any{
			"address": addr,
			"blocks":  blocks,
			"offset":  offset,
			"limit":   limit,
			"total":   total,
			"count":   len(blocks),
		})
	}
}
