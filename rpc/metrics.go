package rpc

import (
	"fmt"
	"net/http"
	"runtime"
	"time"
)

var nodeStartTime = time.Now()

// MetricsHandler returns Prometheus-compatible metrics.
func MetricsHandler(ns *NodeState) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ns.Mu.RLock()
		height := 0
		blocks := 0
		accounts := 0
		totalMinted := uint64(0)
		peers := 0
		if ns.Chain != nil {
			blocks = len(ns.Chain.Blocks)
			if blocks > 0 {
				height = ns.Chain.Blocks[blocks-1].Header.Height
			}
			accounts = len(ns.Chain.State)
			totalMinted = ns.Chain.TotalMinted
			peers = len(ns.Chain.Peers)
		}
		mempoolSize := ns.MempoolSize()
		ns.Mu.RUnlock()

		var m runtime.MemStats
		runtime.ReadMemStats(&m)

		uptime := time.Since(nodeStartTime).Seconds()

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "# HELP boson_chain_height Current blockchain height\n")
		fmt.Fprintf(w, "# TYPE boson_chain_height gauge\n")
		fmt.Fprintf(w, "boson_chain_height %d\n", height)
		fmt.Fprintf(w, "# HELP boson_chain_blocks Total number of blocks\n")
		fmt.Fprintf(w, "boson_chain_blocks %d\n", blocks)
		fmt.Fprintf(w, "# HELP boson_accounts Number of accounts\n")
		fmt.Fprintf(w, "boson_accounts %d\n", accounts)
		fmt.Fprintf(w, "# HELP boson_mempool_size Transactions in mempool\n")
		fmt.Fprintf(w, "boson_mempool_size %d\n", mempoolSize)
		fmt.Fprintf(w, "# HELP boson_peers_count Connected peers\n")
		fmt.Fprintf(w, "boson_peers_count %d\n", peers)
		fmt.Fprintf(w, "# HELP boson_total_minted_atoms Total minted in atoms\n")
		fmt.Fprintf(w, "boson_total_minted_atoms %d\n", totalMinted)
		fmt.Fprintf(w, "# HELP boson_uptime_seconds Node uptime\n")
		fmt.Fprintf(w, "boson_uptime_seconds %.0f\n", uptime)
		fmt.Fprintf(w, "# HELP boson_go_goroutines Number of goroutines\n")
		fmt.Fprintf(w, "boson_go_goroutines %d\n", runtime.NumGoroutine())
		fmt.Fprintf(w, "# HELP boson_go_heap_bytes Heap memory in use\n")
		fmt.Fprintf(w, "boson_go_heap_bytes %d\n", m.HeapAlloc)
		fmt.Fprintf(w, "# HELP boson_go_sys_bytes Total memory from OS\n")
		fmt.Fprintf(w, "boson_go_sys_bytes %d\n", m.Sys)

		// Mining hub stats
		if ns.MiningHub != nil {
			hub := ns.MiningHub.(*MiningHub)
			fmt.Fprintf(w, "# HELP boson_ws_miners Connected WebSocket miners\n")
			fmt.Fprintf(w, "boson_ws_miners %d\n", hub.ClientCount())
		}
	}
}
