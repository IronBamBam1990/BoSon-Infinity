package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

/* -------------------------------------------------------------------------- */
/*                        BOSON INFINITY — GO MINER                            */
/* -------------------------------------------------------------------------- */
// Multi-threaded CPU miner with WebSocket and HTTP polling support.
// For GPU mining, use miner_gpu.c (OpenCL) or adapt this as a template.
//
// Usage:
//   boson-miner [--ws]
//
// Environment:
//   BOSON_NODE_URL    — node URL (default http://127.0.0.1:8080)
//   BOSON_API_KEY     — API key for submitWork
//   BOSON_WALLET      — miner wallet address (40 hex)
//   BOSON_THREADS     — number of mining threads (default: NumCPU)
//   BOSON_USE_WS      — "1" to use WebSocket (default: HTTP polling)

var (
	nodeURL    string
	apiKey     string
	minerAddr  string
	threads    int
	useWS      bool
	hashCount  atomic.Uint64
	blockCount atomic.Uint64
	shareCount atomic.Uint64
)

type Work struct {
	HeaderHex       string `json:"header_hex"`
	Difficulty      uint32 `json:"difficulty"`
	ShareDifficulty uint32 `json:"share_difficulty"`
	JobID           string `json:"job_id"`
	ExpiresAt       int64  `json:"expires_at"`
	DAGEpoch        int    `json:"dag_epoch"`
}

func main() {
	core.InitConsensus()

	nodeURL = envOr("BOSON_NODE_URL", "http://127.0.0.1:8080")
	apiKey = os.Getenv("BOSON_API_KEY")
	minerAddr = os.Getenv("BOSON_WALLET")
	threads = envInt("BOSON_THREADS", runtime.NumCPU())
	useWS = os.Getenv("BOSON_USE_WS") == "1"

	if minerAddr == "" || len(minerAddr) != 40 {
		log.Fatal("[MINER] BOSON_WALLET must be set (40 hex chars)")
	}
	if apiKey == "" {
		log.Fatal("[MINER] BOSON_API_KEY must be set")
	}

	// Check for --ws flag
	for _, arg := range os.Args[1:] {
		if arg == "--ws" || arg == "-ws" {
			useWS = true
		}
	}

	log.Printf("[MINER] Boson Infinity Miner v2.1.0")
	log.Printf("[MINER] Node: %s", nodeURL)
	log.Printf("[MINER] Wallet: %s", minerAddr)
	log.Printf("[MINER] Threads: %d", threads)
	log.Printf("[MINER] Mode: %s", map[bool]string{true: "WebSocket", false: "HTTP polling"}[useWS])

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Stats reporter
	go statsLoop(ctx)

	if useWS {
		mineWS(ctx)
	} else {
		mineHTTP(ctx)
	}
}

/* -------------------------------------------------------------------------- */
/*                              HTTP POLLING MODE                              */
/* -------------------------------------------------------------------------- */

func mineHTTP(ctx context.Context) {
	client := &http.Client{Timeout: 10 * time.Second}

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Get work
		work, err := fetchWork(client)
		if err != nil {
			log.Printf("[MINER] getWork failed: %v (retrying in 5s)", err)
			time.Sleep(5 * time.Second)
			continue
		}

		log.Printf("[MINER] Got work: job=%s diff=%d", work.JobID[:16], work.Difficulty)

		// Mine
		nonce, mix, found := mineWork(ctx, work)
		if !found {
			log.Printf("[MINER] Work expired or cancelled, getting new work...")
			time.Sleep(500 * time.Millisecond) // small delay before next getWork
			continue
		}

		// Submit
		log.Printf("[MINER] Found solution! nonce=%d, submitting...", nonce)
		if err := submitWork(client, work, nonce, mix); err != nil {
			log.Printf("[MINER] submitWork failed: %v", err)
			time.Sleep(2 * time.Second) // backoff on submit failure
		} else {
			blockCount.Add(1)
			log.Printf("[MINER] BLOCK ACCEPTED! job=%s nonce=%d blocks=%d",
				work.JobID[:16], nonce, blockCount.Load())
			time.Sleep(500 * time.Millisecond) // brief pause before next job
		}
	}
}

func fetchWork(client *http.Client) (*Work, error) {
	resp, err := client.Get(nodeURL + "/getWork")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("status %d: %s", resp.StatusCode, string(body))
	}
	var work Work
	if err := json.NewDecoder(resp.Body).Decode(&work); err != nil {
		return nil, err
	}
	if work.JobID == "" || work.HeaderHex == "" {
		return nil, fmt.Errorf("invalid work: empty job_id or header_hex")
	}
	return &work, nil
}

func submitWork(client *http.Client, work *Work, nonce uint64, mix string) error {
	body := fmt.Sprintf(`{"job_id":"%s","header_hex":"%s","nonce":%d,"mix_hex":"%s","miner_address":"%s"}`,
		work.JobID, work.HeaderHex, nonce, mix, minerAddr)

	req, err := http.NewRequest("POST", nodeURL+"/submitWork", strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", apiKey)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/*                              WEBSOCKET MODE                                 */
/* -------------------------------------------------------------------------- */

func mineWS(ctx context.Context) {
	wsURL := strings.Replace(nodeURL, "http://", "ws://", 1)
	wsURL = strings.Replace(wsURL, "https://", "wss://", 1)
	wsURL += "/ws/mining"

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Printf("[MINER] Connecting to %s...", wsURL)
		conn, _, err := websocket.Dial(ctx, wsURL, nil)
		if err != nil {
			log.Printf("[MINER] WS connect failed: %v (retrying in 5s)", err)
			time.Sleep(5 * time.Second)
			continue
		}
		conn.SetReadLimit(1 << 16)

		log.Printf("[MINER] WebSocket connected")
		runWSSession(ctx, conn)
		conn.Close(websocket.StatusNormalClosure, "")
		log.Printf("[MINER] WebSocket disconnected, reconnecting...")
		time.Sleep(2 * time.Second)
	}
}

func runWSSession(ctx context.Context, conn *websocket.Conn) {
	// Track cancel func for current mining goroutine
	type cancelHolder struct {
		cancel context.CancelFunc
	}
	holder := &cancelHolder{cancel: func() {}}
	defer func() { holder.cancel() }()

	for {
		var msg map[string]json.RawMessage
		err := wsjson.Read(ctx, conn, &msg)
		if err != nil {
			return
		}

		var msgType string
		json.Unmarshal(msg["type"], &msgType)

		switch msgType {
		case "new_work":
			var work Work
			json.Unmarshal(msg["work"], &work)

			// Cancel previous mining, start new
			holder.cancel()
			mineCtx, cancel := context.WithCancel(ctx)
			holder.cancel = cancel

			go func() {
				nonce, mix, found := mineWork(mineCtx, &work)
				if !found {
					return
				}

				// Submit via WebSocket
				sub := map[string]any{
					"type":          "submit",
					"job_id":        work.JobID,
					"header_hex":    work.HeaderHex,
					"nonce":         nonce,
					"mix_hex":       mix,
					"miner_address": minerAddr,
				}
				wsjson.Write(ctx, conn, sub)
			}()

		case "accepted":
			blockCount.Add(1)
			log.Printf("[MINER] BLOCK ACCEPTED! blocks=%d", blockCount.Load())

		case "error":
			var errMsg string
			json.Unmarshal(msg["error"], &errMsg)
			log.Printf("[MINER] Server error: %s", errMsg)
		}
	}
}

/* -------------------------------------------------------------------------- */
/*                              MINING CORE                                    */
/* -------------------------------------------------------------------------- */

func mineWork(ctx context.Context, work *Work) (uint64, string, bool) {
	deadline := time.Unix(work.ExpiresAt, 0)
	diff := int(work.Difficulty)
	height := 0 // We don't know exact height, but DAGEpoch tells us

	// Use DAG if epoch > 0
	var dag *crypto.DAG
	if work.DAGEpoch > 0 || height >= core.DAGActivationHeight {
		dag = crypto.GetDAG(work.DAGEpoch)
	}

	type result struct {
		nonce uint64
		mix   string
	}
	found := make(chan result, 1)

	for t := 0; t < threads; t++ {
		go func(startNonce uint64) {
			for nonce := startNonce; ; nonce += uint64(threads) {
				select {
				case <-ctx.Done():
					return
				default:
				}

				if time.Now().After(deadline) {
					return
				}

				var mix string
				if dag != nil {
					mix = crypto.MixHashDAG(work.HeaderHex, nonce, dag)
				} else {
					mix = crypto.MixHash(work.HeaderHex, nonce)
				}

				hashCount.Add(1)

				if crypto.CheckMask(mix, diff) {
					select {
					case found <- result{nonce, mix}:
					default:
					}
					return
				}
			}
		}(uint64(t))
	}

	select {
	case r := <-found:
		return r.nonce, r.mix, true
	case <-ctx.Done():
		return 0, "", false
	case <-time.After(time.Until(deadline)):
		return 0, "", false
	}
}

/* -------------------------------------------------------------------------- */
/*                                 STATS                                       */
/* -------------------------------------------------------------------------- */

func statsLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	var lastCount uint64

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := hashCount.Load()
			delta := current - lastCount
			hps := float64(delta) / 10.0
			lastCount = current
			log.Printf("[MINER] %s | blocks: %d | shares: %d | total: %d hashes",
				core.FormatHashrate(hps), blockCount.Load(), shareCount.Load(), current)
		}
	}
}

/* -------------------------------------------------------------------------- */
/*                                HELPERS                                       */
/* -------------------------------------------------------------------------- */

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n := 0
	for _, c := range v {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	if n <= 0 {
		return def
	}
	return n
}
