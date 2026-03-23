package rpc

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"nhooyr.io/websocket"
)

/* -------------------------------------------------------------------------- */
/*                        MINING WEBSOCKET PROTOCOL                            */
/* -------------------------------------------------------------------------- */
// Miners connect to /ws/mining. The server pushes new Work objects
// whenever a new block is mined or mempool changes significantly.
// Miners submit solutions over the same WebSocket.

const (
	JobPushInterval = 5 * time.Second  // push new work every 5s
	WSWriteTimeout  = 10 * time.Second
	WSMaxMsgSize    = 1 << 16 // 64KB
)

// MiningHub manages connected miners and pushes work.
type MiningHub struct {
	mu      sync.Mutex
	clients map[*miningClient]struct{}
	ns      *NodeState
}

type miningClient struct {
	conn *websocket.Conn
	send chan []byte
}

func NewMiningHub(ns *NodeState) *MiningHub {
	return &MiningHub{
		clients: make(map[*miningClient]struct{}),
		ns:      ns,
	}
}

// Start begins the periodic work push goroutine.
func (h *MiningHub) Start() {
	go h.pushLoop()
}

func (h *MiningHub) pushLoop() {
	ticker := time.NewTicker(JobPushInterval)
	defer ticker.Stop()

	for range ticker.C {
		h.PushWork()
	}
}

// PushWork sends current work to all connected miners.
func (h *MiningHub) PushWork() {
	h.ns.Mu.Lock()
	if h.ns.Chain == nil || len(h.ns.Chain.Blocks) == 0 {
		h.ns.Mu.Unlock()
		return
	}
	work := buildWork(h.ns)
	h.ns.Mu.Unlock()

	data, err := json.Marshal(map[string]any{
		"type": "new_work",
		"work": work,
	})
	if err != nil {
		return
	}

	h.mu.Lock()
	for client := range h.clients {
		select {
		case client.send <- data:
		default:
			// client too slow, skip
		}
	}
	h.mu.Unlock()
}

// NotifyNewBlock should be called when a new block arrives to push work immediately.
func (h *MiningHub) NotifyNewBlock() {
	go h.PushWork()
}

// ClientCount returns number of connected miners.
func (h *MiningHub) ClientCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.clients)
}

func (h *MiningHub) addClient(c *miningClient) {
	h.mu.Lock()
	h.clients[c] = struct{}{}
	h.mu.Unlock()
	slog.Info("miner connected via WebSocket", "total", h.ClientCount())
}

func (h *MiningHub) removeClient(c *miningClient) {
	h.mu.Lock()
	delete(h.clients, c)
	h.mu.Unlock()
	slog.Info("miner disconnected", "total", h.ClientCount())
}

// MiningWSHandler handles WebSocket connections for miners.
func MiningWSHandler(ns *NodeState, hub *MiningHub, broadcastFn func(block any)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
			OriginPatterns: []string{"*"},
		})
		if err != nil {
			slog.Warn("ws accept failed", "error", err)
			return
		}
		conn.SetReadLimit(WSMaxMsgSize)

		client := &miningClient{
			conn: conn,
			send: make(chan []byte, 16),
		}
		hub.addClient(client)
		defer hub.removeClient(client)

		ctx := r.Context()

		// Writer goroutine: sends work to miner
		go func() {
			for {
				select {
				case msg, ok := <-client.send:
					if !ok {
						return
					}
					writeCtx, cancel := context.WithTimeout(ctx, WSWriteTimeout)
					err := conn.Write(writeCtx, websocket.MessageText, msg)
					cancel()
					if err != nil {
						return
					}
				case <-ctx.Done():
					return
				}
			}
		}()

		// Send initial work immediately
		ns.Mu.Lock()
		if ns.Chain != nil && len(ns.Chain.Blocks) > 0 {
			work := buildWork(ns)
			ns.Mu.Unlock()
			data, _ := json.Marshal(map[string]any{
				"type": "new_work",
				"work": work,
			})
			select {
			case client.send <- data:
			default:
			}
		} else {
			ns.Mu.Unlock()
		}

		// Reader loop: receive solutions from miner
		for {
			_, msg, err := conn.Read(ctx)
			if err != nil {
				return // disconnect
			}

			var sub struct {
				Type      string `json:"type"`
				HeaderHex string `json:"header_hex"`
				Nonce     uint64 `json:"nonce"`
				MixHex    string `json:"mix_hex"`
				MinerAddr string `json:"miner_address"`
				JobID     string `json:"job_id"`
			}
			if err := json.Unmarshal(msg, &sub); err != nil {
				sendWSError(client, "bad_json")
				continue
			}

			if sub.Type != "submit" {
				sendWSError(client, "unknown_type")
				continue
			}

			ns.Mu.Lock()
			err = SubmitSolved(ns, sub.JobID, sub.HeaderHex, sub.MixHex, sub.MinerAddr, sub.Nonce, nil)
			ns.Mu.Unlock()

			if err != nil {
				sendWSError(client, "rejected")
				continue
			}

			// Success — notify hub to push new work to all miners
			response, _ := json.Marshal(map[string]any{
				"type":   "accepted",
				"job_id": sub.JobID,
			})
			select {
			case client.send <- response:
			default:
			}

			hub.NotifyNewBlock()
		}
	}
}

func sendWSError(c *miningClient, msg string) {
	data, _ := json.Marshal(map[string]any{
		"type":  "error",
		"error": msg,
	})
	select {
	case c.send <- data:
	default:
	}
}
