package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

const version = "2.1.0"

var (
	nodeURL = "http://127.0.0.1:8080"
	client  = &http.Client{Timeout: 10 * time.Second}
)

func main() {
	if v := os.Getenv("BOSON_NODE_URL"); v != "" {
		nodeURL = v
	}

	args := os.Args[1:]
	if len(args) == 0 {
		printUsage()
		return
	}

	switch args[0] {
	case "status", "info":
		cmdStatus()
	case "stats":
		cmdStats()
	case "balance":
		if len(args) < 2 {
			fatal("Usage: boson-cli balance <address>")
		}
		cmdBalance(args[1])
	case "block":
		if len(args) < 2 {
			fatal("Usage: boson-cli block <height>")
		}
		cmdBlock(args[1])
	case "tx":
		if len(args) < 2 {
			fatal("Usage: boson-cli tx <hash>")
		}
		cmdTx(args[1])
	case "history":
		if len(args) < 2 {
			fatal("Usage: boson-cli history <address>")
		}
		cmdHistory(args[1])
	case "mempool":
		cmdMempool()
	case "peers":
		cmdPeers()
	case "metrics":
		cmdMetrics()
	case "version":
		fmt.Printf("boson-cli v%s\nNode: %s\n", version, nodeURL)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", args[0])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`boson-cli v%s — Boson Infinity command-line interface

Usage: boson-cli <command> [args]

Commands:
  status              Node health check
  stats               Network statistics
  balance <addr>      Account balance
  block <height>      View block by height
  tx <hash>           View transaction by hash
  history <addr>      Transaction history for address
  mempool             View mempool contents
  peers               List connected peers
  metrics             Raw Prometheus metrics
  version             Show version

Environment:
  BOSON_NODE_URL      Node URL (default: http://127.0.0.1:8080)

`, version)
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func apiGet(path string) (map[string]any, error) {
	resp, err := client.Get(nodeURL + path)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()
	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func apiGetRaw(path string) (string, error) {
	resp, err := client.Get(nodeURL + path)
	if err != nil {
		return "", fmt.Errorf("connection failed: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func prettyJSON(v any) string {
	b, _ := json.MarshalIndent(v, "", "  ")
	return string(b)
}

func cmdStatus() {
	data, err := apiGet("/health")
	if err != nil {
		fatal("Node unreachable: " + err.Error())
	}
	fmt.Printf("Node: %s\n", nodeURL)
	fmt.Printf("Status: %s\n", data["status"])
	fmt.Printf("Height: %.0f\n", data["height"])
	fmt.Printf("Blocks: %.0f\n", data["blocks"])
	fmt.Printf("Accounts: %.0f\n", data["accounts"])
	fmt.Printf("Mempool: %.0f txs\n", data["mempool"])
}

func cmdStats() {
	data, err := apiGet("/stats")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Height:       %.0f\n", data["height"])
	fmt.Printf("Difficulty:   %.0f bits\n", data["difficulty_bits"])
	fmt.Printf("Block Time:   %.1fs avg\n", data["avg_block_seconds"])
	fmt.Printf("Hashrate:     %s\n", data["est_network_pretty"])
	fmt.Printf("Minted:       %.2f / %.0f BOS\n", data["total_minted"], data["max_supply"])
	if cpc, ok := data["cost_per_coin"].(float64); ok && cpc > 0 {
		fmt.Printf("Cost/Coin:    %.4f %s\n", cpc, data["fiat_currency"])
	}
}

func cmdBalance(addr string) {
	if len(addr) != 40 {
		fatal("Invalid address: must be 40 hex characters")
	}
	data, err := apiGet("/account?addr=" + addr)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("Address: %s\n", addr)
	fmt.Printf("Balance: %v BOS\n", data["balance"])
	fmt.Printf("Atoms:   %.0f\n", data["balance_atoms"])
	fmt.Printf("Nonce:   %.0f\n", data["nonce"])
}

func cmdBlock(height string) {
	data, err := apiGet("/block?height=" + height)
	if err != nil {
		fatal(err.Error())
	}
	if errMsg, ok := data["error"]; ok {
		fatal(fmt.Sprintf("Error: %v", errMsg))
	}
	header, _ := data["header"].(map[string]any)
	fmt.Printf("Block #%.0f\n", header["height"])
	fmt.Printf("Hash:       %s\n", data["hash"])
	fmt.Printf("Prev:       %s\n", header["prev_hash"])
	fmt.Printf("Miner:      %s\n", header["miner"])
	fmt.Printf("Time:       %s\n", header["timestamp"])
	fmt.Printf("Difficulty: %.0f bits\n", header["difficulty"])
	fmt.Printf("Nonce:      %.0f\n", header["nonce"])
	if txs, ok := data["txs"].([]any); ok {
		fmt.Printf("TXs:        %d\n", len(txs))
		for i, tx := range txs {
			t, _ := tx.(map[string]any)
			fmt.Printf("  [%d] %s → %s  %.0f atoms\n", i,
				shortStr(fmt.Sprint(t["from"]), 10),
				shortStr(fmt.Sprint(t["to"]), 10),
				t["amount"])
		}
	}
}

func cmdTx(hash string) {
	data, err := apiGet("/tx/get?hash=" + hash)
	if err != nil {
		fatal(err.Error())
	}
	if errMsg, ok := data["error"]; ok {
		fatal(fmt.Sprintf("Error: %v", errMsg))
	}
	tx, _ := data["tx"].(map[string]any)
	fmt.Printf("TX: %s\n", tx["hash"])
	fmt.Printf("Status:  %s\n", data["status"])
	fmt.Printf("From:    %s\n", tx["from"])
	fmt.Printf("To:      %s\n", tx["to"])
	fmt.Printf("Amount:  %.0f atoms\n", tx["amount"])
	fmt.Printf("Fee:     %.0f atoms\n", tx["fee"])
	fmt.Printf("Nonce:   %.0f\n", tx["nonce"])
	fmt.Printf("Type:    %v\n", tx["type"])
	if bh, ok := data["block_height"]; ok {
		fmt.Printf("Block:   #%.0f\n", bh)
	}
}

func cmdHistory(addr string) {
	if len(addr) != 40 {
		fatal("Invalid address: must be 40 hex characters")
	}
	data, err := apiGet("/address/txs?addr=" + addr + "&limit=20")
	if err != nil {
		fatal(err.Error())
	}
	txs, _ := data["txs"].([]any)
	fmt.Printf("Address: %s\n", addr)
	fmt.Printf("Showing: %d transactions\n\n", len(txs))
	for _, item := range txs {
		entry, _ := item.(map[string]any)
		tx, _ := entry["tx"].(map[string]any)
		dir := "→"
		if fmt.Sprint(tx["to"]) == addr {
			dir = "←"
		}
		fmt.Printf("  #%.0f %s %s %s  %.0f atoms  [%s]\n",
			entry["block_height"], dir,
			shortStr(fmt.Sprint(tx["from"]), 8),
			shortStr(fmt.Sprint(tx["to"]), 8),
			tx["amount"],
			shortStr(fmt.Sprint(tx["hash"]), 12))
	}
}

func cmdMempool() {
	data, err := apiGet("/tx/pool")
	if err != nil {
		fatal(err.Error())
	}
	// Pool returns array directly
	fmt.Println(prettyJSON(data))
}

func cmdPeers() {
	raw, err := apiGetRaw("/health")
	if err != nil {
		fatal(err.Error())
	}
	// Try P2P port
	p2pURL := strings.Replace(nodeURL, ":8080", ":8081", 1)
	resp, err2 := client.Get(p2pURL + "/peers/list")
	if err2 != nil {
		fmt.Printf("Node healthy: %s\n", raw)
		fmt.Println("P2P port unreachable — try BOSON_NODE_URL with P2P port")
		return
	}
	defer resp.Body.Close()
	var data map[string]any
	json.NewDecoder(resp.Body).Decode(&data)
	fmt.Println(prettyJSON(data))
}

func cmdMetrics() {
	raw, err := apiGetRaw("/metrics")
	if err != nil {
		fatal(err.Error())
	}
	fmt.Print(raw)
}

func shortStr(s string, n int) string {
	if len(s) > n {
		return s[:n] + ".."
	}
	return s
}
