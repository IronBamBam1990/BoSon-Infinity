//go:build wallet

package main

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bcrypto "github.com/IronBamBam1990/BoSon-Infinity/crypto"
)

const (
	WalletVersion = "2.1.0"
	BridgeEnabled = false
)

var (
	walletFilePath = "wallet.json"
	currentWallet  *WalletFile
	httpClient     = &http.Client{Timeout: 10 * time.Second}
	sessionToken   string
)

/* -------------------------------------------------------------------------- */
/*                                  TYPES                                      */
/* -------------------------------------------------------------------------- */

// WalletFile — on-disk format. PrivEnc is the Argon2id+AES-256-GCM encrypted key.
type WalletFile struct {
	PrivEnc string `json:"priv_enc,omitempty"` // encrypted private key (new format)
	Priv    string `json:"priv,omitempty"`     // plaintext (legacy, migrated on save)
	Pub     string `json:"pub"`
	Addr    string `json:"addr"`
	Node    string `json:"node_url"`
	APIKey  string `json:"api_key"`
}

type AccountResp struct {
	Balance      uint64  `json:"balance"`
	BalanceAtoms uint64  `json:"balance_atoms"`
	Nonce        uint64  `json:"nonce"`
}

/* -------------------------------------------------------------------------- */
/*                             WALLET FILE I/O                                 */
/* -------------------------------------------------------------------------- */

func walletNodeURL() string {
	if v := os.Getenv("BOSON_NODE_URL"); v != "" {
		return v
	}
	return "http://127.0.0.1:8080"
}

func walletPassphrase() string {
	return os.Getenv("BOSON_WALLET_PASS")
}

func loadWallet() (*WalletFile, error) {
	f, err := os.Open(walletFilePath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("no_wallet")
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var wf WalletFile
	if err := json.NewDecoder(f).Decode(&wf); err != nil {
		return nil, err
	}
	if wf.Addr == "" || wf.Pub == "" {
		return nil, fmt.Errorf("wallet_corrupt")
	}
	if wf.Node == "" {
		wf.Node = walletNodeURL()
	}

	// Migrate: if legacy plaintext key exists, encrypt it
	if wf.Priv != "" && wf.PrivEnc == "" {
		pass := walletPassphrase()
		if pass != "" {
			enc, err := bcrypto.EncryptPrivKey([]byte(wf.Priv), pass)
			if err == nil {
				wf.PrivEnc = enc
				wf.Priv = "" // remove plaintext
				saveWallet(&wf)
				log.Println("[WALLET] Migrated private key to encrypted format")
			}
		} else {
			log.Println("[WARN] BOSON_WALLET_PASS not set — private key stored in plaintext!")
		}
	}

	return &wf, nil
}

func saveWallet(wf *WalletFile) error {
	tmp := walletFilePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(wf); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, walletFilePath)
}

func getPrivKey(wf *WalletFile) (string, error) {
	// New encrypted format
	if wf.PrivEnc != "" {
		pass := walletPassphrase()
		if pass == "" {
			return "", fmt.Errorf("BOSON_WALLET_PASS required to decrypt private key")
		}
		plaintext, err := bcrypto.DecryptPrivKey(wf.PrivEnc, pass)
		if err != nil {
			return "", fmt.Errorf("decrypt failed: %w", err)
		}
		return string(plaintext), nil
	}
	// Legacy plaintext
	if wf.Priv != "" {
		return wf.Priv, nil
	}
	return "", fmt.Errorf("no private key in wallet")
}

func createNewWallet(nodeURL, apiKey string) (*WalletFile, error) {
	if _, err := os.Stat(walletFilePath); err == nil {
		return nil, fmt.Errorf("wallet_exists")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	addr := bcrypto.AddrFromPub(pub)
	if nodeURL == "" {
		nodeURL = walletNodeURL()
	}

	privHex := hex.EncodeToString(priv)

	wf := &WalletFile{
		Pub:    hex.EncodeToString(pub),
		Addr:   addr,
		Node:   nodeURL,
		APIKey: apiKey,
	}

	// Encrypt if passphrase is set
	pass := walletPassphrase()
	if pass != "" {
		enc, err := bcrypto.EncryptPrivKey([]byte(privHex), pass)
		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %w", err)
		}
		wf.PrivEnc = enc
	} else {
		wf.Priv = privHex
		log.Println("[WARN] BOSON_WALLET_PASS not set — private key stored in plaintext!")
	}

	if err := saveWallet(wf); err != nil {
		return nil, err
	}
	return wf, nil
}

/* -------------------------------------------------------------------------- */
/*                                HTTP HELPERS                                 */
/* -------------------------------------------------------------------------- */

func respondJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func httpGetJSON(url string, dst any) error {
	resp, err := httpClient.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status_%d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(dst)
}

func httpPostJSON(url string, payload any, apiKey string, dst any) error {
	body, _ := json.Marshal(payload)
	req, err := http.NewRequest("POST", url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set("X-API-Key", apiKey)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("status_%d", resp.StatusCode)
	}
	if dst != nil {
		return json.NewDecoder(resp.Body).Decode(dst)
	}
	return nil
}

/* -------------------------------------------------------------------------- */
/*                             AMOUNT PARSING                                  */
/* -------------------------------------------------------------------------- */

func parseAmountStr(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty")
	}
	if strings.Contains(s, ",") {
		s = strings.ReplaceAll(s, ",", ".")
	}
	if !strings.Contains(s, ".") {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return v * core.UNIT, nil
	}
	parts := strings.SplitN(s, ".", 2)
	fracPart := parts[1]
	if len(fracPart) > core.Decimals {
		fracPart = fracPart[:core.Decimals]
	}
	for len(fracPart) < core.Decimals {
		fracPart += "0"
	}
	i, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseUint(fracPart, 10, 64)
	if err != nil {
		return 0, err
	}
	return i*core.UNIT + f, nil
}

func formatCoins(atoms uint64) string {
	intPart := atoms / core.UNIT
	frac := atoms % core.UNIT
	if frac == 0 {
		return fmt.Sprintf("%d", intPart)
	}
	return fmt.Sprintf("%d.%0*d", intPart, core.Decimals, frac)
}

/* -------------------------------------------------------------------------- */
/*                                HANDLERS                                     */
/* -------------------------------------------------------------------------- */

func handleGetWallet(w http.ResponseWriter, r *http.Request) {
	if currentWallet == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"no_wallet"}`)
		return
	}
	respondJSON(w, 200, map[string]any{
		"addr":      currentWallet.Addr,
		"node_url":  currentWallet.Node,
		"encrypted": currentWallet.PrivEnc != "",
	})
}

func handleNewWallet(w http.ResponseWriter, r *http.Request) {
	if wf, err := loadWallet(); err == nil {
		currentWallet = wf
		respondJSON(w, 200, map[string]any{
			"addr":     wf.Addr,
			"node_url": wf.Node,
		})
		return
	}

	var req struct {
		NodeURL string `json:"nodeUrl"`
		APIKey  string `json:"apiKey"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	wf, err := createNewWallet(req.NodeURL, req.APIKey)
	if err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	currentWallet = wf
	respondJSON(w, 200, map[string]any{
		"addr":     wf.Addr,
		"node_url": wf.Node,
	})
}

func handleBalance(w http.ResponseWriter, r *http.Request) {
	if currentWallet == nil {
		respondJSON(w, 400, map[string]any{"error": "no_wallet"})
		return
	}
	url := fmt.Sprintf("%s/account?addr=%s", currentWallet.Node, currentWallet.Addr)
	var acc AccountResp
	if err := httpGetJSON(url, &acc); err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	atoms := acc.BalanceAtoms
	if atoms == 0 && acc.Balance > 0 {
		atoms = acc.Balance * core.UNIT
	}
	respondJSON(w, 200, map[string]any{
		"addr":  currentWallet.Addr,
		"atoms": atoms,
		"coins": formatCoins(atoms),
		"nonce": acc.Nonce,
	})
}

func handleSend(w http.ResponseWriter, r *http.Request) {
	if currentWallet == nil {
		respondJSON(w, 400, map[string]any{"error": "no_wallet"})
		return
	}
	var req struct {
		To     string `json:"to"`
		Amount string `json:"amount"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondJSON(w, 400, map[string]any{"error": "bad_json"})
		return
	}
	if !core.IsValidAddr(req.To) {
		respondJSON(w, 400, map[string]any{"error": "invalid_address"})
		return
	}
	amountAtoms, err := parseAmountStr(req.Amount)
	if err != nil || amountAtoms == 0 {
		respondJSON(w, 400, map[string]any{"error": "bad_amount"})
		return
	}

	// Get nonce
	urlAcc := fmt.Sprintf("%s/account?addr=%s", currentWallet.Node, currentWallet.Addr)
	var acc AccountResp
	if err := httpGetJSON(urlAcc, &acc); err != nil {
		respondJSON(w, 500, map[string]any{"error": "account_query_failed"})
		return
	}

	// Decrypt private key
	privHex, err := getPrivKey(currentWallet)
	if err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}

	fee := (amountAtoms * uint64(core.FeePermille)) / 1000
	if fee == 0 {
		fee = 1
	}

	tx, err := bcrypto.BuildTx(
		privHex, currentWallet.Pub, currentWallet.Addr, req.To,
		amountAtoms, fee, acc.Nonce+1, "transfer", "",
	)
	if err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}

	urlTx := fmt.Sprintf("%s/tx/submit", currentWallet.Node)
	if err := httpPostJSON(urlTx, tx, currentWallet.APIKey, nil); err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	respondJSON(w, 200, map[string]any{"ok": true, "hash": tx.Hash})
}

func handleStats(w http.ResponseWriter, r *http.Request) {
	if currentWallet == nil {
		respondJSON(w, 400, map[string]any{"error": "no_wallet"})
		return
	}
	url := fmt.Sprintf("%s/stats", currentWallet.Node)
	var stats map[string]any
	if err := httpGetJSON(url, &stats); err != nil {
		respondJSON(w, 500, map[string]any{"error": err.Error()})
		return
	}
	respondJSON(w, 200, stats)
}

/* -------------------------------------------------------------------------- */
/*                               SECURITY                                      */
/* -------------------------------------------------------------------------- */

func generateSessionToken() string {
	t, _ := core.GenerateSecureToken(16)
	return t
}

func requireSession(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/wallet" && r.Method == "GET" {
			next(w, r)
			return
		}
		if r.URL.Path == "/" {
			next(w, r)
			return
		}
		token := r.Header.Get("X-Session-Token")
		if token == "" {
			token = r.URL.Query().Get("_token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(sessionToken)) != 1 {
			respondJSON(w, 403, map[string]any{"error": "invalid_session"})
			return
		}
		next(w, r)
	}
}

func walletSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline'; connect-src 'self'")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		next.ServeHTTP(w, r)
	})
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

/* -------------------------------------------------------------------------- */
/*                                   MAIN                                      */
/* -------------------------------------------------------------------------- */

func main() {
	core.InitConsensus()
	sessionToken = generateSessionToken()
	log.Printf("[WALLET] Boson Infinity Wallet v%s\n", WalletVersion)

	wf, err := loadWallet()
	if err == nil {
		currentWallet = wf
		log.Printf("[WALLET] Loaded wallet addr=%s node=%s encrypted=%v\n",
			wf.Addr, wf.Node, wf.PrivEnc != "")
	} else {
		log.Printf("[WALLET] No wallet yet (%v)\n", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		html := strings.Replace(indexHTML, "%%SESSION_TOKEN%%", sessionToken, 1)
		fmt.Fprint(w, html)
	})
	mux.HandleFunc("/api/wallet", requireSession(handleGetWallet))
	mux.HandleFunc("/api/new_wallet", requireSession(handleNewWallet))
	mux.HandleFunc("/api/balance", requireSession(handleBalance))
	mux.HandleFunc("/api/send", requireSession(handleSend))
	mux.HandleFunc("/api/stats", requireSession(handleStats))

	listenAddr := "127.0.0.1:8090"
	log.Printf("[GUI] Listening on http://%s\n", listenAddr)
	go openBrowser("http://" + listenAddr)

	server := &http.Server{
		Addr:              listenAddr,
		Handler:           walletSecurityHeaders(mux),
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

// Placeholder HTML — reuse from original wallet_gui.go or replace with full UI
const indexHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Boson Infinity Wallet v2</title>
  <style>
    body { font-family: system-ui; background: #0a0a0a; color: #e5e7eb; padding: 32px; }
    .card { max-width: 600px; margin: 0 auto; padding: 24px; border-radius: 16px; background: #111827; border: 1px solid #1f2937; }
    h1 { color: #38bdf8; font-size: 22px; }
    .mono { font-family: monospace; font-size: 12px; word-break: break-all; }
    button { padding: 8px 16px; border-radius: 8px; border: 1px solid #38bdf8; background: #0c4a6e; color: #e0f2fe; cursor: pointer; margin: 4px; }
    input { width: 100%; padding: 8px; border-radius: 8px; border: 1px solid #1f2937; background: #1e293b; color: #e5e7eb; margin: 4px 0; }
    #status { margin-top: 16px; font-size: 13px; color: #9ca3af; }
  </style>
</head>
<body>
  <div class="card">
    <h1>BOSON WALLET v2</h1>
    <p style="font-size:12px;color:#6b7280">Keys encrypted with Argon2id + AES-256-GCM. Keys never leave your machine.</p>
    <div id="wallet-info"></div>
    <hr style="border-color:#1f2937">
    <div>
      <button onclick="initWallet()">Load / Create Wallet</button>
      <button onclick="getBalance()">Refresh Balance</button>
      <button onclick="getStats()">Network Stats</button>
    </div>
    <hr style="border-color:#1f2937">
    <div>
      <label>To Address:</label>
      <input id="to" placeholder="40 hex chars">
      <label>Amount (BOS):</label>
      <input id="amount" placeholder="e.g. 1.5">
      <button onclick="sendTx()">Send</button>
    </div>
    <div id="status"></div>
  </div>
  <script>
    const TOKEN = "%%SESSION_TOKEN%%";
    const H = {"X-Session-Token": TOKEN, "Content-Type": "application/json"};
    const status = s => document.getElementById("status").innerHTML = s;
    async function initWallet() {
      const r = await fetch("/api/new_wallet", {method:"POST", headers:H});
      const d = await r.json();
      if(d.addr) { document.getElementById("wallet-info").innerHTML = '<p class="mono">Address: '+d.addr+'</p><p>Node: '+d.node_url+'</p>'; status("Wallet loaded."); }
      else status("Error: "+JSON.stringify(d));
    }
    async function getBalance() {
      const r = await fetch("/api/balance", {headers:H});
      const d = await r.json();
      if(d.coins!==undefined) status("Balance: "+d.coins+" BOS ("+d.atoms+" atoms) | Nonce: "+d.nonce);
      else status("Error: "+JSON.stringify(d));
    }
    async function sendTx() {
      const to = document.getElementById("to").value;
      const amount = document.getElementById("amount").value;
      const r = await fetch("/api/send", {method:"POST", headers:H, body:JSON.stringify({to,amount})});
      const d = await r.json();
      if(d.ok) status("TX sent! Hash: "+d.hash);
      else status("Error: "+JSON.stringify(d));
    }
    async function getStats() {
      const r = await fetch("/api/stats", {headers:H});
      const d = await r.json();
      status("Height: "+d.height+" | Difficulty: "+d.difficulty_bits+" | Network: "+(d.est_network_pretty||"N/A")+" | Minted: "+(d.total_minted||0)+" / "+(d.max_supply||0)+" BOS");
    }
    initWallet();
  </script>
</body>
</html>`
