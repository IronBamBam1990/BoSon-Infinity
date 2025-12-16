package main

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"
)

/*
   BOSON INFINITY — DESKTOP WALLET GUI
   -----------------------------------------------
   • 1 wallet per urządzenie (wallet.json)
   • Ed25519, adres = SHA512(pub)[:20] → hex (40)
   • GET  /api/wallet        — info o portfelu albo 404
   • POST /api/new_wallet    — tworzy lub ładuje wallet
   • GET  /api/balance       — saldo z noda
   • POST /api/send          — wysyłka BOS
   • POST /api/bridge_lock   — na razie DISABLED (stub)
*/
type NodeStats struct {
    Height           int     `json:"height"`
    DifficultyBits   int     `json:"difficulty_bits"`
    EstNetworkPretty string  `json:"est_network_pretty"`

    EnergyJPerHash    float64 `json:"energy_j_per_hash"`
    EnergyPricePerKWh float64 `json:"energy_price_per_kwh"`
    FiatCurrency      string  `json:"fiat_currency"`
    CostPerHash       float64 `json:"cost_per_hash"`
    CostPerBlock      float64 `json:"cost_per_block"`
    CostPerCoin       float64 `json:"cost_per_coin"`
    EnergyModelUpdated int64  `json:"energy_model_updated"`

    TotalMinted float64 `json:"total_minted"`
    MaxSupply   float64 `json:"max_supply"`
}

const (
    Decimals       = 8
    DefaultNodeURL = "http://94.130.151.250"
    BridgeEnabled  = false

    NetworkName = "boson-infinity-l0" // musi się zgadzać z nodem
    FeePermille = 1                   // 0.1%
)

func calcFee(amount uint64) uint64 {
    // 0.1% = FeePermille / 1000
    return (amount * uint64(FeePermille)) / 1000
}


var (
    UNIT           = uint64(math.Pow10(Decimals))
    walletFilePath = "wallet.json"
    currentWallet  *WalletFile
    httpClient     = &http.Client{Timeout: 10 * time.Second}
)

/* -------------------------------------------------------------------------- */
/*                                  TYPES                                      */
/* -------------------------------------------------------------------------- */

type Account struct {
    Balance      uint64 `json:"balance"`       // w BOS
    BalanceAtoms uint64 `json:"balance_atoms"` // w atomach
    Nonce        uint64 `json:"nonce"`
}

type txPayload struct {
    ChainID string `json:"chain_id"`
    From    string `json:"from"`
    To      string `json:"to"`
    Amount  uint64 `json:"amount"`
    Fee     uint64 `json:"fee"`
    Nonce   uint64 `json:"nonce"`
    PubKey  string `json:"pubkey"`
    Type    string `json:"type,omitempty"`
    Data    string `json:"data,omitempty"`
}

type Tx struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
	Fee    uint64 `json:"fee"`
	Nonce  uint64 `json:"nonce"`
	PubKey string `json:"pubkey"`
	Sig    string `json:"signature"`
	Hash   string `json:"hash"`
	Type   string `json:"type,omitempty"`
	Data   string `json:"data,omitempty"`
}

type WalletFile struct {
	Priv   string `json:"priv"`
	Pub    string `json:"pub"`
	Addr   string `json:"addr"`
	Node   string `json:"node_url"`
	APIKey string `json:"api_key"`
}

/* -------------------------------------------------------------------------- */
/*                             CRYPTO HELPERS                                  */
/* -------------------------------------------------------------------------- */

func handlePending(w http.ResponseWriter, r *http.Request) {
    if currentWallet == nil {
        respondJSON(w, 400, map[string]any{"error": "no_wallet"})
        return
    }

    url := fmt.Sprintf("%s/tx/pending?addr=%s", currentWallet.Node, currentWallet.Addr)
    var txs []Tx
    if err := httpGetJSON(url, &txs); err != nil {
        respondJSON(w, 500, map[string]any{"error": err.Error()})
        return
    }

    respondJSON(w, 200, txs)
}

// addrFromPub: adres = pierwsze 20 bajtów SHA512(pub) → hex (40 znaków)
func addrFromPub(pub []byte) string {
	sum := sha512.Sum512(pub)
	return hex.EncodeToString(sum[:20])
}

// HashBytes: SHA-512 → hex
func HashBytes(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

// BuildTx: kompatybilny z tym co robi nod przy walidacji
// BuildTx: kompatybilny z tym co robi nod przy walidacji (Ed25519 + chain_id)
func BuildTx(privHex, pubHex, from, to string,
    amount, nonce uint64, txType, data string) (Tx, error) {

    priv, err := hex.DecodeString(privHex)
    if err != nil || len(priv) != ed25519.PrivateKeySize {
        return Tx{}, fmt.Errorf("bad private key")
    }
    if _, err := hex.DecodeString(pubHex); err != nil {
        return Tx{}, fmt.Errorf("bad pubkey")
    }

    fee := calcFee(amount) // 0.1%

    payload := txPayload{
        ChainID: NetworkName,
        From:    from,
        To:      to,
        Amount:  amount,
        Fee:     fee,
        Nonce:   nonce,
        PubKey:  pubHex,
        Type:    txType,
        Data:    data,
    }

    raw, _ := json.Marshal(payload)

    sig := ed25519.Sign(priv, raw)
    sigHex := hex.EncodeToString(sig)
    h := HashBytes(raw)

    return Tx{
        From:   from,
        To:     to,
        Amount: amount,
        Fee:    fee,
        Nonce:  nonce,
        PubKey: pubHex,
        Sig:    sigHex,
        Hash:   h,
        Type:   txType,
        Data:   data,
    }, nil
}



/* -------------------------------------------------------------------------- */
/*                             WALLET FILE I/O                                 */
/* -------------------------------------------------------------------------- */

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
	if wf.Addr == "" || wf.Priv == "" || wf.Pub == "" {
		return nil, fmt.Errorf("wallet_corrupt")
	}
	if wf.Node == "" {
		wf.Node = DefaultNodeURL
	}
	return &wf, nil
}

func saveWallet(wf *WalletFile) error {
	tmp := walletFilePath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(f).Encode(wf); err != nil {
		f.Close()
		return err
	}
	f.Close()
	return os.Rename(tmp, walletFilePath)
}

func createNewWallet(nodeURL, apiKey string) (*WalletFile, error) {
	// twardo pilnujemy 1 wallet per device
	if _, err := os.Stat(walletFilePath); err == nil {
		return nil, fmt.Errorf("wallet_exists")
	}

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}

	addr := addrFromPub(pub)
	if nodeURL == "" {
		nodeURL = DefaultNodeURL
	}

	wf := &WalletFile{
		Priv:   hex.EncodeToString(priv),
		Pub:    hex.EncodeToString(pub),
		Addr:   addr,
		Node:   nodeURL,
		APIKey: apiKey,
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
	_ = json.NewEncoder(w).Encode(v)
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

	// pozwól na przecinek jako separator dziesiętny
	if strings.Contains(s, ",") {
		s = strings.ReplaceAll(s, ",", ".")
	}

	// bez części ułamkowej
	if !strings.Contains(s, ".") {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return 0, err
		}
		return v * UNIT, nil
	}

	parts := strings.SplitN(s, ".", 2)
	intPart := parts[0]
	fracPart := parts[1]

	if len(fracPart) > Decimals {
		fracPart = fracPart[:Decimals]
	}
	for len(fracPart) < Decimals {
		fracPart += "0"
	}

	i, err := strconv.ParseUint(intPart, 10, 64)
	if err != nil {
		return 0, err
	}
	f, err := strconv.ParseUint(fracPart, 10, 64)
	if err != nil {
		return 0, err
	}

	return i*UNIT + f, nil
}

func formatCoins(atoms uint64) string {
	intPart := atoms / UNIT
	frac := atoms % UNIT
	if frac == 0 {
		return fmt.Sprintf("%d", intPart)
	}
	return fmt.Sprintf("%d.%0*d", intPart, Decimals, frac)
}

/* -------------------------------------------------------------------------- */
/*                                HANDLERS                                     */
/* -------------------------------------------------------------------------- */

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, indexHTML)
}

func handleGetWallet(w http.ResponseWriter, r *http.Request) {
	if currentWallet == nil {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":"no_wallet"}`)
		return
	}

	resp := map[string]any{
		"addr":     currentWallet.Addr,
		"node_url": currentWallet.Node,
	}
	respondJSON(w, 200, resp)
}

type newWalletReq struct {
	NodeURL string `json:"nodeUrl"`
	APIKey  string `json:"apiKey"`
}

// NOWA LOGIKA: jeśli wallet.json już istnieje → wczytaj go zamiast rzucać wallet_exists
func handleNewWallet(w http.ResponseWriter, r *http.Request) {
	// 1) Spróbuj załadować istniejący wallet
	if wf, err := loadWallet(); err == nil {
		currentWallet = wf
		respondJSON(w, 200, map[string]any{
			"addr":     wf.Addr,
			"node_url": wf.Node,
		})
		return
	}

	// 2) Jak nie ma portfela → utwórz nowy
	var req newWalletReq
	_ = json.NewDecoder(r.Body).Decode(&req)

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

    // 1) Confirmed from node
    url := fmt.Sprintf("%s/account?addr=%s", currentWallet.Node, currentWallet.Addr)
    var acc Account
    if err := httpGetJSON(url, &acc); err != nil {
        respondJSON(w, 500, map[string]any{"error": err.Error()})
        return
    }

    atoms := acc.BalanceAtoms
    if atoms == 0 && acc.Balance > 0 {
        atoms = acc.Balance * UNIT
    }

    confirmed := atoms

    // 2) Pending TX (mempool)
    urlPending := fmt.Sprintf("%s/tx/pending?addr=%s", currentWallet.Node, currentWallet.Addr)
    var pending []Tx
    if err := httpGetJSON(urlPending, &pending); err != nil {
        // jak się nie uda, trudno – pokażemy tylko confirmed
        pending = nil
    }

    var pendingIn uint64
    var pendingOut uint64

    for _, tx := range pending {
        if tx.To == currentWallet.Addr {
            pendingIn += tx.Amount
        }
        if tx.From == currentWallet.Addr {
            // amount + fee
            pendingOut += tx.Amount + tx.Fee
        }
    }

    instantAtoms := confirmed + pendingIn - pendingOut

    respondJSON(w, 200, map[string]any{
        "addr":          currentWallet.Addr,
        "atoms":         confirmed,
        "coins":         formatCoins(confirmed),
        "instant_atoms": instantAtoms,
        "instant_coins": formatCoins(instantAtoms),
        "pending_in":    pendingIn,
        "pending_out":   pendingOut,
        "nonce":         acc.Nonce,
        "nodeUrl":       currentWallet.Node,
    })
}


func handleStats(w http.ResponseWriter, r *http.Request) {
    if currentWallet == nil {
        respondJSON(w, 400, map[string]any{"error": "no_wallet"})
        return
    }

    url := fmt.Sprintf("%s/stats", currentWallet.Node)
    var ns NodeStats
    if err := httpGetJSON(url, &ns); err != nil {
        respondJSON(w, 500, map[string]any{"error": err.Error()})
        return
    }

    respondJSON(w, 200, ns)
}

type sendReq struct {
    To     string `json:"to"`
    Amount string `json:"amount"`
}



func handleSend(w http.ResponseWriter, r *http.Request) {
    if currentWallet == nil {
        respondJSON(w, 400, map[string]any{"error": "no_wallet"})
        return
    }

    var req sendReq
    if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
        respondJSON(w, 400, map[string]any{"error": "bad_json"})
        return
    }

    amountAtoms, err := parseAmountStr(req.Amount)
    if err != nil {
        respondJSON(w, 400, map[string]any{"error": "bad_amount"})
        return
    }

    // pobierz nonce z noda
    urlAcc := fmt.Sprintf("%s/account?addr=%s", currentWallet.Node, currentWallet.Addr)
    var acc Account
    if err := httpGetJSON(urlAcc, &acc); err != nil {
        respondJSON(w, 500, map[string]any{"error": "account_query_failed"})
        return
    }

    nonce := acc.Nonce + 1

    tx, err := BuildTx(
        currentWallet.Priv,
        currentWallet.Pub,
        currentWallet.Addr,
        req.To,
        amountAtoms,
        nonce,
        "transfer",
        "",
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


func handleBridgeLock(w http.ResponseWriter, r *http.Request) {
	if !BridgeEnabled {
		respondJSON(w, 400, map[string]any{
			"error":   "bridge_disabled",
			"message": "Bridge to ERC-20 is not live yet.",
		})
		return
	}

	respondJSON(w, 400, map[string]any{"error": "not_implemented"})
}

/* -------------------------------------------------------------------------- */
/*                               BROWSER LAUNCH                                */
/* -------------------------------------------------------------------------- */

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
	// przy starcie próbujemy załadować istniejący wallet
	wf, err := loadWallet()
	if err == nil {
		currentWallet = wf
		log.Printf("[WALLET] Loaded wallet addr=%s node=%s\n", wf.Addr, wf.Node)
	} else {
		log.Printf("[WALLET] No wallet yet (%v)\n", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", handleIndex)
	mux.HandleFunc("/api/wallet", handleGetWallet)
	mux.HandleFunc("/api/new_wallet", handleNewWallet)
	mux.HandleFunc("/api/balance", handleBalance)
	mux.HandleFunc("/api/send", handleSend)
  mux.HandleFunc("/api/pending", handlePending)
	mux.HandleFunc("/api/bridge_lock", handleBridgeLock)
  mux.HandleFunc("/api/stats", handleStats) // NEW
	addr := "127.0.0.1:8090"
	log.Printf("[GUI] Listening on http://%s\n", addr)
	go openBrowser("http://" + addr)

	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatal(err)
	}
}

/* -------------------------------------------------------------------------- */
/*                                   HTML                                      */
/* -------------------------------------------------------------------------- */

const indexHTML = `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Boson Infinity — Desktop Wallet</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, sans-serif;
      background: radial-gradient(circle at top, #020617 0, #000 60%);
      color: #e5e7eb;
    }
    .card {
      max-width: 820px;
      margin: 0 auto;
      padding: 24px 28px;
      border-radius: 20px;
      background: rgba(15,23,42,0.96);
      border: 1px solid rgba(56,189,248,0.5);
      box-shadow: 0 24px 60px rgba(15,23,42,0.9);
    }
    h1 {
      margin-top: 0;
      font-size: 26px;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: #38bdf8;
    }
    h2 {
      margin-top: 20px;
      font-size: 16px;
      color: #e5e7eb;
    }
    .subtitle {
      font-size: 12px;
      color: #9ca3af;
      margin-bottom: 16px;
    }
    label {
      display: block;
      font-size: 13px;
      margin-top: 12px;
      color: #cbd5f5;
    }
    input {
      width: 100%;
      margin-top: 4px;
      padding: 8px 10px;
      border-radius: 10px;
      border: 1px solid #1f2937;
      background: rgba(15,23,42,0.9);
      color: #e5e7eb;
      font-size: 13px;
    }
    input:focus {
      outline: none;
      border-color: #38bdf8;
      box-shadow: 0 0 0 1px rgba(56,189,248,0.4);
    }
    button {
      margin-top: 14px;
      padding: 8px 16px;
      border-radius: 999px;
      border: 1px solid #38bdf8;
      background: radial-gradient(circle at top left, #0369a1, #020617 55%);
      color: #e0f2fe;
      font-size: 13px;
      cursor: pointer;
    }
    button.secondary {
      border-color: #4b5563;
      background: rgba(15,23,42,0.9);
      color: #e5e7eb;
      margin-left: 8px;
    }
    button:disabled {
      opacity: 0.4;
      cursor: not-allowed;
    }
    button:hover:not(:disabled) {
      filter: brightness(1.08);
    }
    .row {
      display: flex;
      gap: 16px;
      flex-wrap: wrap;
      margin-top: 8px;
    }
    .row > div {
      flex: 1 1 240px;
    }
    .mono {
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
      font-size: 12px;
      word-break: break-all;
    }
    .pill {
      display: inline-flex;
      align-items: center;
      padding: 3px 10px;
      border-radius: 999px;
      background: rgba(15,118,110,0.2);
      border: 1px solid rgba(45,212,191,0.5);
      font-size: 11px;
      color: #a5f3fc;
      margin-left: 8px;
    }
    .status {
      margin-top: 8px;
      font-size: 12px;
      color: #9ca3af;
    }
    .status.error { color: #f97373; }
    .status.success { color: #4ade80; }
    hr {
      margin: 18px 0;
      border: none;
      border-top: 1px solid rgba(31,41,55,0.8);
    }
    .tag {
      display: inline-flex;
      padding: 2px 8px;
      border-radius: 999px;
      border: 1px solid rgba(148,163,184,0.6);
      font-size: 11px;
      color: #9ca3af;
      margin-left: 6px;
    }
  </style>
</head>
<body>
  <div class="card">
    <h1>BOSON WALLET</h1>
    <div class="subtitle">
      Local desktop wallet for Boson Infinity. Keys stay on your machine.
    </div>

    <div id="section-no-wallet" style="display:none;">
      <h2>Setup wallet</h2>
      <div class="row">
        <div>
          <label>Node URL
            <input id="cfg-node" value="` + DefaultNodeURL + `" />
          </label>
        </div>
        <div>
          <label>Node API Key
            <input id="cfg-apikey" placeholder="same API key as for miner" />
          </label>
        </div>
      </div>
      <button onclick="createWallet()">Create / load wallet</button>
      <div id="create-status" class="status"></div>
    </div>

    <div id="section-wallet" style="display:none;">
      <h2>Your wallet <span class="pill">1 device → 1 wallet</span></h2>
      <label>Address
        <div class="mono" id="addr"></div>
      </label>
      <div class="row">
        <div>
          <label>Connected node
            <div class="mono" id="node"></div>
          </label>
        </div>
        <div>
          <label>Balance
            <div class="mono" id="balance">–</div>
          </label>
          <div class="status" id="pending-info"></div>
        </div>
      </div>
      <button onclick="refreshBalance()">Refresh balance</button>
      <button class="secondary" onclick="copyAddr()">Copy address</button>
      <div id="balance-status" class="status"></div>

      <hr />

      <h2>Send BOS</h2>
      <div class="row">
        <div>
          <label>Recipient address
            <input id="send-to" placeholder="40-hex Boson address" />
          </label>
        </div>
        <div>
          <label>Amount (BOS)
            <input id="send-amount" placeholder="1.0" />
          </label>
        </div>
        <div>
          <label>Fee
            <div class="mono">0.1% of amount (auto)</div>
          </label>
        </div>
      </div>
      <button onclick="sendTx()">Send</button>
      <div id="send-status" class="status"></div>

            <hr />

      <h2>Network energy & cost</h2>
      <div class="row">
        <div>
          <label>Height / Difficulty
            <div class="mono" id="stats-height">–</div>
          </label>
        </div>
        <div>
          <label>Network hashrate
            <div class="mono" id="stats-hashrate">–</div>
          </label>
        </div>
      </div>
      <div class="row">
        <div>
          <label>Energy model
            <div class="mono" id="stats-energy">–</div>
          </label>
        </div>
        <div>
          <label>Cost per 1 BOS (energy)
            <div class="mono" id="stats-cost-coin">–</div>
          </label>
        </div>
      </div>
      <div>
        <label>Your balance (energy value)
          <div class="mono" id="stats-balance-fiat">–</div>
        </label>
      </div>
      <button class="secondary" onclick="refreshStats()">Refresh energy stats</button>
      <div id="stats-status" class="status"></div>


      <h2>Bridge → ERC-20 (soon)
        <span class="tag">disabled</span>
      </h2>
      <div class="status">
        Bridge to ERC-20 is not live yet. Mining & native BOS transfers are active, ERC-20 minting will be enabled after the Ethereum contract + relayer go live.
      </div>
    </div>
  </div>

  <script>
	let g_balanceCoins = 0.0;

    async function api(path, opts) {
      const res = await fetch(path, opts || {});
      if (!res.ok) {
        let msg = "HTTP " + res.status;
        try {
          const j = await res.json();
          if (j.error) msg = j.error;
        } catch (e) {}
        throw new Error(msg);
      }
      return res.json();
    }

    async function loadWallet() {
      try {
        const w = await api("/api/wallet");
        document.getElementById("section-wallet").style.display = "";
        document.getElementById("section-no-wallet").style.display = "none";
        document.getElementById("addr").textContent = w.addr;
        document.getElementById("node").textContent = w.node_url;
        refreshBalance();
		await refreshStats(); // NEW
      } catch (e) {
        document.getElementById("section-wallet").style.display = "none";
        document.getElementById("section-no-wallet").style.display = "";
      }
    }

    async function createWallet() {
      const nodeUrl = document.getElementById("cfg-node").value.trim();
      const apiKey  = document.getElementById("cfg-apikey").value.trim();
      const status  = document.getElementById("create-status");
      status.textContent = "Preparing wallet...";
      status.classList.remove("error","success");
      try {
        const w = await api("/api/new_wallet", {
          method: "POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify({nodeUrl, apiKey})
        });
        status.textContent = "";
        document.getElementById("section-wallet").style.display = "";
        document.getElementById("section-no-wallet").style.display = "none";
        document.getElementById("addr").textContent = w.addr;
        document.getElementById("node").textContent = w.node_url;
        refreshBalance();
      } catch (e) {
        status.textContent = e.message;
        status.classList.add("error");
      }
    }

    async function refreshBalance() {
      const status = document.getElementById("balance-status");
      const el = document.getElementById("balance");
      const pendingInfo = document.getElementById("pending-info");

      status.textContent = "Loading balance...";
      status.classList.remove("error","success");

      try {
        const b = await api("/api/balance");

        // confirmed
        const confirmed = b.coins + " BOS";

        // instant: confirmed + pending_in - pending_out
        let line = confirmed;
        if (b.instant_coins && b.instant_coins !== b.coins) {
          line = b.instant_coins + " BOS (instant, confirmed: " + confirmed + ")";
        }

        el.textContent = line;
        g_balanceCoins = parseFloat(b.instant_coins || b.coins);

        // info o pending (jeśli są)
        if (b.pending_in || b.pending_out) {
          const pin  = (b.pending_in  || 0) / 1e8;
          const pout = (b.pending_out || 0) / 1e8;
          pendingInfo.textContent =
            "Pending: +" + pin + " BOS, -" + pout + " BOS";
        } else {
          pendingInfo.textContent = "";
        }

        status.textContent = "Balance updated.";
        status.classList.add("success");
      } catch (e) {
        status.textContent = e.message;
        status.classList.add("error");
      }
    }


    async function refreshStats() {
      const status = document.getElementById("stats-status");
      status.textContent = "Loading stats...";
      status.classList.remove("error","success");

      const elH = document.getElementById("stats-height");
      const elR = document.getElementById("stats-hashrate");
      const elE = document.getElementById("stats-energy");
      const elC = document.getElementById("stats-cost-coin");
      const elB = document.getElementById("stats-balance-fiat");

      try {
        const s = await api("/api/stats");

        elH.textContent = "#" + s.height + "  •  diff " + s.difficulty_bits;

        elR.textContent = s.est_network_pretty || "–";

        if (s.energy_j_per_hash > 0 && s.energy_price_per_kwh > 0 && s.cost_per_coin > 0) {
          elE.textContent =
            s.energy_j_per_hash.toExponential(3) + " J/hash  •  " +
            s.energy_price_per_kwh.toFixed(4) + " " + (s.fiat_currency || "FIAT") + "/kWh";

          elC.textContent = s.cost_per_coin.toFixed(6) + " " + (s.fiat_currency || "FIAT");

          if (g_balanceCoins > 0) {
            const val = g_balanceCoins * s.cost_per_coin;
            elB.textContent = g_balanceCoins.toFixed(4) + " BOS ≈ " +
              val.toFixed(2) + " " + (s.fiat_currency || "FIAT");
          } else {
            elB.textContent = "–";
          }
        } else {
          elE.textContent = "Energy model not available (oracle offline or stale).";
          elC.textContent = "–";
          elB.textContent = "–";
        }

        status.textContent = "Energy stats updated.";
        status.classList.add("success");
      } catch (e) {
        status.textContent = e.message;
        status.classList.add("error");
      }
    }


    async function sendTx() {
      const to     = document.getElementById("send-to").value.trim();
      const amount = document.getElementById("send-amount").value.trim();
      const status = document.getElementById("send-status");
      status.textContent = "Sending...";
      status.classList.remove("error","success");
      try {
        const res = await api("/api/send", {
          method: "POST",
          headers: {"Content-Type":"application/json"},
          body: JSON.stringify({to, amount}) // <-- bez fee
        });
        status.textContent = "Sent. TX hash: " + res.hash;
        status.classList.add("success");
        refreshBalance();
      } catch (e) {
        status.textContent = e.message;
        status.classList.add("error");
      }
    }


    function copyAddr() {
      const addr = document.getElementById("addr").textContent.trim();
      if (!addr) return;
      navigator.clipboard.writeText(addr).then(() => {
        const st = document.getElementById("balance-status");
        st.textContent = "Address copied to clipboard.";
        st.classList.remove("error");
        st.classList.add("success");
      }).catch(() => {});
    }

    window.addEventListener("load", () => {
  loadWallet();
  // auto-refresh co 1s
  setInterval(() => {
    refreshBalance();
  }, 1000);
});

  </script>
</body>
</html>
`
