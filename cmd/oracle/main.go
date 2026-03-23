package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

/* -------------------------------------------------------------------------- */
/*                     ENERGY ORACLE / AGGREGATOR                              */
/* -------------------------------------------------------------------------- */

type MinerReport struct {
	MinerID           string  `json:"miner_id"`
	HashrateHps       float64 `json:"hashrate_hps"`
	PowerWatts        float64 `json:"power_watts"`
	EnergyPricePerKWh float64 `json:"energy_price_per_kwh"`
	FiatCurrency      string  `json:"fiat_currency"`
	Country           string  `json:"country"`
	ReportedAt        int64   `json:"reported_at"`
	Sig               string  `json:"sig"`
}

type EnergyModel struct {
	AvgJoulesPerHash float64 `json:"avg_j_per_hash"`
	AvgPricePerKWh   float64 `json:"avg_price_per_kwh"`
	FiatCurrency     string  `json:"fiat_currency"`
	UpdatedAt        int64   `json:"updated_at"`
	SampleCount      int     `json:"sample_count"`
	MinCostPerHash   float64 `json:"min_cost_per_hash"`
}

const (
	maxMiners       = 1000
	reportCooldownS = 30
	maxReportAge    = 15 * 60
)

var (
	modelPath    string
	reportsMu    sync.Mutex
	lastReport   = map[string]MinerReport{}
	lastReportTS = map[string]int64{}
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func trimmedMean(vals []float64, trimFrac float64) float64 {
	n := len(vals)
	if n == 0 {
		return 0
	}
	sort.Float64s(vals)
	cut := int(trimFrac * float64(n))
	if cut*2 >= n {
		sum := 0.0
		for _, v := range vals {
			sum += v
		}
		return sum / float64(n)
	}
	vals = vals[cut : n-cut]
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

func verifyReportHMAC(rep MinerReport, secret string) bool {
	if secret == "" {
		return true
	}
	if rep.Sig == "" {
		return false
	}
	msg := fmt.Sprintf("%s|%.6f|%.6f|%d", rep.MinerID, rep.HashrateHps, rep.PowerWatts, rep.ReportedAt)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(msg))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(rep.Sig), []byte(expected))
}

func recomputeModelLocked() (*EnergyModel, error) {
	now := time.Now().Unix()

	type prepared struct {
		jPerHash float64
		price    float64
		powerW   float64
	}

	var rows []prepared
	var jphList []float64
	var currency string

	for _, r := range lastReport {
		if now-r.ReportedAt > maxReportAge {
			continue
		}
		if r.HashrateHps <= 0 || r.PowerWatts <= 0 || r.EnergyPricePerKWh <= 0 {
			continue
		}
		if r.PowerWatts > 100000 || r.HashrateHps > 1e18 || r.EnergyPricePerKWh > 1000 {
			continue
		}
		jPerHash := r.PowerWatts / r.HashrateHps
		if jPerHash <= 0 || jPerHash > 1e6 {
			continue
		}
		rows = append(rows, prepared{jPerHash: jPerHash, price: r.EnergyPricePerKWh, powerW: r.PowerWatts})
		jphList = append(jphList, jPerHash)
		if currency == "" && r.FiatCurrency != "" {
			currency = r.FiatCurrency
		}
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("no_valid_reports")
	}
	if currency == "" {
		currency = "USD"
	}

	avgJPerHash := trimmedMean(jphList, 0.1)

	var sumPW, sumPricePW float64
	for _, row := range rows {
		sumPW += row.powerW
		sumPricePW += row.price * row.powerW
	}
	if sumPW <= 0 {
		return nil, fmt.Errorf("bad_power_sum")
	}
	avgPrice := sumPricePW / sumPW

	// Compute min cost per hash (for fee floor)
	minCostPerHash := (avgJPerHash / 3_600_000.0) * avgPrice

	em := &EnergyModel{
		AvgJoulesPerHash: avgJPerHash,
		AvgPricePerKWh:   avgPrice,
		FiatCurrency:     currency,
		UpdatedAt:        now,
		SampleCount:      len(rows),
		MinCostPerHash:   minCostPerHash,
	}

	// Atomic write
	tmp := modelPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		return nil, err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(em); err != nil {
		f.Close()
		return nil, err
	}
	f.Close()
	if err := os.Rename(tmp, modelPath); err != nil {
		return nil, err
	}

	log.Printf("[ORACLE] model updated: J/hash=%.6f price=%.4f %s/kWh cost/hash=%.2e (samples=%d)\n",
		avgJPerHash, avgPrice, currency, minCostPerHash, len(rows))

	return em, nil
}

func evictOldestMiner() {
	if len(lastReport) < maxMiners {
		return
	}
	oldestID := ""
	var oldestTS int64
	for id, r := range lastReport {
		if oldestID == "" || r.ReportedAt < oldestTS {
			oldestID = id
			oldestTS = r.ReportedAt
		}
	}
	if oldestID != "" {
		delete(lastReport, oldestID)
		delete(lastReportTS, oldestID)
	}
}

func main() {
	secret := os.Getenv("BFI_ORACLE_SECRET")
	bind := os.Getenv("BFI_ORACLE_BIND")
	if bind == "" {
		bind = "0.0.0.0:8090"
	}
	modelPath = os.Getenv("BFI_MODEL_PATH")
	if modelPath == "" {
		modelPath = "energy.model.json"
	}

	log.Printf("[ORACLE] Boson Infinity Energy Oracle v2.1.0")
	log.Printf("[ORACLE] Starting on %s, model: %s", bind, modelPath)
	if secret == "" {
		log.Printf("[WARN] BFI_ORACLE_SECRET not set — reports will NOT be authenticated!")
	}

	// Periodic recompute
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			reportsMu.Lock()
			recomputeModelLocked()
			reportsMu.Unlock()
		}
	}()

	reportHandler := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "use POST", http.StatusMethodNotAllowed)
			return
		}
		var rep MinerReport
		if err := json.NewDecoder(r.Body).Decode(&rep); err != nil {
			http.Error(w, "bad_json", 400)
			return
		}
		if rep.MinerID == "" {
			http.Error(w, "missing_miner_id", 400)
			return
		}
		if rep.FiatCurrency == "" {
			rep.FiatCurrency = "EUR"
		}
		if rep.ReportedAt == 0 {
			rep.ReportedAt = time.Now().Unix()
		}
		if rep.HashrateHps <= 0 || rep.PowerWatts <= 0 || rep.EnergyPricePerKWh <= 0 {
			http.Error(w, "invalid_values", 400)
			return
		}
		if rep.HashrateHps > 1e18 || rep.PowerWatts > 100000 || rep.EnergyPricePerKWh > 1000 {
			http.Error(w, "out_of_range", 400)
			return
		}
		if !verifyReportHMAC(rep, secret) {
			http.Error(w, "unauthorized", 401)
			return
		}

		reportsMu.Lock()
		now := time.Now().Unix()
		if last, ok := lastReportTS[rep.MinerID]; ok && now-last < reportCooldownS {
			reportsMu.Unlock()
			http.Error(w, "rate_limited", 429)
			return
		}
		evictOldestMiner()
		lastReport[rep.MinerID] = rep
		lastReportTS[rep.MinerID] = now
		_, err := recomputeModelLocked()
		reportsMu.Unlock()
		if err != nil {
			http.Error(w, "recompute_failed", 500)
			return
		}
		writeJSON(w, 200, map[string]any{"ok": true})
	}

	http.HandleFunc("/report", reportHandler)
	http.HandleFunc("/v1/miner/report", reportHandler)

	http.HandleFunc("/model", func(w http.ResponseWriter, r *http.Request) {
		f, err := os.Open(modelPath)
		if err != nil {
			http.Error(w, "no_model", 404)
			return
		}
		defer f.Close()
		var em EnergyModel
		if err := json.NewDecoder(f).Decode(&em); err != nil {
			http.Error(w, "model_corrupt", 500)
			return
		}
		writeJSON(w, 200, em)
	})

	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		reportsMu.Lock()
		count := len(lastReport)
		reportsMu.Unlock()
		writeJSON(w, 200, map[string]any{"status": "ok", "miners": count})
	})

	server := &http.Server{
		Addr:              bind,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Fatal(server.ListenAndServe())
}
