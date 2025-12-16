//go:build aggregator
// +build aggregator

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// Ten sam format co w node.go
type MinerReport struct {
	MinerID           string  `json:"miner_id"`             // unikalny id minera (label albo address)
	HashrateHps       float64 `json:"hashrate_hps"`         // H/s
	PowerWatts        float64 `json:"power_watts"`          // W
	EnergyPricePerKWh float64 `json:"energy_price_per_kwh"` // FIAT / kWh
	FiatCurrency      string  `json:"fiat_currency"`        // np. "EUR"
	Country           string  `json:"country"`              // np. "DE"
	ReportedAt        int64   `json:"reported_at"`          // unix time
}

// Ten sam struct co w node.go
type EnergyModel struct {
	AvgJoulesPerHash float64 `json:"avg_j_per_hash"`
	AvgPricePerKWh   float64 `json:"avg_price_per_kwh"`
	FiatCurrency     string  `json:"fiat_currency"`
	UpdatedAt        int64   `json:"updated_at"`
}

var (
	modelPath  = "energy.model.json"
	reportsMu  sync.Mutex
	lastReport = map[string]MinerReport{} // miner_id -> ostatni raport
)

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// trimmed-mean – wyrzuca skrajne 10% z góry i z dołu
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

// Przelicza model na podstawie lastReport i zapisuje energy.model.json
func recomputeModelLocked() (*EnergyModel, error) {
	const maxAge = 15 * 60 // raporty ważne 15 minut

	now := time.Now().Unix()

	type prepared struct {
		jPerHash float64
		price    float64
		powerW   float64
	}

	var rows []prepared
	var prices []float64
	var jphList []float64
	var currency string

	for _, r := range lastReport {
		// stare raporty – wypad
		if now-r.ReportedAt > maxAge {
			continue
		}
		// sanity
		if r.HashrateHps <= 0 || r.PowerWatts <= 0 || r.EnergyPricePerKWh <= 0 {
			continue
		}
		// odrzucamy absurdalne śmieci
		if r.PowerWatts > 100000 || r.HashrateHps > 1e18 || r.EnergyPricePerKWh > 1000 {
			continue
		}

		jPerHash := r.PowerWatts / r.HashrateHps // J/hash
		if jPerHash <= 0 || jPerHash > 1e6 {
			continue
		}

		rows = append(rows, prepared{
			jPerHash: jPerHash,
			price:    r.EnergyPricePerKWh,
			powerW:   r.PowerWatts,
		})
		jphList = append(jphList, jPerHash)
		prices = append(prices, r.EnergyPricePerKWh)

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

	// średnia J/hash z obcięciem outlierów
	avgJPerHash := trimmedMean(jphList, 0.1)

	// cena za kWh ważona mocą (duże farmy mają większy wpływ)
	var sumPW float64
	var sumPricePW float64
	for _, row := range rows {
		sumPW += row.powerW
		sumPricePW += row.price * row.powerW
	}
	if sumPW <= 0 {
		return nil, fmt.Errorf("bad_power_sum")
	}
	avgPrice := sumPricePW / sumPW

	em := &EnergyModel{
		AvgJoulesPerHash: avgJPerHash,
		AvgPricePerKWh:   avgPrice,
		FiatCurrency:     currency,
		UpdatedAt:        now,
	}

	// zapis do energy.model.json (czytane przez node.go)
	f, err := os.Create(modelPath)
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

	log.Printf("[ORACLE] model updated: J/hash=%.6f price=%.4f %s/kWh (samples=%d)\n",
		avgJPerHash, avgPrice, currency, len(rows))

	return em, nil
}

func main() {
	secret := os.Getenv("BFI_ORACLE_SECRET")
	bind := os.Getenv("BFI_ORACLE_BIND")
	if bind == "" {
		bind = "0.0.0.0:8090"
	}

	log.Printf("[ORACLE] starting on %s", bind)
	if secret == "" {
		log.Printf("[WARN] BFI_ORACLE_SECRET not set (na razie i tak tylko logujemy).")
	}

	// 🔁 PERIODYCZNY RECOMPUTE CO 5 MINUT
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			reportsMu.Lock()
			em, err := recomputeModelLocked()
			reportsMu.Unlock()

			if err != nil {
				// typowo "no_valid_reports" jeśli nic świeżego nie ma
				log.Printf("[ORACLE] periodic recompute skipped/failed: %v", err)
				continue
			}

			log.Printf("[ORACLE] periodic model updated (timer): J/hash=%.6f price=%.4f %s/kWh\n",
				em.AvgJoulesPerHash, em.AvgPricePerKWh, em.FiatCurrency)
		}
	}()

	// Wspólny handler dla /report i /v1/miner/report
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

		log.Printf("[REPORT] miner=%s H/s=%.3g W=%.3g price=%.3g %s/kWh (%s)\n",
			rep.MinerID,
			rep.HashrateHps,
			rep.PowerWatts,
			rep.EnergyPricePerKWh,
			rep.FiatCurrency,
			rep.Country,
		)

		reportsMu.Lock()
		lastReport[rep.MinerID] = rep
		_, err := recomputeModelLocked()
		reportsMu.Unlock()

		if err != nil {
			http.Error(w, "recompute_failed", 500)
			return
		}

		writeJSON(w, 200, map[string]any{"ok": true})
	}

	// POST /report – raport od minera (stary endpoint)
	http.HandleFunc("/report", reportHandler)
	// POST /v1/miner/report – to, co woła miner_gpu
	http.HandleFunc("/v1/miner/report", reportHandler)

	// GET /model – debug, pokazuje bieżący energy.model.json
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

	log.Fatal(http.ListenAndServe(bind, nil))
}

