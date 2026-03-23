package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func CurrentParamsHash() string {
	blob := fmt.Sprintf("%s|%d|%f|%d|%f|%d",
		core.NetworkName,
		core.Decimals,
		core.RewardInitialCoins,
		core.HalvingInterval,
		core.MaxSupplyCoins,
		core.RetargetWindow)
	sum := sha256.Sum256([]byte(blob))
	return hex.EncodeToString(sum[:])
}

func SaveChain(c *core.Chain, chainPath string) {
	tmp := chainPath + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		slog.Error("save chain failed", "error", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		slog.Error("encode chain failed", "error", err)
		return
	}
	if err := os.Rename(tmp, chainPath); err != nil {
		slog.Error("rename chain failed", "error", err)
		return
	}
	slog.Info("chain saved", "blocks", len(c.Blocks), "accounts", len(c.State))
}

func LoadChain(chainPath string, cfg *core.Config) *core.Chain {
	f, err := os.Open(chainPath)
	if err != nil {
		slog.Info("no existing chain (will create new)")
		return nil
	}
	defer f.Close()

	var c core.Chain
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		slog.Error("load chain failed", "error", err)
		return nil
	}

	if c.State == nil {
		c.State = map[string]core.Account{}
	}
	// Migration: add treasury account if missing
	if _, ok := c.State[cfg.TreasuryAddr]; !ok {
		c.State[cfg.TreasuryAddr] = core.Account{Balance: 0, Nonce: 0}
		slog.Info("migration: treasury account added", "addr", cfg.TreasuryAddr)
	}

	if c.Staking.Validators == nil {
		c.Staking.Validators = map[string]core.Staker{}
	}
	if c.Bridge.Locks == nil {
		c.Bridge.Locks = map[string]core.BridgeLock{}
	}
	if c.Bridge.Unlocks == nil {
		c.Bridge.Unlocks = map[string]core.BridgeUnlock{}
	}
	if c.Bridge.Consumed == nil {
		c.Bridge.Consumed = map[string]bool{}
	}
	if c.Blocks == nil {
		c.Blocks = []core.Block{}
	}
	if c.Contracts == nil {
		c.Contracts = map[string]core.Contract{}
	}

	if c.GenesisMessage == "" {
		c.GenesisMessage = core.GenesisMessage
	}
	if c.GenesisMessageHex == "" && c.GenesisMessage != "" {
		c.GenesisMessageHex = hex.EncodeToString([]byte(c.GenesisMessage))
	}

	slog.Info("chain loaded", "blocks", len(c.Blocks), "accounts", len(c.State))
	return &c
}

func LoadEnergyModel(path string) (*core.EnergyModel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var em core.EnergyModel
	if err := json.NewDecoder(f).Decode(&em); err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	// Model freshness: max 24h
	if em.UpdatedAt == 0 || now-em.UpdatedAt > 86400 {
		return nil, fmt.Errorf("energy_model_stale")
	}

	// Sanity checks for production ranges
	if em.AvgJoulesPerHash <= 0 || em.AvgJoulesPerHash > 10 {
		return nil, fmt.Errorf("invalid_j_per_hash")
	}
	if em.AvgPricePerKWh <= 0.001 || em.AvgPricePerKWh > 5 {
		return nil, fmt.Errorf("invalid_price_per_kwh")
	}

	if em.FiatCurrency == "" {
		em.FiatCurrency = "EUR"
	}

	return &em, nil
}

func CreateGenesis() core.Block {
	return core.Block{
		Header: core.BlockHeader{
			Version:    1,
			PrevHash:   "0x0",
			Merkle:     "",
			Timestamp:  time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC), // deterministic
			Nonce:      0,
			Height:     0,
			Difficulty: core.DifficultyBitsInit,
			Miner:      "GENESIS",
		},
		Mix:  "0x0",
		Hash: "GENESIS",
	}
}

// GenesisProofHash returns a deterministic SHA-256 hash that proves authorship
// of the genesis block. This is NOT the block hash (which stays "GENESIS" for compat),
// but a separate cryptographic proof embedded in the chain metadata.
func GenesisProofHash() string {
	data := fmt.Sprintf("GENESIS_PROOF:%s:%s:%d:%d",
		core.GenesisMessage,
		time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		core.DifficultyBitsInit,
		core.HalvingInterval)
	sum := sha256.Sum256([]byte(data))
	return hex.EncodeToString(sum[:])
}

func BuildGenesisState(cfg *core.Config) map[string]core.Account {
	state := map[string]core.Account{}
	state[cfg.BridgeVaultAddr] = core.Account{Balance: 0, Nonce: 0}
	state[cfg.BridgeOperatorAddr] = core.Account{Balance: 0, Nonce: 0}
	state[cfg.TreasuryAddr] = core.Account{Balance: 0, Nonce: 0}
	return state
}
