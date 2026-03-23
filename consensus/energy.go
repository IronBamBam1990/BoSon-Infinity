package consensus

import (
	"log/slog"
	"math"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

/* -------------------------------------------------------------------------- */
/*                    ENERGY-BASED ECONOMICS                                   */
/* -------------------------------------------------------------------------- */
// The energy model links coin value to real-world mining cost.
// When an energy model is available, we can compute:
//   1. MinFeeFloor — minimum fee that ensures mining is not unprofitable
//   2. CostPerCoin — energy cost of mining one BOS
//   3. EnergyCostPerBlock — total energy cost per block

// EnergyAwareFee returns a minimum fee floor based on energy cost.
// If no model is available or the computed floor is below the fixed fee, returns 0 (use fixed fee).
func EnergyAwareFee(amount uint64, energyModelPath string) uint64 {
	em, err := storage.LoadEnergyModel(energyModelPath)
	if err != nil {
		return 0 // no model = use fixed fee
	}

	// Cost per hash in fiat
	costPerHash := (em.AvgJoulesPerHash / 3_600_000.0) * em.AvgPricePerKWh
	if costPerHash <= 0 {
		return 0
	}

	// At current difficulty, roughly 2^difficulty hashes per block
	// Minimum fee should cover at least the miner's energy cost for including this TX
	// Simplified: fee_floor = (cost_per_hash * estimated_hashes_per_tx) / coin_value
	// For now we use a simpler model: fee = max(fixed_fee, energy_adjusted_fee)

	// Energy-adjusted minimum: 0.01% of amount scaled by energy cost ratio
	// This ensures fees track real-world costs
	energyFee := uint64(float64(amount) * costPerHash * 1000)
	if energyFee < 1 {
		energyFee = 1
	}

	fixedFee := CalcFee(amount)
	if energyFee > fixedFee {
		return energyFee
	}
	return 0 // fixed fee is already sufficient
}

// ComputeBlockEconomics calculates energy-based economics for a block.
type BlockEconomics struct {
	CostPerHash    float64 `json:"cost_per_hash"`
	HashesPerBlock float64 `json:"hashes_per_block"`
	CostPerBlock   float64 `json:"cost_per_block"`
	RewardPerBlock float64 `json:"reward_per_block"`
	ProfitMargin   float64 `json:"profit_margin"` // (reward - cost) / cost
	CostPerCoin    float64 `json:"cost_per_coin"`
}

func ComputeBlockEconomics(difficulty int, height int, energyModelPath string) *BlockEconomics {
	em, err := storage.LoadEnergyModel(energyModelPath)
	if err != nil {
		return nil
	}

	costPerHash := (em.AvgJoulesPerHash / 3_600_000.0) * em.AvgPricePerKWh
	hashesPerBlock := math.Exp2(float64(difficulty))
	costPerBlock := hashesPerBlock * costPerHash

	rewardUnits := float64(BaseRewardAt(height))
	rewardCoins := rewardUnits / float64(core.UNIT)

	var profitMargin float64
	if costPerBlock > 0 {
		profitMargin = (rewardCoins - costPerBlock) / costPerBlock
	}

	var costPerCoin float64
	if rewardCoins > 0 {
		costPerCoin = costPerBlock / rewardCoins
	}

	slog.Debug("block economics",
		"cost_per_block", costPerBlock,
		"reward", rewardCoins,
		"margin", profitMargin,
		"cost_per_coin", costPerCoin)

	return &BlockEconomics{
		CostPerHash:    costPerHash,
		HashesPerBlock: hashesPerBlock,
		CostPerBlock:   costPerBlock,
		RewardPerBlock: rewardCoins,
		ProfitMargin:   profitMargin,
		CostPerCoin:    costPerCoin,
	}
}
