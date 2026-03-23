package consensus

import "github.com/IronBamBam1990/BoSon-Infinity/core"

func BaseRewardAt(height int) uint64 {
	if height <= 0 {
		return 0
	}
	halvings := height / core.HalvingInterval
	if halvings > 63 {
		return 0
	}
	return core.REWARD0_UNITS >> uint(halvings)
}

func SplitReward80_20(total uint64) (minerShare uint64, treasuryShare uint64) {
	treasuryShare = total / 5          // 20%
	minerShare = total - treasuryShare // 80%
	return
}

// CalcFee — fixed fee 0.1% of amount (in atoms)
func CalcFee(amount uint64) uint64 {
	fee := (amount * uint64(core.FeePermille)) / 1000
	if fee == 0 {
		fee = 1
	}
	return fee
}
