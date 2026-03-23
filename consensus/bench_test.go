package consensus

import (
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func BenchmarkBaseRewardAt(b *testing.B) {
	core.InitConsensus()
	for i := 0; i < b.N; i++ {
		BaseRewardAt(i % 1_000_000)
	}
}

func BenchmarkCalcFee(b *testing.B) {
	core.InitConsensus()
	for i := 0; i < b.N; i++ {
		CalcFee(uint64(i)*100 + 1)
	}
}

func BenchmarkSplitReward(b *testing.B) {
	for i := 0; i < b.N; i++ {
		SplitReward80_20(uint64(i) * 1000)
	}
}
