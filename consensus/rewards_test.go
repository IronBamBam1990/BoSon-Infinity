package consensus

import (
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func init() {
	core.InitConsensus()
}

func TestBaseRewardAt(t *testing.T) {
	if BaseRewardAt(0) != 0 {
		t.Error("height 0 should have 0 reward")
	}
	r := BaseRewardAt(1)
	if r != core.REWARD0_UNITS {
		t.Errorf("height 1: expected %d, got %d", core.REWARD0_UNITS, r)
	}
	r2 := BaseRewardAt(core.HalvingInterval + 1)
	if r2 != core.REWARD0_UNITS/2 {
		t.Errorf("after halving: expected %d, got %d", core.REWARD0_UNITS/2, r2)
	}
	r3 := BaseRewardAt(core.HalvingInterval * 64)
	if r3 != 0 {
		t.Errorf("after 64 halvings: expected 0, got %d", r3)
	}
}

func TestSplitReward80_20(t *testing.T) {
	miner, treasury := SplitReward80_20(100)
	if miner != 80 || treasury != 20 {
		t.Errorf("expected 80/20, got %d/%d", miner, treasury)
	}
	m2, t2 := SplitReward80_20(101)
	if m2+t2 != 101 {
		t.Errorf("split does not sum to total: %d + %d != 101", m2, t2)
	}
	m0, t0 := SplitReward80_20(0)
	if m0 != 0 || t0 != 0 {
		t.Errorf("zero split failed: %d/%d", m0, t0)
	}
}

func TestCalcFee(t *testing.T) {
	if CalcFee(1000) != 1 {
		t.Errorf("expected 1, got %d", CalcFee(1000))
	}
	if CalcFee(1) != 1 {
		t.Errorf("minimum fee should be 1, got %d", CalcFee(1))
	}
	f := CalcFee(100_000_000)
	expected := uint64(100_000)
	if f != expected {
		t.Errorf("expected %d, got %d", expected, f)
	}
}
