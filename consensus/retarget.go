package consensus

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func Retarget(c *core.Chain) int {
	n := len(c.Blocks)
	if n < 2 {
		return c.Blocks[0].Header.Difficulty
	}

	N := core.RetargetWindow
	if N < 10 {
		N = 10
	}
	if n-1 < N {
		N = n - 1
	}
	if N <= 1 {
		return c.Blocks[n-1].Header.Difficulty
	}

	T := core.TargetBlockSeconds
	if T <= 0 {
		T = 400
	}

	var sumWeighted float64
	var sumWeights float64

	prev := c.Blocks[n-N-1].Header.Timestamp

	for i := n - N; i < n; i++ {
		ts := c.Blocks[i].Header.Timestamp
		solve := ts.Sub(prev).Seconds()
		if solve < 1 {
			solve = 1
		}
		weight := float64(i-(n-N)) + 1
		sumWeights += weight
		sumWeighted += solve * weight
		prev = ts
	}

	lwma := sumWeighted / sumWeights
	ratio := T / lwma

	if ratio > 4 {
		ratio = 4
	}
	if ratio < 0.25 {
		ratio = 0.25
	}

	delta := int(math.Round(math.Log2(ratio)))
	if delta > core.MaxDifficultyStep {
		delta = core.MaxDifficultyStep
	}
	if delta < -core.MaxDifficultyStep {
		delta = -core.MaxDifficultyStep
	}

	oldBits := c.Blocks[n-1].Header.Difficulty
	newBits := oldBits + delta
	if newBits < 1 {
		newBits = 1
	}
	if newBits > 62 {
		newBits = 62
	}

	slog.Debug("difficulty retarget",
		"lwma", fmt.Sprintf("%.2fs", lwma),
		"ratio", fmt.Sprintf("%.3f", ratio),
		"old", oldBits, "delta", delta, "new", newBits)

	return newBits
}
