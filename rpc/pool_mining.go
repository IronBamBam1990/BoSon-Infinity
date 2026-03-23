package rpc

import (
	"log/slog"
	"sync"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
)

/* -------------------------------------------------------------------------- */
/*                        MINING POOL / SHARE TRACKING                         */
/* -------------------------------------------------------------------------- */
// Share-based mining: miners submit at a lower "share difficulty" and the pool
// tracks their contributions. When a real block solution is found, the miner
// who found it gets the block reward, but shares are tracked for future
// pool reward distribution.

const (
	ShareDifficultyOffset = 6  // share diff = block diff - 6 (e.g. diff 16 → share 10)
	MinShareDifficulty    = 4  // minimum share difficulty
	ShareWindowSeconds    = 600 // 10 minute share window
)

// Share represents a valid share submitted by a miner.
type Share struct {
	MinerAddr string    `json:"miner_addr"`
	JobID     string    `json:"job_id"`
	Nonce     uint64    `json:"nonce"`
	ShareDiff int       `json:"share_diff"`
	BlockDiff int       `json:"block_diff"`
	IsBlock   bool      `json:"is_block"` // true if this share also solves the block
	Time      time.Time `json:"time"`
}

// ShareTracker tracks shares from miners for pool-style reward distribution.
type ShareTracker struct {
	mu     sync.Mutex
	shares []Share
	// Per-miner share count in current window
	counts map[string]int
}

func NewShareTracker() *ShareTracker {
	st := &ShareTracker{
		shares: make([]Share, 0),
		counts: make(map[string]int),
	}
	go st.cleanupLoop()
	return st
}

// ShareDifficulty returns the share difficulty for the current block difficulty.
func ShareDifficulty(blockDiff int) int {
	sd := blockDiff - ShareDifficultyOffset
	if sd < MinShareDifficulty {
		sd = MinShareDifficulty
	}
	return sd
}

// SubmitShare validates and records a share.
// Returns (isValidShare, isBlockSolution).
func (st *ShareTracker) SubmitShare(ns *NodeState, jobID, headerHex, mixHex, minerAddr string, nonce uint64) (bool, bool) {
	if !core.IsValidAddr(minerAddr) {
		return false, false
	}

	j, ok := ns.Jobs.Load(jobID)
	if !ok {
		return false, false
	}
	if time.Now().Unix() > j.E {
		return false, false
	}
	if j.H != headerHex {
		return false, false
	}

	// Verify the hash
	wantMix := crypto.MixHash(headerHex, nonce)
	if mixHex != wantMix {
		return false, false
	}

	shareDiff := ShareDifficulty(j.D)

	// Check if it meets share difficulty
	if !crypto.CheckMask(mixHex, shareDiff) {
		return false, false
	}

	// It's a valid share!
	isBlock := crypto.CheckMask(mixHex, j.D)

	share := Share{
		MinerAddr: minerAddr,
		JobID:     jobID,
		Nonce:     nonce,
		ShareDiff: shareDiff,
		BlockDiff: j.D,
		IsBlock:   isBlock,
		Time:      time.Now(),
	}

	st.mu.Lock()
	st.shares = append(st.shares, share)
	st.counts[minerAddr]++
	st.mu.Unlock()

	slog.Debug("share accepted", "miner", core.Short(minerAddr),
		"share_diff", shareDiff, "block_diff", j.D, "is_block", isBlock)

	return true, isBlock
}

// GetShareCounts returns the share count per miner in the current window.
func (st *ShareTracker) GetShareCounts() map[string]int {
	st.mu.Lock()
	defer st.mu.Unlock()

	result := make(map[string]int, len(st.counts))
	for k, v := range st.counts {
		result[k] = v
	}
	return result
}

// GetRecentShares returns shares from the last N seconds.
func (st *ShareTracker) GetRecentShares(windowSec int) []Share {
	st.mu.Lock()
	defer st.mu.Unlock()

	cutoff := time.Now().Add(-time.Duration(windowSec) * time.Second)
	var result []Share
	for _, s := range st.shares {
		if s.Time.After(cutoff) {
			result = append(result, s)
		}
	}
	return result
}

// TotalShares returns total share count in current window.
func (st *ShareTracker) TotalShares() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return len(st.shares)
}

func (st *ShareTracker) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		st.mu.Lock()
		cutoff := time.Now().Add(-time.Duration(ShareWindowSeconds) * time.Second)
		var kept []Share
		newCounts := make(map[string]int)
		for _, s := range st.shares {
			if s.Time.After(cutoff) {
				kept = append(kept, s)
				newCounts[s.MinerAddr]++
			}
		}
		st.shares = kept
		st.counts = newCounts
		st.mu.Unlock()
	}
}
