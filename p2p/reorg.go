package p2p

import (
	"fmt"
	"log/slog"

	"github.com/IronBamBam1990/BoSon-Infinity/consensus"
	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/rpc"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

const (
	MaxReorgDepth = 100 // max blocks to rewind during reorg
)

// FindForkPoint finds the last common block between our chain and a peer's chain.
// Returns the fork height (last common block), or -1 if no common ancestor found.
func FindForkPoint(ns *rpc.NodeState, peerBlocks []core.Block) int {
	if len(peerBlocks) == 0 {
		return -1
	}

	// Build hash→height map for peer blocks
	peerByHeight := map[int]string{}
	for _, b := range peerBlocks {
		peerByHeight[b.Header.Height] = b.Hash
	}

	// Walk backwards through our chain to find common block
	for i := len(ns.Chain.Blocks) - 1; i >= 0; i-- {
		ourBlock := ns.Chain.Blocks[i]
		if peerHash, ok := peerByHeight[ourBlock.Header.Height]; ok {
			if peerHash == ourBlock.Hash {
				return ourBlock.Header.Height
			}
		}
		// If we've checked the height range of peer blocks and found no match, stop
		if ourBlock.Header.Height < peerBlocks[0].Header.Height {
			break
		}
	}

	return -1
}

// Reorg performs a chain reorganization: rewinds to forkPoint, then applies newBlocks.
// Returns error if reorg fails (chain state is restored).
// MUST be called with ns.Mu held.
func Reorg(ns *rpc.NodeState, forkPoint int, newBlocks []core.Block) error {
	ourHeight := len(ns.Chain.Blocks) - 1
	reorgDepth := ourHeight - forkPoint

	if reorgDepth <= 0 {
		return fmt.Errorf("nothing to reorg")
	}
	if reorgDepth > MaxReorgDepth {
		return fmt.Errorf("reorg too deep: %d blocks (max %d)", reorgDepth, MaxReorgDepth)
	}

	slog.Warn("chain reorg starting",
		"fork_point", forkPoint,
		"our_height", ourHeight,
		"reorg_depth", reorgDepth,
		"new_blocks", len(newBlocks))

	// Save rollback state
	savedBlocks := make([]core.Block, len(ns.Chain.Blocks))
	copy(savedBlocks, ns.Chain.Blocks)
	savedState := core.CopyState(ns.Chain.State)
	savedStaking := core.CopyStaking(ns.Chain.Staking)
	savedMinted := ns.Chain.TotalMinted

	// Rewind: rebuild state from genesis to forkPoint
	ns.Chain.Blocks = ns.Chain.Blocks[:forkPoint+1]
	ns.Chain.State = rebuildState(ns.Chain.Blocks, ns.Cfg)
	ns.Chain.TotalMinted = recalcMinted(ns.Chain.Blocks)
	// Staking state also needs rebuild but for simplicity we reset
	ns.Chain.Staking = core.StakingState{
		Validators: map[string]core.Staker{},
	}

	// Rebuild staking from blocks
	for i := 1; i <= forkPoint && i < len(ns.Chain.Blocks); i++ {
		for _, tx := range ns.Chain.Blocks[i].Txs {
			if tx.Type == "stake" || tx.Type == "unstake" {
				consensus.ApplyTx(ns.Chain.State, tx, ns.Chain, ns.Chain.Blocks[i].Header.Height, ns.Cfg)
			}
		}
	}

	// Apply new blocks
	for _, b := range newBlocks {
		if !consensus.ValidateBlock(ns.Chain, b, ns.Cfg) {
			// Reorg failed — restore original state
			slog.Error("reorg failed: invalid block in new chain", "height", b.Header.Height)
			ns.Chain.Blocks = savedBlocks
			ns.Chain.State = savedState
			ns.Chain.Staking = savedStaking
			ns.Chain.TotalMinted = savedMinted
			return fmt.Errorf("invalid block at height %d", b.Header.Height)
		}
		consensus.ApplyBlock(ns.Chain, b, ns.Cfg)
		ns.Chain.Blocks = append(ns.Chain.Blocks, b)
	}

	// Persist to database
	if ns.DB != nil {
		// Save all new blocks and final state
		for i := range newBlocks {
			ns.DB.SaveBlockAndState(&newBlocks[i], ns.Chain.State, ns.Chain.TotalMinted)
		}
		ns.DB.SaveStaking(ns.Chain.Staking)
	}

	// Return orphaned TXs to mempool
	orphanedTxs := collectOrphanedTxs(savedBlocks[forkPoint+1:], newBlocks)
	for _, tx := range orphanedTxs {
		if ns.Pool != nil {
			ns.Pool.Add(tx)
		}
	}

	slog.Info("chain reorg complete",
		"new_height", ns.Chain.Blocks[len(ns.Chain.Blocks)-1].Header.Height,
		"orphaned_txs_returned", len(orphanedTxs))

	return nil
}

// rebuildState replays all blocks from genesis to reconstruct account state.
func rebuildState(blocks []core.Block, cfg *core.Config) map[string]core.Account {
	state := storage.BuildGenesisState(cfg)

	// Build a temporary chain object so ApplyTx can access staking/bridge state
	tmpChain := &core.Chain{
		Blocks:    blocks,
		State:     state,
		Staking:   core.StakingState{Validators: map[string]core.Staker{}},
		Bridge:    core.BridgeState{Locks: map[string]core.BridgeLock{}, Unlocks: map[string]core.BridgeUnlock{}, Consumed: map[string]bool{}},
		Contracts: map[string]core.Contract{},
	}

	for i := 1; i < len(blocks); i++ {
		b := blocks[i]
		for _, tx := range b.Txs {
			consensus.ApplyTx(state, tx, tmpChain, b.Header.Height, cfg)
		}
		var totalFees uint64
		for _, tx := range b.Txs {
			totalFees += tx.Fee
		}
		br := consensus.BaseRewardAt(b.Header.Height)
		totalReward := br + totalFees
		minerShare, treasuryShare := consensus.SplitReward80_20(totalReward)

		ma := state[b.Header.Miner]
		ma.Balance += minerShare
		state[b.Header.Miner] = ma

		ta := state[cfg.TreasuryAddr]
		ta.Balance += treasuryShare
		state[cfg.TreasuryAddr] = ta
	}

	return state
}

// recalcMinted sums up all block subsidies.
func recalcMinted(blocks []core.Block) uint64 {
	var total uint64
	for i := 1; i < len(blocks); i++ {
		br := consensus.BaseRewardAt(blocks[i].Header.Height)
		if total+br > core.MAX_SUPPLY_UNITS {
			br = core.MAX_SUPPLY_UNITS - total
		}
		total += br
	}
	return total
}

// collectOrphanedTxs finds TXs that were in old blocks but NOT in new blocks.
func collectOrphanedTxs(oldBlocks, newBlocks []core.Block) []core.Tx {
	newTxHashes := map[string]bool{}
	for _, b := range newBlocks {
		for _, tx := range b.Txs {
			newTxHashes[tx.Hash] = true
		}
	}

	var orphaned []core.Tx
	for _, b := range oldBlocks {
		for _, tx := range b.Txs {
			if !newTxHashes[tx.Hash] {
				orphaned = append(orphaned, tx)
			}
		}
	}
	return orphaned
}
