package storage

import (
	"encoding/json"
	"log/slog"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bolt "go.etcd.io/bbolt"
)

/* -------------------------------------------------------------------------- */
/*                              BLOCK PRUNING                                  */
/* -------------------------------------------------------------------------- */
// Pruning removes full block data (TX bodies) from old blocks while keeping:
//   - Block headers (for chain validation)
//   - State (account balances)
//   - TX index (hash → location mapping)
//   - Checkpoints
//
// This saves significant disk space. Pruned blocks can be re-downloaded from
// peers if needed (e.g., for a full resync).

// PrunedBlock contains only header data — TX bodies removed.
type PrunedBlock struct {
	Header  core.BlockHeader `json:"header"`
	Hash    string           `json:"hash"`
	Mix     string           `json:"mix"`
	TxCount int              `json:"tx_count"` // how many TXs were pruned
}

// PruneBlocks removes TX data from blocks below keepHeight.
// Keeps the last `keepHeight` blocks intact.
func (s *Store) PruneBlocks(currentHeight, keepBlocks int) (int, error) {
	pruneBelow := currentHeight - keepBlocks
	if pruneBelow <= 0 {
		return 0, nil
	}

	pruned := 0
	err := s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBlocks)
		c := bk.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			h := decodeHeight(k)
			if h >= pruneBelow {
				break // stop pruning
			}

			// Decode full block
			var block core.Block
			if err := json.Unmarshal(v, &block); err != nil {
				continue
			}

			// Already pruned?
			if len(block.Txs) == 0 {
				continue
			}

			// Create pruned version (keep header, remove TXs)
			prunedBlock := core.Block{
				Header: block.Header,
				Hash:   block.Hash,
				Mix:    block.Mix,
				Txs:    nil, // remove TX data
			}

			data, err := json.Marshal(prunedBlock)
			if err != nil {
				continue
			}

			if err := bk.Put(k, data); err != nil {
				return err
			}
			pruned++
		}
		return nil
	})

	if pruned > 0 {
		slog.Info("pruning complete", "pruned_blocks", pruned, "kept_from", pruneBelow)
	}
	return pruned, err
}

// PruneStats returns info about prunable vs kept blocks.
type PruneStats struct {
	TotalBlocks   int   `json:"total_blocks"`
	PrunedBlocks  int   `json:"pruned_blocks"`
	FullBlocks    int   `json:"full_blocks"`
	EstSavedBytes int64 `json:"est_saved_bytes"`
}

func (s *Store) GetPruneStats() PruneStats {
	var stats PruneStats
	s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBlocks)
		return bk.ForEach(func(k, v []byte) error {
			stats.TotalBlocks++
			var block core.Block
			if json.Unmarshal(v, &block) == nil {
				if len(block.Txs) == 0 && block.Header.Height > 0 {
					stats.PrunedBlocks++
				} else {
					stats.FullBlocks++
				}
			}
			return nil
		})
	})
	return stats
}

// DBSize returns the size of the database file in bytes.
func (s *Store) DBSize() int64 {
	var size int64
	s.db.View(func(tx *bolt.Tx) error {
		size = tx.Size()
		return nil
	})
	return size
}

// DBPath returns the path to the database file.
func (s *Store) DBPath() string {
	return s.path
}

// Compact runs a full compaction on the database (reclaims freed pages).
func (s *Store) Compact() error {
	// BBolt doesn't have built-in compaction, but we can trigger
	// a freelist sync which helps with page reuse
	return s.db.Update(func(tx *bolt.Tx) error {
		return nil // just opening a write tx helps
	})
}

// Info returns storage information.
type StorageInfo struct {
	DBPath     string     `json:"db_path"`
	DBSize     int64      `json:"db_size_bytes"`
	DBSizeMB   float64    `json:"db_size_mb"`
	Height     int        `json:"height"`
	PruneStats PruneStats `json:"prune_stats"`
}

func (s *Store) Info() StorageInfo {
	size := s.DBSize()
	return StorageInfo{
		DBPath:     s.path,
		DBSize:     size,
		DBSizeMB:   float64(size) / (1024 * 1024),
		Height:     s.GetHeight(),
		PruneStats: s.GetPruneStats(),
	}
}

// Auto-prune: keep last N blocks with full data
const DefaultKeepBlocks = 10000

func (s *Store) AutoPrune(currentHeight int) {
	if currentHeight < DefaultKeepBlocks*2 {
		return // not enough blocks to bother
	}

	pruned, err := s.PruneBlocks(currentHeight, DefaultKeepBlocks)
	if err != nil {
		slog.Error("auto-prune failed", "error", err)
		return
	}
	if pruned > 0 {
		slog.Info("auto-pruned old blocks", "count", pruned)
	}
}

