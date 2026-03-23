package storage

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bolt "go.etcd.io/bbolt"
)

/* -------------------------------------------------------------------------- */
/*                              CHECKPOINTS                                    */
/* -------------------------------------------------------------------------- */
// Checkpoints store periodic snapshots of the state hash at known heights.
// New nodes can verify they're on the correct chain by comparing checkpoint
// hashes without replaying every block.
//
// Checkpoint interval: every 10000 blocks.

const CheckpointInterval = 10000

var bucketCheckpoints = []byte("checkpoints")

// Checkpoint stores a verified state hash at a given height.
type Checkpoint struct {
	Height    int    `json:"height"`
	BlockHash string `json:"block_hash"`
	StateHash string `json:"state_hash"` // SHA-256 of sorted state JSON
}

// EnsureCheckpointBucket creates the checkpoint bucket if missing.
func (s *Store) EnsureCheckpointBucket() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists(bucketCheckpoints)
		return err
	})
}

// SaveCheckpoint stores a checkpoint.
func (s *Store) SaveCheckpoint(cp Checkpoint) error {
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("marshal checkpoint: %w", err)
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketCheckpoints)
		if bk == nil {
			return nil
		}
		return bk.Put(heightKey(cp.Height), data)
	})
}

// GetCheckpoint returns a checkpoint at a given height.
func (s *Store) GetCheckpoint(height int) (*Checkpoint, error) {
	var cp Checkpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketCheckpoints)
		if bk == nil {
			return fmt.Errorf("no checkpoints bucket")
		}
		data := bk.Get(heightKey(height))
		if data == nil {
			return fmt.Errorf("no checkpoint at height %d", height)
		}
		return json.Unmarshal(data, &cp)
	})
	return &cp, err
}

// GetLatestCheckpoint returns the most recent checkpoint.
func (s *Store) GetLatestCheckpoint() *Checkpoint {
	var cp Checkpoint
	found := false
	s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketCheckpoints)
		if bk == nil {
			return nil
		}
		c := bk.Cursor()
		k, v := c.Last()
		if k != nil && v != nil {
			if json.Unmarshal(v, &cp) == nil {
				found = true
			}
		}
		return nil
	})
	if !found {
		return nil
	}
	return &cp
}

// ListCheckpoints returns all checkpoints.
func (s *Store) ListCheckpoints() []Checkpoint {
	var cps []Checkpoint
	s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketCheckpoints)
		if bk == nil {
			return nil
		}
		return bk.ForEach(func(k, v []byte) error {
			var cp Checkpoint
			if json.Unmarshal(v, &cp) == nil {
				cps = append(cps, cp)
			}
			return nil
		})
	})
	return cps
}

// MaybeCreateCheckpoint creates a checkpoint if height is at a checkpoint interval.
func (s *Store) MaybeCreateCheckpoint(chain *core.Chain, height int) {
	if height == 0 || height%CheckpointInterval != 0 {
		return
	}

	// Find block at this height
	var blockHash string
	for _, b := range chain.Blocks {
		if b.Header.Height == height {
			blockHash = b.Hash
			break
		}
	}
	if blockHash == "" {
		return
	}

	stateHash := ComputeStateHash(chain.State)

	cp := Checkpoint{
		Height:    height,
		BlockHash: blockHash,
		StateHash: stateHash,
	}

	if err := s.SaveCheckpoint(cp); err != nil {
		slog.Error("save checkpoint failed", "height", height, "error", err)
		return
	}

	slog.Info("checkpoint created", "height", height, "state_hash", stateHash[:16])
}

// ComputeStateHash computes a deterministic hash of the account state.
func ComputeStateHash(state map[string]core.Account) string {
	// Sort addresses for determinism
	type entry struct {
		Addr string       `json:"a"`
		Acc  core.Account `json:"b"`
	}

	var entries []entry
	for addr, acc := range state {
		entries = append(entries, entry{Addr: addr, Acc: acc})
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Addr < entries[j].Addr
	})

	data, err := json.Marshal(entries)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

// VerifyCheckpoint verifies that a chain state matches a known checkpoint.
func VerifyCheckpoint(state map[string]core.Account, cp *Checkpoint) bool {
	actual := ComputeStateHash(state)
	return actual == cp.StateHash
}
