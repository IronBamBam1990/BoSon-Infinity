package storage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bolt "go.etcd.io/bbolt"
)

// TX Index buckets
var (
	bucketTxIndex   = []byte("tx_index")      // tx_hash -> TxLocation JSON
	bucketAddrTxs   = []byte("addr_txs")      // addr+height_bytes+idx -> tx_hash
)

// TxLocation stores where a TX lives in the chain.
type TxLocation struct {
	BlockHeight int    `json:"block_height"`
	BlockHash   string `json:"block_hash"`
	TxIndex     int    `json:"tx_index"`
}

// EnsureTxIndexBuckets creates TX index buckets if missing.
func (s *Store) EnsureTxIndexBuckets() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketTxIndex, bucketAddrTxs} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
}

// IndexBlockTxs indexes all transactions in a block.
func (s *Store) IndexBlockTxs(block *core.Block) error {
	if len(block.Txs) == 0 {
		return nil
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		txIdx := tx.Bucket(bucketTxIndex)
		addrIdx := tx.Bucket(bucketAddrTxs)
		if txIdx == nil || addrIdx == nil {
			return nil // buckets not created yet
		}

		for i, btx := range block.Txs {
			loc := TxLocation{
				BlockHeight: block.Header.Height,
				BlockHash:   block.Hash,
				TxIndex:     i,
			}
			locData, err := json.Marshal(loc)
			if err != nil {
				return fmt.Errorf("marshal tx location: %w", err)
			}

			// tx_hash → location
			if err := txIdx.Put([]byte(btx.Hash), locData); err != nil {
				return err
			}

			// addr_txs: from_addr
			addrKey := makeAddrTxKey(btx.From, block.Header.Height, i)
			if err := addrIdx.Put(addrKey, []byte(btx.Hash)); err != nil {
				return err
			}

			// addr_txs: to_addr (if different)
			if btx.To != btx.From {
				addrKey2 := makeAddrTxKey(btx.To, block.Header.Height, i)
				if err := addrIdx.Put(addrKey2, []byte(btx.Hash)); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// GetTxByHash retrieves a transaction and its location by hash.
func (s *Store) GetTxByHash(hash string) (*core.Tx, *TxLocation, error) {
	var loc TxLocation
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketTxIndex)
		if bk == nil {
			return fmt.Errorf("tx_index bucket not found")
		}
		data := bk.Get([]byte(hash))
		if data == nil {
			return fmt.Errorf("tx not found")
		}
		return json.Unmarshal(data, &loc)
	})
	if err != nil {
		return nil, nil, err
	}

	block, err := s.GetBlock(loc.BlockHeight)
	if err != nil {
		return nil, nil, err
	}

	if loc.TxIndex >= len(block.Txs) {
		return nil, nil, fmt.Errorf("tx index out of range")
	}

	tx := block.Txs[loc.TxIndex]
	return &tx, &loc, nil
}

// GetTxsByAddr returns TX hashes for an address, newest first.
// Returns up to `limit` results starting from `offset`.
func (s *Store) GetTxsByAddr(addr string, offset, limit int) ([]string, error) {
	var hashes []string

	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketAddrTxs)
		if bk == nil {
			return nil
		}

		prefix := []byte(addr)
		c := bk.Cursor()

		// Collect all matching keys (addr prefix)
		var allKeys [][]byte
		for k, _ := c.Seek(prefix); k != nil && len(k) >= 40 && string(k[:40]) == addr; k, _ = c.Next() {
			keyCopy := make([]byte, len(k))
			copy(keyCopy, k)
			allKeys = append(allKeys, keyCopy)
		}

		// Reverse for newest first
		for i, j := 0, len(allKeys)-1; i < j; i, j = i+1, j-1 {
			allKeys[i], allKeys[j] = allKeys[j], allKeys[i]
		}

		// Apply offset+limit
		start := offset
		if start > len(allKeys) {
			return nil
		}
		end := start + limit
		if end > len(allKeys) {
			end = len(allKeys)
		}

		for _, k := range allKeys[start:end] {
			v := bk.Get(k)
			if v != nil {
				hashes = append(hashes, string(v))
			}
		}
		return nil
	})

	return hashes, err
}

// makeAddrTxKey creates a key: addr(40) + height(8 BE) + txidx(4 BE)
func makeAddrTxKey(addr string, height, txIdx int) []byte {
	key := make([]byte, 40+8+4)
	copy(key[:40], addr)
	binary.BigEndian.PutUint64(key[40:48], uint64(height))
	binary.BigEndian.PutUint32(key[48:52], uint32(txIdx))
	return key
}

// RebuildTxIndex re-indexes all transactions from all blocks. Use for migration.
func (s *Store) RebuildTxIndex() error {
	s.EnsureTxIndexBuckets()

	height := s.GetHeight()
	if height < 0 {
		return nil
	}

	for h := 0; h <= height; h++ {
		block, err := s.GetBlock(h)
		if err != nil {
			continue
		}
		if err := s.IndexBlockTxs(block); err != nil {
			return fmt.Errorf("index block %d: %w", h, err)
		}
	}
	return nil
}
