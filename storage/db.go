package storage

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	bolt "go.etcd.io/bbolt"
)

// Bucket names
var (
	bucketBlocks      = []byte("blocks")       // key: height (uint64 BE) → Block JSON
	bucketBlockHash   = []byte("block_hash")   // key: hash → height (uint64 BE)
	bucketState       = []byte("state")        // key: addr → Account JSON
	bucketMeta        = []byte("meta")         // key: various → value
	bucketStaking     = []byte("staking")      // key: addr → Staker JSON
	bucketBridgeLocks = []byte("bridge_locks") // key: id → BridgeLock JSON
	bucketBridgeUnlocks = []byte("bridge_unlocks")
	bucketBridgeConsumed = []byte("bridge_consumed") // key: lock_id → []byte{1}
	bucketPeers       = []byte("peers")        // key: addr → []byte{1}

	metaHeight      = []byte("height")
	metaTotalMinted = []byte("total_minted")
	metaParamsHash  = []byte("params_hash")
	metaGenesis     = []byte("genesis_message")
	metaGenesisHex  = []byte("genesis_message_hex")
	metaParams      = []byte("consensus_params")
)

// Store wraps a BBolt database for blockchain persistence.
type Store struct {
	db   *bolt.DB
	path string
}

// OpenStore opens or creates a BBolt database at the given path.
func OpenStore(dataDir string) (*Store, error) {
	if dataDir == "" || dataDir == "." {
		dataDir = "."
	}
	if dataDir != "." {
		if err := os.MkdirAll(dataDir, 0755); err != nil {
			return nil, fmt.Errorf("create data dir: %w", err)
		}
	}

	dbPath := filepath.Join(dataDir, "boson.db")
	db, err := bolt.Open(dbPath, 0600, &bolt.Options{
		NoFreelistSync: true,
	})
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}

	// Create all buckets
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{
			bucketBlocks, bucketBlockHash, bucketState, bucketMeta,
			bucketStaking, bucketBridgeLocks, bucketBridgeUnlocks,
			bucketBridgeConsumed, bucketPeers,
		} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("create buckets: %w", err)
	}

	slog.Info("database opened", "path", dbPath)
	return &Store{db: db, path: dbPath}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// heightKey encodes height as 8-byte big-endian for sorted iteration.
func heightKey(h int) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(h))
	return b
}

func decodeHeight(b []byte) int {
	return int(binary.BigEndian.Uint64(b))
}

/* -------------------------------------------------------------------------- */
/*                              BLOCK OPERATIONS                               */
/* -------------------------------------------------------------------------- */

// SaveBlock persists a single block and updates the hash index.
func (s *Store) SaveBlock(b *core.Block) error {
	data, err := json.Marshal(b)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBlocks)
		if err := bk.Put(heightKey(b.Header.Height), data); err != nil {
			return err
		}
		// Hash index
		hi := tx.Bucket(bucketBlockHash)
		return hi.Put([]byte(b.Hash), heightKey(b.Header.Height))
	})
}

// GetBlock retrieves a block by height.
func (s *Store) GetBlock(height int) (*core.Block, error) {
	var b core.Block
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBlocks)
		data := bk.Get(heightKey(height))
		if data == nil {
			return fmt.Errorf("block not found at height %d", height)
		}
		return json.Unmarshal(data, &b)
	})
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// GetBlockByHash retrieves a block by its hash.
func (s *Store) GetBlockByHash(hash string) (*core.Block, error) {
	var height int
	err := s.db.View(func(tx *bolt.Tx) error {
		hi := tx.Bucket(bucketBlockHash)
		data := hi.Get([]byte(hash))
		if data == nil {
			return fmt.Errorf("block hash not found: %s", hash)
		}
		height = decodeHeight(data)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return s.GetBlock(height)
}

// GetBlockRange returns blocks from startHeight to endHeight (inclusive).
func (s *Store) GetBlockRange(startHeight, endHeight int) ([]core.Block, error) {
	var blocks []core.Block
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketBlocks)
		c := bk.Cursor()
		for k, v := c.Seek(heightKey(startHeight)); k != nil; k, v = c.Next() {
			h := decodeHeight(k)
			if h > endHeight {
				break
			}
			var b core.Block
			if err := json.Unmarshal(v, &b); err != nil {
				return err
			}
			blocks = append(blocks, b)
		}
		return nil
	})
	return blocks, err
}

// GetLastNBlocks returns the last N blocks (for retarget, stats, etc.)
func (s *Store) GetLastNBlocks(n int) ([]core.Block, error) {
	height := s.GetHeight()
	start := height - n + 1
	if start < 0 {
		start = 0
	}
	return s.GetBlockRange(start, height)
}

/* -------------------------------------------------------------------------- */
/*                              STATE OPERATIONS                               */
/* -------------------------------------------------------------------------- */

// SaveState persists the full account state map.
func (s *Store) SaveState(state map[string]core.Account) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketState)
		for addr, acc := range state {
			data, err := json.Marshal(acc)
			if err != nil {
				return err
			}
			if err := bk.Put([]byte(addr), data); err != nil {
				return err
			}
		}
		return nil
	})
}

// SaveAccount persists a single account.
func (s *Store) SaveAccount(addr string, acc core.Account) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketState)
		data, err := json.Marshal(acc)
		if err != nil {
			return err
		}
		return bk.Put([]byte(addr), data)
	})
}

// GetAccount retrieves an account by address.
func (s *Store) GetAccount(addr string) (core.Account, error) {
	var acc core.Account
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketState)
		data := bk.Get([]byte(addr))
		if data == nil {
			return nil // zero account
		}
		return json.Unmarshal(data, &acc)
	})
	return acc, err
}

// LoadFullState loads ALL accounts into a map (for in-memory processing).
func (s *Store) LoadFullState() (map[string]core.Account, error) {
	state := map[string]core.Account{}
	err := s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketState)
		return bk.ForEach(func(k, v []byte) error {
			var acc core.Account
			if err := json.Unmarshal(v, &acc); err != nil {
				return err
			}
			state[string(k)] = acc
			return nil
		})
	})
	return state, err
}

/* -------------------------------------------------------------------------- */
/*                              META OPERATIONS                                */
/* -------------------------------------------------------------------------- */

// SaveMeta stores metadata key-value pairs.
func (s *Store) SaveMeta(key, value []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(key, value)
	})
}

func (s *Store) GetMeta(key []byte) []byte {
	var val []byte
	s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get(key)
		if v != nil {
			val = make([]byte, len(v))
			copy(val, v)
		}
		return nil
	})
	return val
}

// GetHeight returns the current chain height (or -1 if empty).
func (s *Store) GetHeight() int {
	v := s.GetMeta(metaHeight)
	if v == nil {
		return -1
	}
	return int(binary.BigEndian.Uint64(v))
}

// SetHeight stores the current chain height.
func (s *Store) SetHeight(h int) error {
	return s.SaveMeta(metaHeight, heightKey(h))
}

// GetTotalMinted returns total minted units.
func (s *Store) GetTotalMinted() uint64 {
	v := s.GetMeta(metaTotalMinted)
	if v == nil {
		return 0
	}
	return binary.BigEndian.Uint64(v)
}

// SetTotalMinted stores total minted units.
func (s *Store) SetTotalMinted(m uint64) error {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, m)
	return s.SaveMeta(metaTotalMinted, b)
}

func (s *Store) GetParamsHash() string {
	v := s.GetMeta(metaParamsHash)
	if v == nil {
		return ""
	}
	return string(v)
}

func (s *Store) SetParamsHash(h string) error {
	return s.SaveMeta(metaParamsHash, []byte(h))
}

/* -------------------------------------------------------------------------- */
/*                              STAKING                                        */
/* -------------------------------------------------------------------------- */

func (s *Store) SaveStaking(staking core.StakingState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketStaking)
		for addr, staker := range staking.Validators {
			data, err := json.Marshal(staker)
			if err != nil {
				return err
			}
			if err := bk.Put([]byte(addr), data); err != nil {
				return err
			}
		}
		// Save totals as meta
		meta := tx.Bucket(bucketMeta)
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, staking.TotalStaked)
		return meta.Put([]byte("staking_total"), b)
	})
}

func (s *Store) LoadStaking() core.StakingState {
	st := core.StakingState{
		Validators: map[string]core.Staker{},
	}
	s.db.View(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketStaking)
		bk.ForEach(func(k, v []byte) error {
			var staker core.Staker
			if err := json.Unmarshal(v, &staker); err == nil {
				st.Validators[string(k)] = staker
			}
			return nil
		})
		meta := tx.Bucket(bucketMeta)
		if v := meta.Get([]byte("staking_total")); v != nil {
			st.TotalStaked = binary.BigEndian.Uint64(v)
		}
		return nil
	})
	return st
}

/* -------------------------------------------------------------------------- */
/*                              BRIDGE                                         */
/* -------------------------------------------------------------------------- */

func (s *Store) SaveBridge(bridge core.BridgeState) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		locks := tx.Bucket(bucketBridgeLocks)
		for id, lock := range bridge.Locks {
			data, err := json.Marshal(lock)
			if err != nil {
				return fmt.Errorf("marshal lock %s: %w", id, err)
			}
			if err := locks.Put([]byte(id), data); err != nil {
				return err
			}
		}
		unlocks := tx.Bucket(bucketBridgeUnlocks)
		for id, unlock := range bridge.Unlocks {
			data, err := json.Marshal(unlock)
			if err != nil {
				return fmt.Errorf("marshal unlock %s: %w", id, err)
			}
			if err := unlocks.Put([]byte(id), data); err != nil {
				return err
			}
		}
		consumed := tx.Bucket(bucketBridgeConsumed)
		for id := range bridge.Consumed {
			if err := consumed.Put([]byte(id), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) LoadBridge() core.BridgeState {
	bs := core.BridgeState{
		Locks:    map[string]core.BridgeLock{},
		Unlocks:  map[string]core.BridgeUnlock{},
		Consumed: map[string]bool{},
	}
	s.db.View(func(tx *bolt.Tx) error {
		tx.Bucket(bucketBridgeLocks).ForEach(func(k, v []byte) error {
			var lock core.BridgeLock
			if json.Unmarshal(v, &lock) == nil {
				bs.Locks[string(k)] = lock
			}
			return nil
		})
		tx.Bucket(bucketBridgeUnlocks).ForEach(func(k, v []byte) error {
			var unlock core.BridgeUnlock
			if json.Unmarshal(v, &unlock) == nil {
				bs.Unlocks[string(k)] = unlock
			}
			return nil
		})
		tx.Bucket(bucketBridgeConsumed).ForEach(func(k, v []byte) error {
			bs.Consumed[string(k)] = true
			return nil
		})
		return nil
	})
	return bs
}

/* -------------------------------------------------------------------------- */
/*                              PEERS                                          */
/* -------------------------------------------------------------------------- */

func (s *Store) SavePeers(peers []string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		bk := tx.Bucket(bucketPeers)
		for _, p := range peers {
			if err := bk.Put([]byte(p), []byte{1}); err != nil {
				return err
			}
		}
		return nil
	})
}

func (s *Store) LoadPeers() []string {
	var peers []string
	s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeers).ForEach(func(k, v []byte) error {
			peers = append(peers, string(k))
			return nil
		})
	})
	return peers
}

func (s *Store) AddPeer(addr string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketPeers).Put([]byte(addr), []byte{1})
	})
}

/* -------------------------------------------------------------------------- */
/*                         FULL CHAIN SAVE/LOAD                                */
/* -------------------------------------------------------------------------- */

// SaveBlockAndState atomically saves a new block + updated state + meta.
// This replaces the old SaveChain (which wrote the entire chain as one JSON).
func (s *Store) SaveBlockAndState(b *core.Block, state map[string]core.Account, totalMinted uint64) error {
	blockData, err := json.Marshal(b)
	if err != nil {
		return err
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		// Save block
		bk := tx.Bucket(bucketBlocks)
		if err := bk.Put(heightKey(b.Header.Height), blockData); err != nil {
			return err
		}

		// Hash index
		hi := tx.Bucket(bucketBlockHash)
		if err := hi.Put([]byte(b.Hash), heightKey(b.Header.Height)); err != nil {
			return err
		}

		// Update state (only changed accounts)
		stBk := tx.Bucket(bucketState)
		for addr, acc := range state {
			data, err := json.Marshal(acc)
			if err != nil {
				return fmt.Errorf("marshal account %s: %w", addr, err)
			}
			if err := stBk.Put([]byte(addr), data); err != nil {
				return err
			}
		}

		// Update meta
		meta := tx.Bucket(bucketMeta)
		if err := meta.Put(metaHeight, heightKey(b.Header.Height)); err != nil {
			return err
		}
		mintedBytes := make([]byte, 8)
		binary.BigEndian.PutUint64(mintedBytes, totalMinted)
		return meta.Put(metaTotalMinted, mintedBytes)
	})
}

// InitFromChain migrates an existing in-memory Chain to the database.
func (s *Store) InitFromChain(c *core.Chain) error {
	slog.Info("migrating chain to database", "blocks", len(c.Blocks))

	// Save all blocks
	for i := range c.Blocks {
		if err := s.SaveBlock(&c.Blocks[i]); err != nil {
			return fmt.Errorf("save block %d: %w", i, err)
		}
	}

	// Save state
	if err := s.SaveState(c.State); err != nil {
		return fmt.Errorf("save state: %w", err)
	}

	// Save meta
	if len(c.Blocks) > 0 {
		lastHeight := c.Blocks[len(c.Blocks)-1].Header.Height
		s.SetHeight(lastHeight)
	}
	s.SetTotalMinted(c.TotalMinted)
	s.SetParamsHash(c.ParamsHash)
	s.SaveMeta(metaGenesis, []byte(c.GenesisMessage))
	s.SaveMeta(metaGenesisHex, []byte(c.GenesisMessageHex))

	// Save consensus params
	paramsData, err := json.Marshal(c.Params)
	if err != nil {
		return fmt.Errorf("marshal params: %w", err)
	}
	s.SaveMeta(metaParams, paramsData)

	// Save staking
	if err := s.SaveStaking(c.Staking); err != nil {
		return fmt.Errorf("save staking: %w", err)
	}

	// Save bridge
	if err := s.SaveBridge(c.Bridge); err != nil {
		return fmt.Errorf("save bridge: %w", err)
	}

	// Save peers
	if err := s.SavePeers(c.Peers); err != nil {
		return fmt.Errorf("save peers: %w", err)
	}

	slog.Info("migration complete")
	return nil
}

// LoadToChain loads the entire database into an in-memory Chain.
// Used at startup and for backwards compatibility.
func (s *Store) LoadToChain() (*core.Chain, error) {
	height := s.GetHeight()
	if height < 0 {
		return nil, fmt.Errorf("empty database")
	}

	blocks, err := s.GetBlockRange(0, height)
	if err != nil {
		return nil, fmt.Errorf("load blocks: %w", err)
	}

	state, err := s.LoadFullState()
	if err != nil {
		return nil, fmt.Errorf("load state: %w", err)
	}

	var params core.ConsensusParams
	if v := s.GetMeta(metaParams); v != nil {
		json.Unmarshal(v, &params)
	}

	genesisMsg := string(s.GetMeta(metaGenesis))
	if genesisMsg == "" {
		genesisMsg = core.GenesisMessage
	}

	c := &core.Chain{
		Blocks:            blocks,
		Peers:             s.LoadPeers(),
		State:             state,
		TotalMinted:       s.GetTotalMinted(),
		ParamsHash:        s.GetParamsHash(),
		Staking:           s.LoadStaking(),
		Contracts:         map[string]core.Contract{},
		Params:            params,
		Bridge:            s.LoadBridge(),
		GenesisMessage:    genesisMsg,
		GenesisMessageHex: string(s.GetMeta(metaGenesisHex)),
	}

	slog.Info("chain loaded from database", "blocks", len(c.Blocks), "accounts", len(c.State), "height", height)
	return c, nil
}
