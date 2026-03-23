package mempool

import (
	"sort"
	"sync"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

// Mempool is a thread-safe, indexed transaction pool with fee-priority ordering.
type Mempool struct {
	mu         sync.RWMutex
	txsByHash  map[string]*core.Tx            // O(1) lookup by hash
	txsByAddr  map[string]map[string]*core.Tx // from_addr -> hash -> tx (O(1) per-addr count)
	maxSize    int
	maxPerAddr int
}

// New creates a new Mempool with given limits.
func New(maxSize, maxPerAddr int) *Mempool {
	return &Mempool{
		txsByHash:  make(map[string]*core.Tx),
		txsByAddr:  make(map[string]map[string]*core.Tx),
		maxSize:    maxSize,
		maxPerAddr: maxPerAddr,
	}
}

// Add inserts a transaction. Returns false if duplicate, full, or per-addr limit hit.
func (m *Mempool) Add(tx core.Tx) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Duplicate check — O(1)
	if _, exists := m.txsByHash[tx.Hash]; exists {
		return false
	}

	// Size limit
	if len(m.txsByHash) >= m.maxSize {
		return false
	}

	// Per-address limit — O(1)
	addrTxs := m.txsByAddr[tx.From]
	if addrTxs != nil && len(addrTxs) >= m.maxPerAddr {
		return false
	}

	// Add to both indexes
	m.txsByHash[tx.Hash] = &tx

	if m.txsByAddr[tx.From] == nil {
		m.txsByAddr[tx.From] = make(map[string]*core.Tx)
	}
	m.txsByAddr[tx.From][tx.Hash] = &tx

	return true
}

// Has returns true if a TX with given hash is in the mempool — O(1).
func (m *Mempool) Has(hash string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, exists := m.txsByHash[hash]
	return exists
}

// Get returns a TX by hash.
func (m *Mempool) Get(hash string) (*core.Tx, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	tx, ok := m.txsByHash[hash]
	return tx, ok
}

// CountByAddr returns the number of pending TXs from an address — O(1).
func (m *Mempool) CountByAddr(addr string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txsByAddr[addr])
}

// HasNonceConflict checks if any TX from the same address has nonce >= given nonce.
func (m *Mempool) HasNonceConflict(from string, nonce uint64) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	addrTxs := m.txsByAddr[from]
	for _, tx := range addrTxs {
		if nonce <= tx.Nonce {
			return true
		}
	}
	return false
}

// Remove deletes a transaction by hash — O(1).
func (m *Mempool) Remove(hash string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removeLocked(hash)
}

func (m *Mempool) removeLocked(hash string) {
	tx, ok := m.txsByHash[hash]
	if !ok {
		return
	}
	delete(m.txsByHash, hash)
	if addrTxs, ok := m.txsByAddr[tx.From]; ok {
		delete(addrTxs, hash)
		if len(addrTxs) == 0 {
			delete(m.txsByAddr, tx.From)
		}
	}
}

// Purge removes all transactions included in the given block.
func (m *Mempool) Purge(txs []core.Tx) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tx := range txs {
		m.removeLocked(tx.Hash)
	}
}

// Size returns the number of TXs in the mempool.
func (m *Mempool) Size() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txsByHash)
}

// GetForAddr returns pending TXs for an address (sent or received).
func (m *Mempool) GetForAddr(addr string) []core.Tx {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []core.Tx
	// TXs sent from this address (O(1) lookup via index)
	if addrTxs, ok := m.txsByAddr[addr]; ok {
		for _, tx := range addrTxs {
			out = append(out, *tx)
		}
	}
	// TXs received by this address (O(n) scan — no recipient index)
	for _, tx := range m.txsByHash {
		if tx.To == addr && tx.From != addr {
			out = append(out, *tx)
		}
	}
	return out
}

// All returns all TXs as a slice (for JSON serialization).
func (m *Mempool) All() []core.Tx {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]core.Tx, 0, len(m.txsByHash))
	for _, tx := range m.txsByHash {
		out = append(out, *tx)
	}
	return out
}

// PickForBlock returns up to maxTxs transactions sorted by fee (highest first).
func (m *Mempool) PickForBlock(maxTxs int) []core.Tx {
	m.mu.RLock()
	defer m.mu.RUnlock()

	all := make([]core.Tx, 0, len(m.txsByHash))
	for _, tx := range m.txsByHash {
		all = append(all, *tx)
	}

	// Sort by fee descending (highest fee first = priority)
	sort.Slice(all, func(i, j int) bool {
		return all[i].Fee > all[j].Fee
	})

	if len(all) > maxTxs {
		all = all[:maxTxs]
	}
	return all
}

// IsFull returns true if mempool is at capacity.
func (m *Mempool) IsFull() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.txsByHash) >= m.maxSize
}
