package crypto

import (
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"log/slog"
	"sync"
)

/* -------------------------------------------------------------------------- */
/*                           DAG-BASED MEMORY-HARD POW                         */
/* -------------------------------------------------------------------------- */
// The DAG is a large dataset (configurable, default 256MB) that miners must
// keep in GPU VRAM. Mining involves random reads from the DAG combined with
// SHA-512 hashing. This makes the PoW:
//   - Memory-hard (GPU VRAM advantage over CPU cache)
//   - ASIC-resistant (random access pattern is hard to optimize in silicon)
//   - Deterministic (same epoch → same DAG → same results)
//
// DAG is regenerated every DAGEpochBlocks (30000 blocks, ~139 days at 400s/block).

const (
	DAGEpochBlocks  = 30000          // blocks per epoch
	DAGSizeBase     = 256 * 1024 * 1024 // 256MB base DAG size
	DAGGrowthPerEpoch = 8 * 1024 * 1024  // grow 8MB per epoch
	DAGMaxSize      = 4 * 1024 * 1024 * 1024 // 4GB max
	DAGMixRounds    = 64             // random reads per hash
	DAGPageSize     = 128            // bytes read per DAG access
)

// DAG holds the generated dataset for a specific epoch.
type DAG struct {
	mu    sync.RWMutex
	Epoch int
	Data  []byte
	Size  int
}

var (
	currentDAG *DAG
	dagMu      sync.Mutex
)

// DAGEpoch returns the epoch number for a given block height.
func DAGEpoch(height int) int {
	return height / DAGEpochBlocks
}

// DAGSize returns the DAG size in bytes for a given epoch.
func DAGSize(epoch int) int {
	size := DAGSizeBase + epoch*DAGGrowthPerEpoch
	if size > DAGMaxSize {
		size = DAGMaxSize
	}
	// Round to page size
	return (size / DAGPageSize) * DAGPageSize
}

// GetDAG returns the DAG for the given epoch, generating it if needed.
func GetDAG(epoch int) *DAG {
	dagMu.Lock()
	defer dagMu.Unlock()

	if currentDAG != nil && currentDAG.Epoch == epoch {
		return currentDAG
	}

	slog.Info("generating DAG", "epoch", epoch, "size_mb", DAGSize(epoch)/(1024*1024))
	dag := GenerateDAG(epoch)
	currentDAG = dag
	slog.Info("DAG generated", "epoch", epoch)
	return dag
}

// GenerateDAG creates a new DAG for the given epoch.
// The DAG is deterministic: same epoch → same DAG.
func GenerateDAG(epoch int) *DAG {
	size := DAGSize(epoch)
	data := make([]byte, size)

	// Seed from epoch number
	seed := sha512.Sum512([]byte(fmt.Sprintf("boson-dag-epoch-%d", epoch)))

	// Fill DAG with pseudorandom data derived from seed
	// Each 64-byte block is computed from the previous one
	copy(data[:64], seed[:])

	for i := 64; i < size; i += 64 {
		// Mix previous block with position-dependent value
		var buf [72]byte
		copy(buf[:64], data[i-64:i])
		binary.BigEndian.PutUint64(buf[64:], uint64(i))
		h := sha512.Sum512(buf[:])
		end := i + 64
		if end > size {
			end = size
		}
		copy(data[i:end], h[:end-i])
	}

	// Second pass: each element depends on a pseudo-random previous element
	for i := 64; i < size-63; i += 64 {
		pages := uint64(i / 64)
		if pages == 0 {
			continue
		}
		idx := binary.BigEndian.Uint64(data[i:i+8]) % pages
		srcOff := int(idx) * 64
		if srcOff+64 > size {
			continue // bounds safety
		}

		var buf [128]byte
		copy(buf[:64], data[i:i+64])
		copy(buf[64:128], data[srcOff:srcOff+64])
		h := sha512.Sum512(buf[:])
		copy(data[i:i+64], h[:])
	}

	return &DAG{
		Epoch: epoch,
		Data:  data,
		Size:  size,
	}
}

// MixHashDAG computes the PoW hash using DAG random reads.
// This is the memory-hard replacement for the simple MixHash.
func MixHashDAG(headerHex string, nonce uint64, dag *DAG) string {
	raw, err := hexDecode(headerHex)
	if err != nil || len(raw) == 0 {
		return ""
	}

	// Initial hash: SHA-512(header + nonce)
	var initBuf [8]byte
	binary.BigEndian.PutUint64(initBuf[:], nonce)

	initData := make([]byte, len(raw)+8)
	copy(initData, raw)
	copy(initData[len(raw):], initBuf[:])
	mix := sha512.Sum512(initData)

	// DAG random read rounds
	dagPages := dag.Size / DAGPageSize
	if dagPages == 0 {
		dagPages = 1
	}

	for round := 0; round < DAGMixRounds; round++ {
		// Derive page index from current mix state
		pageIdx := binary.BigEndian.Uint64(mix[round%56:round%56+8]) % uint64(dagPages)
		offset := int(pageIdx) * DAGPageSize

		// Bounds check
		end := offset + DAGPageSize
		if end > dag.Size {
			end = dag.Size
		}
		dagSlice := dag.Data[offset:end]

		// XOR DAG page into mix
		for j := 0; j < len(dagSlice) && j < 64; j++ {
			mix[j] ^= dagSlice[j]
		}

		// Re-hash
		mix = sha512.Sum512(mix[:])
	}

	return hexEncode(mix[:])
}

// Helper to avoid import cycle with hex package
func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd-length hex string")
	}
	b := make([]byte, len(s)/2)
	for i := 0; i < len(b); i++ {
		hi := hexVal(s[2*i])
		lo := hexVal(s[2*i+1])
		if hi < 0 || lo < 0 {
			return nil, fmt.Errorf("invalid hex at pos %d", 2*i)
		}
		b[i] = byte(hi<<4 | lo)
	}
	return b, nil
}

func hexEncode(b []byte) string {
	const hextable = "0123456789abcdef"
	dst := make([]byte, len(b)*2)
	for i, v := range b {
		dst[i*2] = hextable[v>>4]
		dst[i*2+1] = hextable[v&0x0f]
	}
	return string(dst)
}

func hexVal(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c - 'a' + 10)
	case c >= 'A' && c <= 'F':
		return int(c - 'A' + 10)
	default:
		return -1
	}
}
