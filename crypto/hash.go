package crypto

import (
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func Sha512Hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

func HashBytes(b []byte) string {
	return Sha512Hex(b)
}

func AddrFromPub(pub []byte) string {
	sum := sha512.Sum512(pub)
	return hex.EncodeToString(sum[:20])
}

func MerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return Sha512Hex(nil)
	}
	level := make([][]byte, len(hashes))
	for i, h := range hashes {
		b, err := hex.DecodeString(h)
		if err != nil {
			level[i] = []byte(h)
		} else {
			level[i] = b
		}
	}
	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 == len(level) {
				sum := sha512.Sum512(level[i])
				next = append(next, sum[:])
			} else {
				combined := append(level[i], level[i+1]...)
				sum := sha512.Sum512(combined)
				next = append(next, sum[:])
			}
		}
		level = next
	}
	return hex.EncodeToString(level[0])
}

func BlockHash(b core.Block) string {
	data := struct {
		H core.BlockHeader `json:"h"`
		M string           `json:"m"`
	}{
		H: b.Header,
		M: b.Mix,
	}
	enc, err := json.Marshal(data)
	if err != nil {
		return "" // should never happen with fixed struct types
	}
	return Sha512Hex(enc)
}
