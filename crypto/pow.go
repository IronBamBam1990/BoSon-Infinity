package crypto

import (
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func MixHash(headerHex string, nonce uint64) string {
	raw, err := hex.DecodeString(headerHex)
	if err != nil {
		return ""
	}

	rolling := make([]byte, 64)
	for j := 0; j < core.ReadsPerTry; j++ {
		k := int((nonce + uint64(j)) % 64)
		rolling[k] ^= byte((nonce >> (uint(j)&7) * 8) & 0xff)
	}

	buf := make([]byte, 0, len(raw)+8+64)
	buf = append(buf, raw...)

	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], nonce)
	buf = append(buf, nb[:]...)
	buf = append(buf, rolling...)

	sum := sha512.Sum512(buf)
	return hex.EncodeToString(sum[:])
}

func CheckMask(mixHex string, bits int) bool {
	raw, err := hex.DecodeString(mixHex)
	if err != nil || len(raw) < 8 {
		return false
	}
	var v uint64
	for i := 0; i < 8; i++ {
		v = (v << 8) | uint64(raw[len(raw)-8+i])
	}
	if bits >= 64 {
		return v == 0
	}
	mask := (uint64(1) << bits) - 1
	return (v & mask) == 0
}
