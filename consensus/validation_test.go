package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
)

func TestValidateTx_Valid(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)
	addr := crypto.AddrFromPub(pub)

	state := map[string]core.Account{
		addr: {Balance: 1_000_000_000, Nonce: 0},
	}

	toAddr := "cccccccccccccccccccccccccccccccccccccccc"
	amount := uint64(100_000_000)
	fee := CalcFee(amount)

	tx, err := crypto.BuildTx(privHex, pubHex, addr, toAddr, amount, fee, 1, "transfer", "")
	if err != nil {
		t.Fatalf("BuildTx failed: %v", err)
	}

	if !ValidateTx(state, tx) {
		t.Error("valid transaction rejected")
	}
}

func TestValidateTx_BadNonce(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)
	addr := crypto.AddrFromPub(pub)

	state := map[string]core.Account{
		addr: {Balance: 1_000_000_000, Nonce: 5},
	}

	toAddr := "cccccccccccccccccccccccccccccccccccccccc"
	amount := uint64(100_000_000)
	fee := CalcFee(amount)

	tx, _ := crypto.BuildTx(privHex, pubHex, addr, toAddr, amount, fee, 3, "", "")

	if ValidateTx(state, tx) {
		t.Error("should reject bad nonce")
	}
}

func TestValidateTx_InsufficientBalance(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)
	addr := crypto.AddrFromPub(pub)

	state := map[string]core.Account{
		addr: {Balance: 100, Nonce: 0},
	}

	toAddr := "cccccccccccccccccccccccccccccccccccccccc"
	amount := uint64(1_000_000_000)
	fee := CalcFee(amount)

	tx, _ := crypto.BuildTx(privHex, pubHex, addr, toAddr, amount, fee, 1, "", "")

	if ValidateTx(state, tx) {
		t.Error("should reject insufficient balance")
	}
}

func TestValidateTx_InvalidType(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	pubHex := hex.EncodeToString(pub)
	privHex := hex.EncodeToString(priv)
	addr := crypto.AddrFromPub(pub)

	state := map[string]core.Account{
		addr: {Balance: 1_000_000_000, Nonce: 0},
	}

	toAddr := "cccccccccccccccccccccccccccccccccccccccc"
	amount := uint64(100_000_000)
	fee := CalcFee(amount)

	tx, _ := crypto.BuildTx(privHex, pubHex, addr, toAddr, amount, fee, 1, "malicious_type", "")

	if ValidateTx(state, tx) {
		t.Error("should reject invalid tx type")
	}
}
