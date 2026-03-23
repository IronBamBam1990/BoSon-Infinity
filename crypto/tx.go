package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

func BuildTx(privHex, pubHex, from, to string, amount, fee, nonce uint64, txType, data string) (core.Tx, error) {
	priv, err := hex.DecodeString(privHex)
	if err != nil || len(priv) != ed25519.PrivateKeySize {
		return core.Tx{}, fmt.Errorf("bad private key")
	}
	if _, err := hex.DecodeString(pubHex); err != nil {
		return core.Tx{}, fmt.Errorf("bad pubkey")
	}

	payload := core.TxPayload{
		ChainID: core.NetworkName,
		From:    from,
		To:      to,
		Amount:  amount,
		Fee:     fee,
		Nonce:   nonce,
		PubKey:  pubHex,
		Type:    txType,
		Data:    data,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return core.Tx{}, fmt.Errorf("marshal payload: %w", err)
	}

	sig := ed25519.Sign(priv, raw)
	sigHex := hex.EncodeToString(sig)
	h := HashBytes(raw)

	return core.Tx{
		From:   from,
		To:     to,
		Amount: amount,
		Fee:    fee,
		Nonce:  nonce,
		PubKey: pubHex,
		Sig:    sigHex,
		Hash:   h,
		Type:   txType,
		Data:   data,
	}, nil
}

func VerifyTxSignature(tx core.Tx) bool {
	pub, err := hex.DecodeString(tx.PubKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}

	payload := core.TxPayload{
		ChainID: core.NetworkName,
		From:    tx.From,
		To:      tx.To,
		Amount:  tx.Amount,
		Fee:     tx.Fee,
		Nonce:   tx.Nonce,
		PubKey:  tx.PubKey,
		Type:    tx.Type,
		Data:    tx.Data,
	}

	raw, err := json.Marshal(payload)
	if err != nil {
		return false
	}

	sig, err := hex.DecodeString(tx.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}

	return ed25519.Verify(ed25519.PublicKey(pub), raw, sig)
}
