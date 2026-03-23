package consensus

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
)

/* -------------------------------------------------------------------------- */
/*                           MULTI-SIG BRIDGE                                  */
/* -------------------------------------------------------------------------- */
// Bridge unlock operations require M-of-N guardian signatures.
// Guardians are Ed25519 public keys configured at genesis.
// Default: 3-of-5 guardians must sign for an unlock.

const (
	DefaultGuardiansRequired = 3 // M
	DefaultGuardiansTotal    = 5 // N
)

// BridgeGuardianConfig holds multi-sig parameters.
type BridgeGuardianConfig struct {
	Required   int      `json:"required"`    // M signatures needed
	Guardians  []string `json:"guardians"`   // N guardian public keys (hex)
}

// BridgeUnlockRequest is submitted with multiple guardian signatures.
type BridgeUnlockRequest struct {
	LockID     string   `json:"lock_id"`
	ToNative   string   `json:"to_native"`
	Signatures []string `json:"signatures"` // hex-encoded Ed25519 signatures
	Signers    []string `json:"signers"`    // pubkeys of signers (matching order)
}

// ValidateMultiSigUnlock checks that enough valid guardian signatures are present.
func ValidateMultiSigUnlock(req BridgeUnlockRequest, guardians BridgeGuardianConfig) error {
	if len(req.Signatures) < guardians.Required {
		return fmt.Errorf("insufficient signatures: need %d, got %d",
			guardians.Required, len(req.Signatures))
	}
	if len(req.Signatures) != len(req.Signers) {
		return fmt.Errorf("signatures and signers count mismatch")
	}

	if !core.IsValidAddr(req.ToNative) {
		return fmt.Errorf("invalid native address")
	}

	// Build the message that guardians signed (deterministic: sorted keys via struct)
	msgStruct := struct {
		LockID   string `json:"lock_id"`
		ToNative string `json:"to_native"`
	}{
		LockID:   req.LockID,
		ToNative: req.ToNative,
	}
	msg, _ := json.Marshal(msgStruct)

	// Track which guardians have signed (no duplicates)
	guardianSet := map[string]bool{}
	for _, g := range guardians.Guardians {
		guardianSet[g] = true
	}

	validSigs := 0
	usedSigners := map[string]bool{}

	for i, sigHex := range req.Signatures {
		signerPub := req.Signers[i]

		// Must be a registered guardian
		if !guardianSet[signerPub] {
			slog.Warn("bridge multisig: signer not a guardian", "pubkey", signerPub[:16])
			continue
		}

		// No duplicate signers
		if usedSigners[signerPub] {
			continue
		}

		// Verify signature
		pub, err := hex.DecodeString(signerPub)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			continue
		}
		sig, err := hex.DecodeString(sigHex)
		if err != nil || len(sig) != ed25519.SignatureSize {
			continue
		}

		if ed25519.Verify(pub, msg, sig) {
			validSigs++
			usedSigners[signerPub] = true
		}
	}

	if validSigs < guardians.Required {
		return fmt.Errorf("not enough valid signatures: need %d, got %d",
			guardians.Required, validSigs)
	}

	slog.Info("bridge multisig unlock validated",
		"lock_id", req.LockID[:16],
		"valid_sigs", validSigs,
		"required", guardians.Required)

	return nil
}
