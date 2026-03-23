package crypto

import (
	"testing"
)

func TestEncryptDecryptPrivKey(t *testing.T) {
	plaintext := []byte("this-is-a-secret-private-key-hex-string-64chars-long-000000000000")
	pass := "MyStr0ngP@ssphrase!"

	encrypted, err := EncryptPrivKey(plaintext, pass)
	if err != nil {
		t.Fatalf("EncryptPrivKey failed: %v", err)
	}
	if encrypted == "" {
		t.Fatal("encrypted string should not be empty")
	}

	decrypted, err := DecryptPrivKey(encrypted, pass)
	if err != nil {
		t.Fatalf("DecryptPrivKey failed: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("decrypted does not match original: got %q", decrypted)
	}
}

func TestDecrypt_WrongPassphrase(t *testing.T) {
	plaintext := []byte("secret-data")
	encrypted, _ := EncryptPrivKey(plaintext, "correct-pass")

	_, err := DecryptPrivKey(encrypted, "wrong-pass")
	if err == nil {
		t.Error("should fail with wrong passphrase")
	}
}

func TestEncrypt_EmptyPassphrase(t *testing.T) {
	_, err := EncryptPrivKey([]byte("data"), "")
	if err == nil {
		t.Error("should reject empty passphrase")
	}
}

func TestEncryptDecrypt_DifferentEachTime(t *testing.T) {
	plaintext := []byte("same-data")
	pass := "same-pass"

	e1, _ := EncryptPrivKey(plaintext, pass)
	e2, _ := EncryptPrivKey(plaintext, pass)

	if e1 == e2 {
		t.Error("encryptions should produce different ciphertext (random salt/nonce)")
	}

	// Both should decrypt correctly
	d1, _ := DecryptPrivKey(e1, pass)
	d2, _ := DecryptPrivKey(e2, pass)
	if string(d1) != string(d2) {
		t.Error("both should decrypt to same plaintext")
	}
}
