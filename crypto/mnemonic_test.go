package crypto

import (
	"strings"
	"testing"
)

func TestGenerateMnemonic(t *testing.T) {
	m, err := GenerateMnemonic()
	if err != nil {
		t.Fatal(err)
	}
	words := strings.Fields(m)
	if len(words) != 24 {
		t.Errorf("expected 24 words, got %d", len(words))
	}

	// Each word should be in word list
	for _, w := range words {
		if _, ok := wordIndex[w]; !ok {
			t.Errorf("word %q not in word list", w)
		}
	}

	// Two mnemonics should be different
	m2, _ := GenerateMnemonic()
	if m == m2 {
		t.Error("two generated mnemonics should not be identical")
	}
}

func TestMnemonicToKeypair_Deterministic(t *testing.T) {
	m, _ := GenerateMnemonic()

	pub1, priv1, err := MnemonicToKeypair(m)
	if err != nil {
		t.Fatal(err)
	}
	pub2, priv2, err := MnemonicToKeypair(m)
	if err != nil {
		t.Fatal(err)
	}

	if string(pub1) != string(pub2) {
		t.Error("same mnemonic should produce same public key")
	}
	if string(priv1) != string(priv2) {
		t.Error("same mnemonic should produce same private key")
	}
}

func TestMnemonicToAddr(t *testing.T) {
	m, _ := GenerateMnemonic()

	addr, pubHex, privHex, err := MnemonicToAddr(m)
	if err != nil {
		t.Fatal(err)
	}
	if len(addr) != 40 {
		t.Errorf("expected 40 char addr, got %d", len(addr))
	}
	if pubHex == "" || privHex == "" {
		t.Error("pubHex and privHex should not be empty")
	}

	// Should be consistent
	addr2, _, _, _ := MnemonicToAddr(m)
	if addr != addr2 {
		t.Error("same mnemonic should produce same address")
	}
}

func TestMnemonicToKeypair_BadInput(t *testing.T) {
	_, _, err := MnemonicToKeypair("only three words")
	if err == nil {
		t.Error("should reject short mnemonic")
	}

	_, _, err = MnemonicToKeypair("abandon " + strings.Repeat("xyznotaword ", 23))
	if err == nil {
		t.Error("should reject invalid words")
	}
}

func TestWordListSize(t *testing.T) {
	if len(wordList) != 2048 {
		t.Errorf("word list should have 2048 entries, got %d", len(wordList))
	}
	// Check uniqueness
	seen := map[string]bool{}
	for _, w := range wordList {
		if seen[w] {
			t.Errorf("duplicate word: %s", w)
		}
		seen[w] = true
	}
}
