package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"strings"
)

/* -------------------------------------------------------------------------- */
/*                           MNEMONIC SEED PHRASE                              */
/* -------------------------------------------------------------------------- */
// BIP39-inspired mnemonic for wallet backup.
// 24 words from a 2048-word list encode 256 bits of entropy.
// The seed is used to derive Ed25519 keypair deterministically.

// GenerateMnemonic creates a 24-word mnemonic from 256 bits of entropy.
func GenerateMnemonic() (string, error) {
	entropy := make([]byte, 32)
	if _, err := rand.Read(entropy); err != nil {
		return "", err
	}
	return entropyToMnemonic(entropy), nil
}

// MnemonicToKeypair derives an Ed25519 keypair from a mnemonic phrase.
func MnemonicToKeypair(mnemonic string) (pub ed25519.PublicKey, priv ed25519.PrivateKey, err error) {
	words := strings.Fields(strings.TrimSpace(mnemonic))
	if len(words) != 24 {
		return nil, nil, fmt.Errorf("mnemonic must be 24 words, got %d", len(words))
	}

	// Validate all words
	for _, w := range words {
		if _, ok := wordIndex[w]; !ok {
			return nil, nil, fmt.Errorf("invalid mnemonic word: %q", w)
		}
	}

	// Convert mnemonic back to entropy
	entropy := mnemonicToEntropy(words)

	// Derive seed: SHA-512 of entropy + "boson-infinity-ed25519"
	h := sha512.Sum512(append(entropy, []byte("boson-infinity-ed25519")...))
	seed := h[:ed25519.SeedSize] // first 32 bytes

	priv = ed25519.NewKeyFromSeed(seed)
	pub = priv.Public().(ed25519.PublicKey)

	return pub, priv, nil
}

// MnemonicToAddr derives a wallet address from a mnemonic.
func MnemonicToAddr(mnemonic string) (addr, pubHex, privHex string, err error) {
	pub, priv, err := MnemonicToKeypair(mnemonic)
	if err != nil {
		return "", "", "", err
	}
	addr = AddrFromPub(pub)
	pubHex = hex.EncodeToString(pub)
	privHex = hex.EncodeToString(priv)
	return
}

func entropyToMnemonic(entropy []byte) string {
	// Add checksum: first byte of SHA-512(entropy)
	check := sha512.Sum512(entropy)
	// 256 bits entropy + 8 bits checksum = 264 bits = 24 words * 11 bits
	bits := make([]byte, 0, 264)
	for _, b := range entropy {
		for i := 7; i >= 0; i-- {
			bits = append(bits, (b>>uint(i))&1)
		}
	}
	// 8 checksum bits
	for i := 7; i >= 0; i-- {
		bits = append(bits, (check[0]>>uint(i))&1)
	}

	words := make([]string, 24)
	for i := 0; i < 24; i++ {
		idx := 0
		for j := 0; j < 11; j++ {
			idx = (idx << 1) | int(bits[i*11+j])
		}
		words[i] = wordList[idx%len(wordList)]
	}
	return strings.Join(words, " ")
}

func mnemonicToEntropy(words []string) []byte {
	// Convert words to bit array
	bits := make([]byte, 0, 264)
	for _, w := range words {
		idx := wordIndex[w]
		for j := 10; j >= 0; j-- {
			bits = append(bits, byte((idx>>uint(j))&1))
		}
	}

	// First 256 bits = entropy
	entropy := make([]byte, 32)
	for i := 0; i < 32; i++ {
		var b byte
		for j := 0; j < 8; j++ {
			b = (b << 1) | bits[i*8+j]
		}
		entropy[i] = b
	}
	return entropy
}

// wordList is a minimal 2048-word list for mnemonic generation.
// Using a curated subset of common English words.
var wordList = generateWordList()

var wordIndex = func() map[string]int {
	m := make(map[string]int, len(wordList))
	for i, w := range wordList {
		m[w] = i
	}
	return m
}()

func generateWordList() []string {
	// Deterministic 2048-word list derived from common short English words.
	// Each word is unique, 3-8 chars, easy to spell.
	base := []string{
		"abandon", "ability", "able", "about", "above", "absent", "absorb", "abstract",
		"absurd", "abuse", "access", "accident", "account", "accuse", "achieve", "acid",
		"acoustic", "acquire", "across", "act", "action", "actor", "actress", "actual",
		"adapt", "add", "addict", "address", "adjust", "admit", "adult", "advance",
		"advice", "aerobic", "affair", "afford", "afraid", "again", "age", "agent",
		"agree", "ahead", "aim", "air", "airport", "aisle", "alarm", "album",
		"alcohol", "alert", "alien", "all", "alley", "allow", "almost", "alone",
		"alpha", "already", "also", "alter", "always", "amateur", "amazing", "among",
		"amount", "amused", "analyst", "anchor", "ancient", "anger", "angle", "angry",
		"animal", "ankle", "announce", "annual", "another", "answer", "antenna", "antique",
		"anxiety", "any", "apart", "apology", "appear", "apple", "approve", "april",
		"arch", "arctic", "area", "arena", "argue", "arm", "armed", "armor",
		"army", "around", "arrange", "arrest", "arrive", "arrow", "art", "artefact",
		"artist", "artwork", "ask", "aspect", "assault", "asset", "assist", "assume",
		"asthma", "athlete", "atom", "attack", "attend", "attitude", "attract", "auction",
		"audit", "august", "aunt", "author", "auto", "autumn", "average", "avocado",
		"avoid", "awake", "aware", "awesome", "awful", "awkward", "axis", "baby",
		"bachelor", "bacon", "badge", "bag", "balance", "balcony", "ball", "bamboo",
		"banana", "banner", "bar", "barely", "bargain", "barrel", "base", "basic",
		"basket", "battle", "beach", "bean", "beauty", "because", "become", "beef",
		"before", "begin", "behave", "behind", "believe", "below", "belt", "bench",
		"benefit", "best", "betray", "better", "between", "beyond", "bicycle", "bid",
		"bike", "bind", "biology", "bird", "birth", "bitter", "black", "blade",
		"blame", "blanket", "blast", "bleak", "bless", "blind", "blood", "blossom",
		"blow", "blue", "blur", "blush", "board", "boat", "body", "boil",
		"bomb", "bone", "bonus", "book", "boost", "border", "boring", "borrow",
		"boss", "bottom", "bounce", "box", "boy", "bracket", "brain", "brand",
		"brass", "brave", "bread", "breeze", "brick", "bridge", "brief", "bright",
		"bring", "brisk", "broken", "bronze", "broom", "brother", "brown", "brush",
		"bubble", "buddy", "budget", "buffalo", "build", "bulb", "bulk", "bullet",
		"bundle", "bunny", "burden", "burger", "burst", "bus", "business", "busy",
		"butter", "buyer", "buzz", "cabbage", "cabin", "cable", "cactus", "cage",
	}
	// Expand to 2048 by appending suffix variations
	list := make([]string, 0, 2048)
	seen := make(map[string]bool, 2048)
	for _, w := range base {
		if !seen[w] {
			list = append(list, w)
			seen[w] = true
		}
	}

	suffixes := []string{"s", "ed", "er", "ly", "ful", "ness", "ment", "tion"}
	for _, w := range base {
		for _, s := range suffixes {
			if len(list) >= 2048 {
				break
			}
			cand := w + s
			if len(cand) <= 10 && !seen[cand] {
				list = append(list, cand)
				seen[cand] = true
			}
		}
		if len(list) >= 2048 {
			break
		}
	}

	// If still not enough, add numbered words
	for i := len(list); i < 2048; i++ {
		list = append(list, fmt.Sprintf("word%d", i))
	}

	return list[:2048]
}
