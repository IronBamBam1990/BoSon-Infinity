package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/ed25519" // <-- DODAJ TO
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

/* -------------------------------------------------------------------------- */
/*                               CONSENSUS PARAMS                              */
/* -------------------------------------------------------------------------- */

const (
	NetworkName          = "boson-infinity-l0"
	DefaultRPCPort       = 8080
	DefaultP2PPort       = 8081
	DifficultyBitsInit   = 16
	TargetBlockSeconds   = 400.0
	RetargetWindow       = 30
	MaxDifficultyStep    = 2
	Decimals             = 8
	RewardInitialCoins   = 50.0
	HalvingInterval      = 210000
	MaxSupplyCoins       = 50_000_000.0
	MaxBlockTXs          = 2000
	MaxJSONKB            = 256
	TimestampFutureSkewS = 600
	ReadsPerTry          = 2048
     // 0.1% = 1 promil
    FeePermille = 1
    TreasuryAddr = "db92fe3a2720cc19256d9a1bab691346ef823e3a" // <- TU MA BYĆ ADRES FIRMY (40 hex)

	// **IMPORTANT**: podmień na losowy 32-znakowy string przed produkcją
	APIKey = "ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669"
    GenesisMessage = "Boson Infinity created by Kamil Padula in 2025 — the original Layer-0 energy-defined PoW blockchain."

	BridgeOperatorAddr = "db92fe3a2720cc19256d9a1bab691346ef823e3a" // 40 hex
	BridgeVaultAddr    = "0000000000000000000000000000000000000001"
)

/* -------------------------------------------------------------------------- */
/*                                  GLOBALS                                    */
/* -------------------------------------------------------------------------- */
const P2PAuthHeader = "X-P2P-Token"

var P2PToken string

var (
	UNIT             uint64
	REWARD0_UNITS    uint64
	MAX_SUPPLY_UNITS uint64

	mu      sync.Mutex
	chain   *Chain
	mempool []Tx
)

/* -------------------------------------------------------------------------- */
/*                                   TYPES                                     */
/* -------------------------------------------------------------------------- */

type BlockHeader struct {
	Version    int       `json:"version"`
	PrevHash   string    `json:"prev_hash"`
	Merkle     string    `json:"merkle_root"`
	Timestamp  time.Time `json:"timestamp"`
	Nonce      uint64    `json:"nonce"`
	Height     int       `json:"height"`
	Difficulty int       `json:"difficulty"` // trailing zero bits
	Miner      string    `json:"miner"`
}

type Block struct {
	Header BlockHeader `json:"header"`
	Txs    []Tx        `json:"txs"`
	Mix    string      `json:"mix"`
	Hash   string      `json:"hash"`
}

type Tx struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Amount uint64 `json:"amount"`
	Fee    uint64 `json:"fee"`
	Nonce  uint64 `json:"nonce"`
	PubKey string `json:"pubkey"`
	Sig    string `json:"signature"`
	Hash   string `json:"hash"`

	Type string `json:"type,omitempty"` // transfer, stake, unstake, bridge_lock, bridge_unlock
	Data string `json:"data,omitempty"` // json payload np. { "to_erc20": "..."}
}

type txPayload struct {
    ChainID string `json:"chain_id"`
    From    string `json:"from"`
    To      string `json:"to"`
    Amount  uint64 `json:"amount"`
    Fee     uint64 `json:"fee"`
    Nonce   uint64 `json:"nonce"`
    PubKey  string `json:"pubkey"`
    Type    string `json:"type,omitempty"`
    Data    string `json:"data,omitempty"`
}
func BuildTx(privHex, pubHex, from, to string, amount, fee, nonce uint64, txType, data string) (Tx, error) {
    priv, err := hex.DecodeString(privHex)
    if err != nil || len(priv) != ed25519.PrivateKeySize {
        return Tx{}, fmt.Errorf("bad private key")
    }
    if _, err := hex.DecodeString(pubHex); err != nil {
        return Tx{}, fmt.Errorf("bad pubkey")
    }

    payload := txPayload{
        ChainID: NetworkName,
        From:    from,
        To:      to,
        Amount:  amount,
        Fee:     fee,
        Nonce:   nonce,
        PubKey:  pubHex,
        Type:    txType,
        Data:    data,
    }

    raw, _ := json.Marshal(payload)

    sig := ed25519.Sign(priv, raw)
    sigHex := hex.EncodeToString(sig)
    h := HashBytes(raw)

    return Tx{
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

type Account struct {
	Balance uint64 `json:"balance"`
	Nonce   uint64 `json:"nonce"`
}

type Staker struct {
	Owner       string `json:"owner"`
	Amount      uint64 `json:"amount"`
	SinceHeight int    `json:"since_height"`
	Active      bool   `json:"active"`
}

type StakingState struct {
	MinStake    uint64            `json:"min_stake"`
	TotalStaked uint64            `json:"total_staked"`
	Validators  map[string]Staker `json:"validators"`
}

type ConsensusParams struct {
	NetworkName       string  `json:"network_name"`
	Decimals          int     `json:"decimals"`
	RewardInitial     float64 `json:"reward_initial"`
	HalvingInterval   int     `json:"halving_interval"`
	MaxSupply         float64 `json:"max_supply"`
	TargetBlockSec    float64 `json:"target_block_sec"`
	RetargetWindow    int     `json:"retarget_window"`
	MaxDifficultyStep int     `json:"max_difficulty_step"`
}

/* ----------------------------- Bridge structs ------------------------------ */

type BridgeLock struct {
	ID        string `json:"id"`
	From      string `json:"from"`
	ToERC20   string `json:"to_erc20"`
	Amount    uint64 `json:"amount"`
	Height    int    `json:"height"`
	CreatedAt int64  `json:"created_at"`
}

type BridgeUnlock struct {
	ID        string `json:"id"`
	LockID    string `json:"lock_id"`
	ToNative  string `json:"to_native"`
	Amount    uint64 `json:"amount"`
	Height    int    `json:"height"`
	CreatedAt int64  `json:"created_at"`
}

type BridgeState struct {
	Locks    map[string]BridgeLock   `json:"locks"`
	Unlocks  map[string]BridgeUnlock `json:"unlocks"`
	Consumed map[string]bool         `json:"consumed"`
}

type Contract struct{}

/* ------------------------------ Main Chain obj ----------------------------- */

type Chain struct {
    Blocks      []Block            `json:"blocks"`
    Peers       []string           `json:"peers"`
    State       map[string]Account `json:"state"`
    TotalMinted uint64             `json:"total_minted"`
    ParamsHash  string             `json:"params_hash"`

    Staking   StakingState        `json:"staking"`
    Contracts map[string]Contract `json:"contracts"`
    Params    ConsensusParams     `json:"params"`
    Bridge    BridgeState         `json:"bridge"`

    // Meta-info o sieci (Bitcoin-style genesis message)
    GenesisMessage    string `json:"genesis_message"`
    GenesisMessageHex string `json:"genesis_message_hex"`
}

// EnergyModel – globalne statystyki energii z aggregator.go (energy.model.json)
// EnergyModel – globalne statystyki energii z aggregator.go (energy.model.json)
type EnergyModel struct {
	AvgJoulesPerHash float64 `json:"avg_j_per_hash"`
	AvgPricePerKWh   float64 `json:"avg_price_per_kwh"`
	FiatCurrency     string  `json:"fiat_currency"`
	UpdatedAt        int64   `json:"updated_at"`
}

// loadEnergyModel ładuje energy.model.json wygenerowany przez oracle
func loadEnergyModel(path string) (*EnergyModel, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var em EnergyModel
	if err := json.NewDecoder(f).Decode(&em); err != nil {
		return nil, err
	}

	now := time.Now().Unix()

	// świeżość modelu max 24h
	if em.UpdatedAt == 0 || now-em.UpdatedAt > 86400 {
		return nil, fmt.Errorf("energy_model_stale")
	}

	// sanity – zakresy produkcyjne, żeby nie rozwalić node'a fake danymi
	if em.AvgJoulesPerHash <= 0 || em.AvgJoulesPerHash > 10 {
		return nil, fmt.Errorf("invalid_j_per_hash")
	}
	if em.AvgPricePerKWh <= 0.001 || em.AvgPricePerKWh > 5 {
		return nil, fmt.Errorf("invalid_price_per_kwh")
	}

	if em.FiatCurrency == "" {
		em.FiatCurrency = "EUR"
	}

	return &em, nil
}
// calcFee – stałe fee 0.1% od kwoty (w atomach)
func calcFee(amount uint64) uint64 {
    // Fee = amount * FeePermille / 1000
    return (amount * uint64(FeePermille)) / 1000
}
func pow10u(n int) uint64 {
	var v uint64 = 1
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

func toUnits(coins float64) uint64 {
	return uint64(coins*float64(UNIT) + 1e-9)
}

func short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

func formatHashrate(v float64) string {
	switch {
	case v >= 1e18:
		return fmt.Sprintf("%.2f EH/s", v/1e18)
	case v >= 1e15:
		return fmt.Sprintf("%.2f PH/s", v/1e15)
	case v >= 1e12:
		return fmt.Sprintf("%.2f TH/s", v/1e12)
	case v >= 1e9:
		return fmt.Sprintf("%.2f GH/s", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.2f MH/s", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.2f kH/s", v/1e3)
	default:
		return fmt.Sprintf("%.2f H/s", v)
	}
}

/* -------------------------------------------------------------------------- */
/*                                 HASHING                                     */
/* -------------------------------------------------------------------------- */

func sha512Hex(b []byte) string {
	sum := sha512.Sum512(b)
	return hex.EncodeToString(sum[:])
}

func HashBytes(b []byte) string {
	return sha512Hex(b)
}

func addrFromPub(pub []byte) string {
	sum := sha512.Sum512(pub)
	return hex.EncodeToString(sum[:20])
}

func MerkleRoot(hashes []string) string {
	if len(hashes) == 0 {
		return sha512Hex(nil)
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

func BlockHash(b Block) string {
	data := struct {
		H BlockHeader `json:"h"`
		M string      `json:"m"`
	}{
		H: b.Header,
		M: b.Mix,
	}
	enc, _ := json.Marshal(data)
	return sha512Hex(enc)
}

/* -------------------------------------------------------------------------- */
/*                                  POW / MIX                                  */
/* -------------------------------------------------------------------------- */

func MixHash(headerHex string, nonce uint64) string {
	raw, err := hex.DecodeString(headerHex)
	if err != nil {
		return ""
	}

	rolling := make([]byte, 64)
	for j := 0; j < ReadsPerTry; j++ {
		k := int((nonce + uint64(j)) % 64)
		rolling[k] ^= byte((nonce >> (uint(j)&7)*8) & 0xff)
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

func checkMask(mixHex string, bits int) bool {
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

/* -------------------------------------------------------------------------- */
/*                                 RETARGET                                    */
/* -------------------------------------------------------------------------- */

func Retarget(c *Chain) int {
	n := len(c.Blocks)
	if n < 2 {
		return c.Blocks[0].Header.Difficulty
	}

	N := RetargetWindow
	if N < 10 {
		N = 10
	}
	if n-1 < N {
		N = n - 1
	}
	if N <= 1 {
		return c.Blocks[n-1].Header.Difficulty
	}

	T := TargetBlockSeconds
	if T <= 0 {
		T = 400
	}

	var sumWeighted float64
	var sumWeights float64

	prev := c.Blocks[n-N-1].Header.Timestamp

	for i := n - N; i < n; i++ {
		ts := c.Blocks[i].Header.Timestamp
		solve := ts.Sub(prev).Seconds()
		if solve < 1 {
			solve = 1
		}
		weight := float64(i-(n-N)) + 1
		sumWeights += weight
		sumWeighted += solve * weight
		prev = ts
	}

	lwma := sumWeighted / sumWeights
	ratio := T / lwma

	if ratio > 4 {
		ratio = 4
	}
	if ratio < 0.25 {
		ratio = 0.25
	}

	delta := int(math.Round(math.Log2(ratio)))
	if delta > MaxDifficultyStep {
		delta = MaxDifficultyStep
	}
	if delta < -MaxDifficultyStep {
		delta = -MaxDifficultyStep
	}

	oldBits := c.Blocks[n-1].Header.Difficulty
	newBits := oldBits + delta
	if newBits < 1 {
		newBits = 1
	}
	if newBits > 62 {
		newBits = 62
	}

	fmt.Printf("[DIFF] LWMA=%.2fs ratio=%.3f old=%d delta=%d new=%d\n",
		lwma, ratio, oldBits, delta, newBits)

	return newBits
}

/* -------------------------------------------------------------------------- */
/*                                 REWARDS                                     */
/* -------------------------------------------------------------------------- */

func baseRewardAt(height int) uint64 {
	if height <= 0 {
		return 0
	}
	halvings := height / HalvingInterval
	if halvings > 63 {
		return 0
	}
	return REWARD0_UNITS >> uint(halvings)
}

/* -------------------------------------------------------------------------- */
/*                         TX VALIDATION & STATE                               */
/* -------------------------------------------------------------------------- */

// fake "signature": sha512(payload+pubkeyHex) == sigHex
// verifyTxSignature: prawdziwy Ed25519 z chain_id
func verifyTxSignature(tx Tx) bool {
    pub, err := hex.DecodeString(tx.PubKey)
    if err != nil || len(pub) != ed25519.PublicKeySize {
        return false
    }

    payload := txPayload{
        ChainID: NetworkName,
        From:    tx.From,
        To:      tx.To,
        Amount:  tx.Amount,
        Fee:     tx.Fee,
        Nonce:   tx.Nonce,
        PubKey:  tx.PubKey,
        Type:    tx.Type,
        Data:    tx.Data,
    }

    raw, _ := json.Marshal(payload)

    sig, err := hex.DecodeString(tx.Sig)
    if err != nil || len(sig) != ed25519.SignatureSize {
        return false
    }

    return ed25519.Verify(ed25519.PublicKey(pub), raw, sig)
}

func ValidateTx(state map[string]Account, tx Tx) bool {
    pub, err := hex.DecodeString(tx.PubKey)
    if err != nil || len(pub) == 0 {
        return false
    }
    want := addrFromPub(pub)
    if want != tx.From {
        return false
    }

    if !verifyTxSignature(tx) {
        return false
    }

    // Wymuszamy stałe fee = 0.1% kwoty
    expectedFee := calcFee(tx.Amount)
    if tx.Fee != expectedFee {
        fmt.Println("[VAL] bad fee, expected", expectedFee, "got", tx.Fee)
        return false
    }

    ac := state[tx.From]

    // nonce musi być sekwencyjnie
    if tx.Nonce != ac.Nonce+1 {
        return false
    }

    // Bezpieczne sprawdzenie overspendu (bez overflow)
    if tx.Amount > ac.Balance {
        return false
    }
    if tx.Fee > ac.Balance-tx.Amount {
        return false
    }

    return true
}

/* ------------------------------ Bridge logic -------------------------------- */
func mempoolCountByAddr(addr string) int {
    cnt := 0
    for _, t := range mempool {
        if t.From == addr {
            cnt++
        }
    }
    return cnt
}
func execBridgeLock(ch *Chain, state map[string]Account, tx Tx, height int) {
	var data struct {
		ToERC20 string `json:"to_erc20"`
	}
	_ = json.Unmarshal([]byte(tx.Data), &data)

	from := state[tx.From]
	from.Balance -= tx.Amount + tx.Fee
	from.Nonce++
	state[tx.From] = from

	vault := state[BridgeVaultAddr]
	vault.Balance += tx.Amount
	state[BridgeVaultAddr] = vault

	lock := BridgeLock{
		ID:        tx.Hash,
		From:      tx.From,
		ToERC20:   data.ToERC20,
		Amount:    tx.Amount,
		Height:    height,
		CreatedAt: time.Now().Unix(),
	}
	ch.Bridge.Locks[lock.ID] = lock

	fmt.Printf("[BRIDGE] lock %s from=%s → ERC20 %s amount=%d\n",
		lock.ID[:8], short(lock.From), data.ToERC20, lock.Amount)
}

func execBridgeUnlock(ch *Chain, state map[string]Account, tx Tx, height int) {
	if tx.From != BridgeOperatorAddr {
		return
	}
	var data struct {
		LockID   string `json:"lock_id"`
		ToNative string `json:"to_native"`
	}
	_ = json.Unmarshal([]byte(tx.Data), &data)

	if ch.Bridge.Consumed[data.LockID] {
		return
	}
	lock, ok := ch.Bridge.Locks[data.LockID]
	if !ok {
		return
	}

	vault := state[BridgeVaultAddr]
	if vault.Balance < lock.Amount {
		return
	}
	vault.Balance -= lock.Amount
	state[BridgeVaultAddr] = vault

	recv := state[data.ToNative]
	recv.Balance += lock.Amount
	state[data.ToNative] = recv

	ch.Bridge.Consumed[data.LockID] = true
	unlock := BridgeUnlock{
		ID:        tx.Hash,
		LockID:    data.LockID,
		ToNative:  data.ToNative,
		Amount:    lock.Amount,
		Height:    height,
		CreatedAt: time.Now().Unix(),
	}
	ch.Bridge.Unlocks[unlock.ID] = unlock

	fmt.Printf("[BRIDGE] unlock %s lock=%s → %s amount=%d\n",
		unlock.ID[:8], lock.ID[:8], short(unlock.ToNative), unlock.Amount)
}

func applyTx(state map[string]Account, tx Tx, ch *Chain, height int) {
	switch tx.Type {
	case "", "transfer":
		from := state[tx.From]
		to := state[tx.To]
		from.Balance -= tx.Amount + tx.Fee
		from.Nonce++
		to.Balance += tx.Amount
		state[tx.From] = from
		state[tx.To] = to

	case "stake":
		from := state[tx.From]
		from.Balance -= tx.Amount + tx.Fee
		from.Nonce++
		state[tx.From] = from

		st := ch.Staking.Validators[tx.From]
		st.Owner = tx.From
		st.Amount += tx.Amount
		st.SinceHeight = height
		st.Active = true
		ch.Staking.Validators[tx.From] = st
		ch.Staking.TotalStaked += tx.Amount

	case "unstake":
		from := state[tx.From]
		from.Nonce++
		st := ch.Staking.Validators[tx.From]
		if st.Active && st.Amount > 0 {
			from.Balance += st.Amount
			ch.Staking.TotalStaked -= st.Amount
			st.Amount = 0
			st.Active = false
			ch.Staking.Validators[tx.From] = st
		}
		state[tx.From] = from

	case "bridge_lock":
		execBridgeLock(ch, state, tx, height)

	case "bridge_unlock":
		execBridgeUnlock(ch, state, tx, height)
	}
}

func applyBlock(c *Chain, b Block) {
    // 1) Zastosuj wszystkie TX do stanu
    for _, tx := range b.Txs {
        applyTx(c.State, tx, c, b.Header.Height)
    }

    // 2) Policz fee
    var totalFees uint64
    for _, tx := range b.Txs {
        totalFees += tx.Fee
    }

    // 3) Subsidy (halving)
    br := baseRewardAt(b.Header.Height)

    // cap supply
    var remaining uint64
    if c.TotalMinted < MAX_SUPPLY_UNITS {
        remaining = MAX_SUPPLY_UNITS - c.TotalMinted
    }
    if br > remaining {
        br = remaining
    }

    // 4) total reward = subsidy + fees
    totalReward := br + totalFees

    minerShare, treasuryShare := splitReward80_20(totalReward)

    miner := b.Header.Miner

    // Miner 80%
    ma := c.State[miner]
    ma.Balance += minerShare
    c.State[miner] = ma

    // Treasury 20% ✅
    ta := c.State[TreasuryAddr]
    ta.Balance += treasuryShare
    c.State[TreasuryAddr] = ta

    // 5) Minted tylko o subsidy
    c.TotalMinted += br

    fmt.Printf("[REWARD] miner=%s +%d (fees=%d) treasury=%s +%d minted=%d/%d\n",
        short(miner), minerShare, totalFees, short(TreasuryAddr),
        treasuryShare, c.TotalMinted, MAX_SUPPLY_UNITS)
}



/* -------------------------------------------------------------------------- */
/*                              BLOCK VALIDATION                               */
/* -------------------------------------------------------------------------- */

func validTimestamp(prev, now time.Time) bool {
	if now.Before(prev) {
		return false
	}
	if now.After(time.Now().Add(time.Duration(TimestampFutureSkewS) * time.Second)) {
		return false
	}
	return true
}

func ValidateBlock(c *Chain, b Block) bool {
    if b.Header.Height == 0 && b.Hash == "GENESIS" {
        return true
    }

    last := c.Blocks[len(c.Blocks)-1]

    if b.Header.PrevHash != last.Hash {
        fmt.Println("[VAL] bad prev hash")
        return false
    }
    if b.Header.Height != last.Header.Height+1 {
        fmt.Println("[VAL] bad height")
        return false
    }
    if !validTimestamp(last.Header.Timestamp, b.Header.Timestamp) {
        fmt.Println("[VAL] bad timestamp")
        return false
    }

    var th []string
    for _, t := range b.Txs {
        th = append(th, t.Hash)
    }
    if MerkleRoot(th) != b.Header.Merkle {
        fmt.Println("[VAL] merkle mismatch")
        return false
    }
    if BlockHash(b) != b.Hash {
        fmt.Println("[VAL] bad block hash")
        return false
    }
    if !checkMask(b.Mix, b.Header.Difficulty) {
        fmt.Println("[VAL] bad mask")
        return false
    }
    expectedDiff := Retarget(c)
    if b.Header.Difficulty != expectedDiff {
        fmt.Println("[VAL] wrong difficulty, expected", expectedDiff)
        return false
    }
    if len(b.Txs) > MaxBlockTXs {
        fmt.Println("[VAL] too many txs")
        return false
    }

    tmpState := copyState(c.State)
    tmpChain := *c
    tmpChain.State = tmpState
    tmpChain.Staking = copyStaking(c.Staking)

    var totalFees uint64
    for _, tx := range b.Txs {
        if !ValidateTx(tmpChain.State, tx) {
            fmt.Println("[VAL] invalid tx", tx.Hash)
            return false
        }
        applyTx(tmpChain.State, tx, &tmpChain, b.Header.Height)
        totalFees += tx.Fee
    }

    br := baseRewardAt(b.Header.Height)
    var remaining uint64
    if c.TotalMinted < MAX_SUPPLY_UNITS {
        remaining = MAX_SUPPLY_UNITS - c.TotalMinted
    }
    if br > remaining {
        br = remaining
    }

    totalReward := br + totalFees
    expMinerShare, expTreasuryShare := splitReward80_20(totalReward)

    minerAddr := b.Header.Miner

    // ✅ Weryfikacja przyrostu MINERA (80%)
    prevMiner := c.State[minerAddr].Balance
    newMiner := tmpState[minerAddr].Balance
    if newMiner < prevMiner || newMiner-prevMiner != expMinerShare {
        fmt.Println("[VAL] miner reward mismatch", "want", expMinerShare, "got", newMiner-prevMiner)
        return false
    }

    // ✅ Weryfikacja przyrostu TREASURY (20%)
    prevTreas := c.State[TreasuryAddr].Balance
    newTreas := tmpState[TreasuryAddr].Balance
    if newTreas < prevTreas || newTreas-prevTreas != expTreasuryShare {
        fmt.Println("[VAL] treasury reward mismatch", "want", expTreasuryShare, "got", newTreas-prevTreas)
        return false
    }

    return true
}

func copyState(in map[string]Account) map[string]Account {
	out := make(map[string]Account, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func copyStaking(in StakingState) StakingState {
	out := StakingState{
		MinStake:    in.MinStake,
		TotalStaked: in.TotalStaked,
		Validators:  make(map[string]Staker, len(in.Validators)),
	}
	for k, v := range in.Validators {
		out.Validators[k] = v
	}
	return out
}

/* -------------------------------------------------------------------------- */
/*                               CHAIN STORAGE                                 */
/* -------------------------------------------------------------------------- */

const chainFile = "chain.mainnet.json"

func currentParamsHash() string {
	blob := fmt.Sprintf("%s|%d|%f|%d|%f|%d",
		NetworkName,
		Decimals,
		RewardInitialCoins,
		HalvingInterval,
		MaxSupplyCoins,
		RetargetWindow)
	sum := sha256.Sum256([]byte(blob))
	return hex.EncodeToString(sum[:])
}

func SaveChain(c *Chain) {
	tmp := chainFile + ".tmp"
	f, err := os.Create(tmp)
	if err != nil {
		fmt.Println("[ERR] save chain:", err)
		return
	}
	defer f.Close()

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	if err := enc.Encode(c); err != nil {
		fmt.Println("[ERR] encode chain:", err)
		return
	}
	if err := os.Rename(tmp, chainFile); err != nil {
		fmt.Println("[ERR] rename chain:", err)
		return
	}
	fmt.Printf("[SAVE] chain saved (%d blocks, %d accounts)\n",
		len(c.Blocks), len(c.State))
}

func LoadChain() *Chain {
	f, err := os.Open(chainFile)
	if err != nil {
		fmt.Println("[LOAD] no chain (new)")
		return nil
	}
	defer f.Close()

	var c Chain
	if err := json.NewDecoder(f).Decode(&c); err != nil {
		fmt.Println("[ERR] load chain:", err)
		return nil
	}

	if c.State == nil {
		c.State = map[string]Account{}
	}
	if c.Staking.Validators == nil {
		c.Staking.Validators = map[string]Staker{}
	}
	if c.Bridge.Locks == nil {
		c.Bridge.Locks = map[string]BridgeLock{}
	}
	if c.Bridge.Unlocks == nil {
		c.Bridge.Unlocks = map[string]BridgeUnlock{}
	}
	if c.Bridge.Consumed == nil {
		c.Bridge.Consumed = map[string]bool{}
	}
	if c.Blocks == nil {
		c.Blocks = []Block{}
	}
    if c.Contracts == nil {
        c.Contracts = map[string]Contract{}
    }
    
    // Uzupełnij genesis message, jeśli pole było puste w starej wersji
    if c.GenesisMessage == "" {
        c.GenesisMessage = GenesisMessage
    }
    if c.GenesisMessageHex == "" && c.GenesisMessage != "" {
        c.GenesisMessageHex = hex.EncodeToString([]byte(c.GenesisMessage))
    }
    
    fmt.Printf("[LOAD] chain loaded: %d blocks, %d accounts\n",
        len(c.Blocks), len(c.State))
    return &c

}

/* -------------------------------------------------------------------------- */
/*                                 MEMPOOL                                     */
/* -------------------------------------------------------------------------- */
func pendingTxsForAddr(addr string) []Tx {
    var out []Tx
    for _, tx := range mempool {
        if tx.From == addr || tx.To == addr {
            out = append(out, tx)
        }
    }
    return out
}
func pendingHandler(w http.ResponseWriter, r *http.Request) {
    addr := r.URL.Query().Get("addr")
    if addr == "" {
        http.Error(w, "missing addr", http.StatusBadRequest)
        return
    }

    mu.Lock()
    defer mu.Unlock()

    txs := pendingTxsForAddr(addr)
    writeJSON(w, txs)
}

func addToMempool(tx Tx) {
	mempool = append(mempool, tx)
}

func purgeFromMempool(txs []Tx) {
	if len(mempool) == 0 {
		return
	}
	inBlock := map[string]bool{}
	for _, t := range txs {
		inBlock[t.Hash] = true
	}
	newPool := make([]Tx, 0, len(mempool))
	for _, t := range mempool {
		if !inBlock[t.Hash] {
			newPool = append(newPool, t)
		}
	}
	mempool = newPool
}

/* -------------------------------------------------------------------------- */
/*                                MINING API                                   */
/* -------------------------------------------------------------------------- */

type Work struct {
	HeaderHex   string  `json:"header_hex"`
	Difficulty  uint32  `json:"difficulty"`
	Reads       uint32  `json:"reads"`
	MerkleRoot  string  `json:"merkle_root"`
	MinerReward float64 `json:"miner_reward"`
	StakeReward float64 `json:"stake_reward"`
	TotalReward float64 `json:"total_reward"`
	Fees        float64 `json:"fees"`
	JobID       string  `json:"job_id"`
	ExpiresAt   int64   `json:"expires_at"`
	TargetProb  string  `json:"target_prob"`
}



type jobInfo struct {
	H   string // headerHex
	M   string // merkle
	P   string // prev hash
	E   int64  // expiry
	TX  []Tx
	D   int
}

type syncMap struct {
	mu sync.Mutex
	m  map[string]jobInfo
}

func (s *syncMap) Store(k string, v jobInfo) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = v
}

func (s *syncMap) Load(k string) (jobInfo, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.m[k]
	return v, ok
}

var jobs = syncMap{m: map[string]jobInfo{}}

func hmacJob(hx, merkle, prev string, exp int64) string {
	h := hmac.New(sha256.New, []byte(APIKey))
	h.Write([]byte(hx))
	h.Write([]byte("|"))
	h.Write([]byte(merkle))
	h.Write([]byte("|"))
	h.Write([]byte(prev))
	h.Write([]byte("|"))
	h.Write([]byte(fmt.Sprint(exp)))
	return hex.EncodeToString(h.Sum(nil))
}

func pickTxsForBlock() []Tx {
	pool := append([]Tx(nil), mempool...)
	rand.Shuffle(len(pool), func(i, j int) { pool[i], pool[j] = pool[j], pool[i] })
	if len(pool) > MaxBlockTXs {
		pool = pool[:MaxBlockTXs]
	}
	return pool
}

func buildWork() Work {
    last := chain.Blocks[len(chain.Blocks)-1]
    nextHeight := last.Header.Height + 1

    // Retarget zwraca int
    nextDiff := Retarget(chain)

    txs := pickTxsForBlock()

    // Zbierz hashe TX + policz sumę fee (uint64)
    var th []string
    var feeSum uint64
    for _, t := range txs {
        th = append(th, t.Hash)
        feeSum += t.Fee
    }

    merkle := MerkleRoot(th)

    header := fmt.Sprintf("%s:%d:%s", last.Hash, nextHeight, merkle)
    headerHex := hex.EncodeToString([]byte(header))

    expires := time.Now().Add(60 * time.Second).Unix()
    jobID := hmacJob(headerHex, merkle, last.Hash, expires)

    // ZAPIS JOBA → D musi być int
    jobs.Store(jobID, jobInfo{
        H:  headerHex,
        M:  merkle,
        P:  last.Hash,
        E:  expires,
        TX: txs,
        D:  nextDiff, // <<=== POPRAWIONE, BEZ uint32()
    })

    // Subsidy (uint64)
    
    brUnits := baseRewardAt(nextHeight)

    // Całkowita nagroda
    totalRewardUnits := brUnits + feeSum
    
    // Podział nagrody 80/20
    nodeShareUnits := totalRewardUnits / 5
    minerShareUnits := totalRewardUnits - nodeShareUnits
    
    minerReward := float64(minerShareUnits) / float64(UNIT)
    stakeReward := float64(nodeShareUnits) / float64(UNIT) // tu nazwa pola zostaje, ale to "node reward"
    totalReward := float64(totalRewardUnits) / float64(UNIT)
    feesCoins := float64(feeSum) / float64(UNIT)


    return Work{
        HeaderHex:  headerHex,
        Difficulty: uint32(nextDiff), // UI MINERA → uint32 OK
        Reads:      ReadsPerTry,
        MerkleRoot: merkle,

        MinerReward: minerReward,
        StakeReward: stakeReward,
        TotalReward: totalReward,
        Fees:        feesCoins,

        JobID:      jobID,
        ExpiresAt:  expires,
        TargetProb: fmt.Sprintf("1 / 2^%d", nextDiff),
    }
}


func submitSolved(jobID, headerHex, mixHex, minerAddr string, nonce uint64) error {
	j, ok := jobs.Load(jobID)
	if !ok {
		return fmt.Errorf("invalid_job")
	}
	if time.Now().Unix() > j.E {
		return fmt.Errorf("job_expired")
	}
	if j.H != headerHex {
		return fmt.Errorf("header_mismatch")
	}
	wantMix := MixHash(headerHex, nonce)
	if mixHex != wantMix {
		return fmt.Errorf("invalid_mixhash")
	}
	if !checkMask(mixHex, j.D) {
		return fmt.Errorf("invalid_difficulty")
	}

	last := chain.Blocks[len(chain.Blocks)-1]
	if !validTimestamp(last.Header.Timestamp, time.Now().UTC()) {
		return fmt.Errorf("bad_timestamp")
	}

	var th []string
	for _, t := range j.TX {
		th = append(th, t.Hash)
	}
	merkle := MerkleRoot(th)
	if merkle != j.M {
		return fmt.Errorf("merkle_mismatch")
	}

	nb := Block{
		Header: BlockHeader{
			Version:    1,
			PrevHash:   last.Hash,
			Merkle:     merkle,
			Timestamp:  time.Now().UTC(),
			Nonce:      nonce,
			Height:     last.Header.Height + 1,
			Difficulty: j.D,
			Miner:      minerAddr,
		},
		Txs: j.TX,
		Mix: mixHex,
	}
	nb.Hash = BlockHash(nb)

	if !ValidateBlock(chain, nb) {
		return fmt.Errorf("invalid_block")
	}

	applyBlock(chain, nb)
	chain.Blocks = append(chain.Blocks, nb)
	purgeFromMempool(nb.Txs)
	SaveChain(chain)
	go broadcastBlock(nb)

	fmt.Printf("[BLOCK] #%d %s miner=%s tx=%d diff=%d\n",
		nb.Header.Height, nb.Hash[:16], short(nb.Header.Miner),
		len(nb.Txs), nb.Header.Difficulty)

	return nil
}

/* -------------------------------------------------------------------------- */
/*                                  RPC API                                    */
/* -------------------------------------------------------------------------- */

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func getWorkHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	work := buildWork()
	writeJSON(w, work)
}

func submitWorkHandler(w http.ResponseWriter, r *http.Request) {
	var sub struct {
		HeaderHex string `json:"header_hex"`
		Nonce     uint64 `json:"nonce"`
		MixHex    string `json:"mix_hex"`
		MinerAddr string `json:"miner_address"`
		JobID     string `json:"job_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&sub); err != nil {
		http.Error(w, "bad_json", 400)
		return
	}
	mu.Lock()
	defer mu.Unlock()

	if err := submitSolved(sub.JobID, sub.HeaderHex, sub.MixHex, sub.MinerAddr, sub.Nonce); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	w.Write([]byte(`{"ok":true}`))
}

func getAccountHandler(w http.ResponseWriter, r *http.Request) {
    addr := r.URL.Query().Get("addr")

    mu.Lock()
    acc := chain.State[addr]
    mu.Unlock()

    out := map[string]any{
        "address":        addr,
        "balance_atoms":  acc.Balance,
        "balance":        float64(acc.Balance) / float64(UNIT), // w BSI (coinach)
        "nonce":         acc.Nonce,
    }

    writeJSON(w, out)
}


func getChainHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, chain)
}

func poolListHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, mempool)
}

type Stats struct {
	Height           int     `json:"height"`
	Window           int     `json:"window"`
	DifficultyBits   int     `json:"difficulty_bits"`
	AvgBlockSeconds  float64 `json:"avg_block_seconds"`
	EstNetworkHps    float64 `json:"est_network_hps"`
	EstNetworkPretty string  `json:"est_network_pretty"`

	// ATOMS (surowe wartości z protokołu)
	TotalMintedAtoms uint64 `json:"total_minted_atoms"`
	MaxSupplyAtoms   uint64 `json:"max_supply_atoms"`

	// COINS (BSI) – już przeliczone po Decimals
	TotalMinted float64 `json:"total_minted"`
	MaxSupply   float64 `json:"max_supply"`

	// --------- ENERGY MODEL (GLOBALNE, Z AGGREGATORA) ----------

	EnergyJPerHash     float64 `json:"energy_j_per_hash"`     // J / hash
	EnergyPricePerKWh  float64 `json:"energy_price_per_kwh"`  // FIAT / kWh
	FiatCurrency       string  `json:"fiat_currency"`         // np. "USD"
	CostPerHash        float64 `json:"cost_per_hash"`         // FIAT / hash
	CostPerBlock       float64 `json:"cost_per_block"`        // FIAT / blok
	CostPerCoin        float64 `json:"cost_per_coin"`         // FIAT / 1 BSI
	EnergyModelUpdated int64   `json:"energy_model_updated"`  // timestamp modelu
}


func getStatsHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	n := len(chain.Blocks)
	if n < 1 {
		http.Error(w, "no_chain", 500)
		return
	}

	// okno do liczenia średniego czasu bloku
	wsize := RetargetWindow
	if wsize < 5 {
		wsize = 5
	}
	if n-1 < wsize {
		wsize = n - 1
	}

	// średni czas bloku na podstawie ostatnich bloków
	var totalDt float64
	for i := n - wsize; i < n; i++ {
		dt := chain.Blocks[i].Header.Timestamp.Sub(chain.Blocks[i-1].Header.Timestamp).Seconds()
		if dt < 0 {
			dt = 0
		}
		totalDt += dt
	}
	avg := totalDt / float64(wsize)

	// bieżąca trudność i estymacja hashrate'u
	bits := chain.Blocks[n-1].Header.Difficulty
	// H/s ~ 2^bits / avg_block_time
	hps := math.Exp2(float64(bits)) / math.Max(avg, 1.0)

	// policz średnie fee w atomach w ostatnim oknie
	var totalFeesUnits uint64
	for i := n - wsize; i < n; i++ {
		for _, tx := range chain.Blocks[i].Txs {
			totalFeesUnits += tx.Fee
		}
	}
	avgFeesUnits := float64(totalFeesUnits) / float64(wsize)

	// nagroda bloku (subsidy) dla następnego heightu
	nextHeight := chain.Blocks[n-1].Header.Height + 1
	rewardUnits := float64(baseRewardAt(nextHeight))

	// całkowita nagroda (subsidy + średnie fee)
	totalRewardUnits := rewardUnits + avgFeesUnits
	totalRewardCoins := totalRewardUnits / float64(UNIT) // w BSI

	// ------------ ENERGY MODEL Z energy.model.json ------------

	var (
		energyJPerHash float64
		energyPriceKWh float64
		fiatCurrency   string
		costPerHash    float64
		costPerBlock   float64
		costPerCoin    float64
		emUpdated      int64
	)

	if em, err := loadEnergyModel("energy.model.json"); err == nil {
		energyJPerHash = em.AvgJoulesPerHash
		energyPriceKWh = em.AvgPricePerKWh
		fiatCurrency = em.FiatCurrency
		emUpdated = em.UpdatedAt

		// koszt 1 hasha:
		// J/hash -> kWh/hash (dzielimy przez 3.6e6) * cena kWh
		costPerHash = (energyJPerHash / 3_600_000.0) * energyPriceKWh

		// oczekiwana liczba hashy na blok ~ 2^bits
		hashesPerBlock := math.Exp2(float64(bits))

		// koszt energii całego bloku
		costPerBlock = hashesPerBlock * costPerHash

		// koszt energii 1 coina
		if totalRewardCoins > 0 {
			costPerCoin = costPerBlock / totalRewardCoins
		}
	} else {
		// brak modelu – pola zostają 0, żeby UI wiedziało, że brak danych
	}

	out := Stats{
		Height:           chain.Blocks[n-1].Header.Height,
		Window:           wsize,
		DifficultyBits:   bits,
		AvgBlockSeconds:  avg,
		EstNetworkHps:    hps,
		EstNetworkPretty: formatHashrate(hps),

		// surowe ATOMS
		TotalMintedAtoms: chain.TotalMinted,
		MaxSupplyAtoms:   MAX_SUPPLY_UNITS,

		// przeliczone na BSI (coiny)
		TotalMinted: float64(chain.TotalMinted) / float64(UNIT),
		MaxSupply:   float64(MAX_SUPPLY_UNITS) / float64(UNIT),

		// ENERGY MODEL
		EnergyJPerHash:     energyJPerHash,
		EnergyPricePerKWh:  energyPriceKWh,
		FiatCurrency:       fiatCurrency,
		CostPerHash:        costPerHash,
		CostPerBlock:       costPerBlock,
		CostPerCoin:        costPerCoin,
		EnergyModelUpdated: emUpdated,
	}

	writeJSON(w, out)
}


func submitTxHandler(w http.ResponseWriter, r *http.Request) {
    var tx Tx
    if err := json.NewDecoder(r.Body).Decode(&tx); err != nil {
        http.Error(w, "bad_json", 400)
        return
    }

    if tx.Hash == "" {
        payload := txPayload{
            ChainID: NetworkName,
            From:    tx.From,
            To:      tx.To,
            Amount:  tx.Amount,
            Fee:     tx.Fee,
            Nonce:   tx.Nonce,
            PubKey:  tx.PubKey,
            Type:    tx.Type,
            Data:    tx.Data,
        }
        raw, _ := json.Marshal(payload)
        tx.Hash = HashBytes(raw)
    }

    mu.Lock()
    defer mu.Unlock()

    // 1) klasyczna walidacja
    if !ValidateTx(chain.State, tx) {
        http.Error(w, "rejected", 400)
        return
    }

    // 2) BLOKADA podwójnego wydania w mempoolu
    for _, m := range mempool {
        if m.From == tx.From && tx.Nonce <= m.Nonce {
            http.Error(w, "nonce_conflict", 400)
            return
        }
    }

    // 3) limit TX z jednego adresu (jak już masz)
    if mempoolCountByAddr(tx.From) >= 100 {
        http.Error(w, "too_many_pending_from_addr", http.StatusTooManyRequests)
        return
    }

    addToMempool(tx)
    // opcjonalnie log:
    // fmt.Printf("[TX] pending=%d from=%s amount=%d\n", len(mempool), short(tx.From), tx.Amount)
}


/* ------------------------------- Bridge RPC -------------------------------- */

func listBridgeLocksHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, chain.Bridge.Locks)
}

func listBridgeUnlocksHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()
	writeJSON(w, chain.Bridge.Unlocks)
}

/* -------------------------------------------------------------------------- */
/*                                    P2P                                      */
/* -------------------------------------------------------------------------- */
func requireP2PAuth(w http.ResponseWriter, r *http.Request) bool {
    // Jeśli nie ustawisz tokena, P2P pozostaje otwarte (dev / testnet)
    if P2PToken == "" {
        return true
    }
    if r.Header.Get(P2PAuthHeader) != P2PToken {
        http.Error(w, "unauthorized", http.StatusUnauthorized)
        return false
    }
    return true
}

func peerReceiveBlockHandler(w http.ResponseWriter, r *http.Request) {
	    if !requireP2PAuth(w, r) {
        return
    }
	var b Block
	if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
		http.Error(w, "bad_json", 400)
		return
	}
	mu.Lock()
	defer mu.Unlock()

	if ValidateBlock(chain, b) {
		applyBlock(chain, b)
		chain.Blocks = append(chain.Blocks, b)
		purgeFromMempool(b.Txs)
		SaveChain(chain)
		fmt.Printf("[SYNC] Block #%d accepted from peer\n", b.Header.Height)
		w.Write([]byte(`{"ok":true}`))
	} else {
		http.Error(w, "invalid_block", 400)
	}
}

func stringsContainsBad(s string) bool {
	return bytes.Contains([]byte(s), []byte{'\n'}) || bytes.Contains([]byte(s), []byte{'\r'})
}

func peerAddHandler(w http.ResponseWriter, r *http.Request) {
	addr := r.URL.Query().Get("addr")
	if addr == "" {
		http.Error(w, "missing addr", 400)
		return
	}
	if stringsContainsBad(addr) {
		http.Error(w, "invalid addr", 400)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	for _, x := range chain.Peers {
		if x == addr {
			w.Write([]byte(`{"ok":true,"info":"exists"}`))
			return
		}
	}
	chain.Peers = append(chain.Peers, addr)
	SaveChain(chain)
	fmt.Printf("[PEER] Added %s\n", addr)
	w.Write([]byte(`{"ok":true}`))
}

func broadcastBlock(b Block) {
    data, _ := json.Marshal(b)
    for _, peer := range chain.Peers {
        url := fmt.Sprintf("http://%s/peer/block", peer)
        go func(url string) {
            req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
            if err != nil {
                fmt.Printf("[PEER] build req error %s: %v\n", url, err)
                return
            }
            req.Header.Set("Content-Type", "application/json")
            if P2PToken != "" {
                req.Header.Set(P2PAuthHeader, P2PToken)
            }

            resp, err := http.DefaultClient.Do(req)
            if err != nil {
                fmt.Printf("[PEER] send error %s: %v\n", url, err)
                return
            }
            resp.Body.Close()
        }(url)
    }
}


/* -------------------------------------------------------------------------- */
/*                               RATE LIMIT / CORS                             */
/* -------------------------------------------------------------------------- */

type bucket struct {
	tokens int
	last   time.Time
}

type rateLimiter struct {
	mu sync.Mutex
	m  map[string]*bucket
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{m: map[string]*bucket{}}
}

func (r *rateLimiter) Allow(key string, limit int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	b := r.m[key]
	if b == nil {
		b = &bucket{tokens: limit, last: now}
		r.m[key] = b
	}
	if now.Sub(b.last) > 10*time.Second {
		b.tokens = limit
		b.last = now
	}
	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

var rl = newRateLimiter()

func clientIP(r *http.Request) string {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func withLimit(next http.HandlerFunc, limit int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ip := clientIP(r)
		if !rl.Allow(ip, limit) {
			http.Error(w, "ratelimited", http.StatusTooManyRequests)
			return
		}
		next(w, r)
	}
}

func withCORS(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if r.Method == "OPTIONS" {
			w.WriteHeader(204)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func limitBody(h http.Handler, max int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, max)
		h.ServeHTTP(w, r)
	})
}

/* -------------------------------------------------------------------------- */
/*                              INIT / GENESIS                                 */
/* -------------------------------------------------------------------------- */

func initConsensus() {
	UNIT = pow10u(Decimals)
	REWARD0_UNITS = toUnits(RewardInitialCoins)
	MAX_SUPPLY_UNITS = toUnits(MaxSupplyCoins)
}

func createGenesis() Block {
	return Block{
		Header: BlockHeader{
			Version:    1,
			PrevHash:   "0x0",
			Merkle:     "",
			Timestamp:  time.Now().UTC(),
			Nonce:      0,
			Height:     0,
			Difficulty: DifficultyBitsInit,
			Miner:      "GENESIS",
		},
		Mix:  "0x0",
		Hash: "GENESIS",
	}
}
func splitReward80_20(total uint64) (minerShare uint64, treasuryShare uint64) {
    treasuryShare = total / 5          // 20%
    minerShare = total - treasuryShare // 80%
    return
}
func buildGenesisState() map[string]Account {
    state := map[string]Account{}
    state[BridgeVaultAddr] = Account{Balance: 0, Nonce: 0}
    state[BridgeOperatorAddr] = Account{Balance: 0, Nonce: 0}
    state[TreasuryAddr] = Account{Balance: 0, Nonce: 0} // ✅ dodaj
    return state
}

/* -------------------------------------------------------------------------- */
/*                                 START NODE                                  */
/* -------------------------------------------------------------------------- */

func StartNode() {
	rand.Seed(time.Now().UnixNano())
	initConsensus()

	currentPH := currentParamsHash()
    P2PToken = os.Getenv("BOSON_P2P_TOKEN")
    if P2PToken == "" {
        fmt.Println("[WARN] BOSON_P2P_TOKEN not set – P2P is unauthenticated (dev/test only)")
    }
	chain = LoadChain()
	if chain == nil {
		fmt.Println("[INIT] creating new chain with GENESIS")
		gen := createGenesis()
		state := buildGenesisState()
		chain = &Chain{
			Blocks:      []Block{gen},
			Peers:       []string{},
			State:       state,
			TotalMinted: 0,
			ParamsHash:  currentPH,
			Params: ConsensusParams{
				NetworkName:       NetworkName,
				Decimals:          Decimals,
				RewardInitial:     RewardInitialCoins,
				HalvingInterval:   HalvingInterval,
				MaxSupply:         MaxSupplyCoins,
				TargetBlockSec:    TargetBlockSeconds,
				RetargetWindow:    RetargetWindow,
				MaxDifficultyStep: MaxDifficultyStep,
			},
			Staking: StakingState{
				MinStake:    0,
				TotalStaked: 0,
				Validators:  map[string]Staker{},
			},
			Contracts: map[string]Contract{},
			Bridge: BridgeState{
				Locks:    map[string]BridgeLock{},
				Unlocks:  map[string]BridgeUnlock{},
				Consumed: map[string]bool{},
			},

			GenesisMessage:    GenesisMessage,
			GenesisMessageHex: hex.EncodeToString([]byte(GenesisMessage)),
		}
		SaveChain(chain)
	} else if chain.ParamsHash != currentPH {
		fmt.Println("[PANIC] Consensus params changed vs stored chain – abort to avoid fork")
		os.Exit(1)
	}

	// RPC
	mux := http.NewServeMux()
	mux.HandleFunc("/getWork", withLimit(getWorkHandler, 100))
	mux.HandleFunc("/submitWork", withLimit(submitWorkHandler, 50))
	mux.HandleFunc("/tx/submit", withLimit(submitTxHandler, 100))
	mux.HandleFunc("/tx/pool", withLimit(poolListHandler, 100))
	mux.HandleFunc("/account", withLimit(getAccountHandler, 100))
	mux.HandleFunc("/chain", withLimit(getChainHandler, 20))
	mux.HandleFunc("/stats", withLimit(getStatsHandler, 50))
	mux.HandleFunc("/bridge/locks", withLimit(listBridgeLocksHandler, 20))
	mux.HandleFunc("/bridge/unlocks", withLimit(listBridgeUnlocksHandler, 20))
	mux.HandleFunc("/tx/pending", withLimit(pendingHandler, 50))
	rpcPort := DefaultRPCPort
	if v := os.Getenv("BOSON_RPC_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			rpcPort = p
		}
	}

	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", rpcPort)
		fmt.Println("[RPC] listening on", addr)
		if err := http.ListenAndServe(addr, withCORS(limitBody(mux, MaxJSONKB*1024))); err != nil {
			fmt.Println("[ERR] RPC listen:", err)
			os.Exit(1)
		}
	}()

	// P2P HTTP
	p2pMux := http.NewServeMux()
	p2pMux.HandleFunc("/peer/block", withLimit(peerReceiveBlockHandler, 200))
	p2pMux.HandleFunc("/peers/add", withLimit(peerAddHandler, 50))

	p2pPort := DefaultP2PPort
	if v := os.Getenv("BOSON_P2P_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			p2pPort = p
		}
	}
	go func() {
		addr := fmt.Sprintf("0.0.0.0:%d", p2pPort) // P2P może być public
		fmt.Println("[P2P] listening on", addr)
		if err := http.ListenAndServe(addr, limitBody(p2pMux, MaxJSONKB*1024)); err != nil {
			fmt.Println("[ERR] P2P listen:", err)
			os.Exit(1)
		}
	}()

	fmt.Println("[NODE] Boson Infinity node started.")
}
