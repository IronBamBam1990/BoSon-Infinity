package core

import "time"

/* -------------------------------------------------------------------------- */
/*                               CONSENSUS PARAMS                             */
/* -------------------------------------------------------------------------- */

const (
	NetworkName          = "boson-infinity-l0"
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
	FeePermille          = 1 // 0.1% = 1 promil

	GenesisMessage = "Boson Infinity created by Kamil Padula in 2025 — the original Layer-0 energy-defined PoW blockchain."

	// DAG PoW activation height — blocks before this use legacy MixHash
	DAGActivationHeight = 1000
)

// P2P Auth
const P2PAuthHeader = "X-P2P-Token"

/* -------------------------------------------------------------------------- */
/*                              DERIVED GLOBALS                                */
/* -------------------------------------------------------------------------- */

var (
	UNIT             uint64
	REWARD0_UNITS    uint64
	MAX_SUPPLY_UNITS uint64
)

func InitConsensus() {
	UNIT = Pow10u(Decimals)
	REWARD0_UNITS = ToUnits(RewardInitialCoins)
	MAX_SUPPLY_UNITS = ToUnits(MaxSupplyCoins)
}

func Pow10u(n int) uint64 {
	var v uint64 = 1
	for i := 0; i < n; i++ {
		v *= 10
	}
	return v
}

func ToUnits(coins float64) uint64 {
	return uint64(coins*float64(UNIT) + 1e-9)
}

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
	Data string `json:"data,omitempty"` // json payload e.g. { "to_erc20": "..."}
}

type TxPayload struct {
	ChainID     string `json:"chain_id"`
	GenesisHash string `json:"genesis_hash,omitempty"` // fork replay protection
	From        string `json:"from"`
	To          string `json:"to"`
	Amount      uint64 `json:"amount"`
	Fee         uint64 `json:"fee"`
	Nonce       uint64 `json:"nonce"`
	PubKey      string `json:"pubkey"`
	Type        string `json:"type,omitempty"`
	Data        string `json:"data,omitempty"`
}

// Allowed transaction types
var ValidTxTypes = map[string]bool{
	"":              true,
	"transfer":      true,
	"stake":         true,
	"unstake":       true,
	"bridge_lock":   true,
	"bridge_unlock": true,
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

	GenesisMessage    string `json:"genesis_message"`
	GenesisMessageHex string `json:"genesis_message_hex"`
}

/* ------------------------------ Energy Model ------------------------------- */

type EnergyModel struct {
	AvgJoulesPerHash float64 `json:"avg_j_per_hash"`
	AvgPricePerKWh   float64 `json:"avg_price_per_kwh"`
	FiatCurrency     string  `json:"fiat_currency"`
	UpdatedAt        int64   `json:"updated_at"`
}

/* ------------------------------ Helpers ------------------------------------ */

func Short(s string) string {
	if len(s) <= 8 {
		return s
	}
	return s[:8]
}

func CopyState(in map[string]Account) map[string]Account {
	out := make(map[string]Account, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func CopyStaking(in StakingState) StakingState {
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
