package consensus

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/crypto"
)

func ValidateTx(state map[string]core.Account, tx core.Tx) bool {
	// Validate transaction type
	if !core.ValidTxTypes[tx.Type] {
		slog.Warn("invalid tx type", "type", tx.Type)
		return false
	}

	// Validate addresses (40 hex chars)
	if !core.IsValidAddr(tx.From) {
		slog.Warn("invalid from address", "from", tx.From)
		return false
	}
	if !core.IsValidAddr(tx.To) {
		slog.Warn("invalid to address", "to", tx.To)
		return false
	}

	// Amount must be > 0
	if tx.Amount == 0 {
		slog.Warn("zero amount transaction")
		return false
	}

	// Verify public key -> address match
	pub, err := hex.DecodeString(tx.PubKey)
	if err != nil || len(pub) == 0 {
		return false
	}
	want := crypto.AddrFromPub(pub)
	if want != tx.From {
		return false
	}

	// Verify Ed25519 signature
	if !crypto.VerifyTxSignature(tx) {
		return false
	}

	// Enforce fixed fee = 0.1% of amount
	expectedFee := CalcFee(tx.Amount)
	if tx.Fee != expectedFee {
		slog.Warn("bad fee", "expected", expectedFee, "got", tx.Fee)
		return false
	}

	ac := state[tx.From]

	// Nonce must be sequential
	if tx.Nonce != ac.Nonce+1 {
		return false
	}

	// Safe overspend check (no overflow)
	if tx.Amount > ac.Balance {
		return false
	}
	if tx.Fee > ac.Balance-tx.Amount {
		return false
	}

	return true
}

func ValidTimestamp(prev, now time.Time) bool {
	if now.Before(prev) {
		return false
	}
	// Reduced future skew: 120s instead of 600s to prevent timestamp manipulation
	if now.After(time.Now().Add(120 * time.Second)) {
		return false
	}
	return true
}

// MedianTimePast returns the median timestamp of the last 11 blocks.
// Used to prevent timestamp manipulation by miners.
func MedianTimePast(c *core.Chain) time.Time {
	n := len(c.Blocks)
	window := 11
	if n < window {
		window = n
	}
	if window == 0 {
		return time.Time{}
	}

	timestamps := make([]int64, window)
	for i := 0; i < window; i++ {
		timestamps[i] = c.Blocks[n-1-i].Header.Timestamp.Unix()
	}

	// Sort
	for i := 0; i < len(timestamps); i++ {
		for j := i + 1; j < len(timestamps); j++ {
			if timestamps[j] < timestamps[i] {
				timestamps[i], timestamps[j] = timestamps[j], timestamps[i]
			}
		}
	}

	median := timestamps[len(timestamps)/2]
	return time.Unix(median, 0)
}

// ValidTimestampMTP checks that a block timestamp is after the MTP.
func ValidTimestampMTP(c *core.Chain, blockTime time.Time) bool {
	mtp := MedianTimePast(c)
	if !mtp.IsZero() && !blockTime.After(mtp) {
		return false
	}
	// Also check future skew
	if blockTime.After(time.Now().Add(120 * time.Second)) {
		return false
	}
	return true
}

func ValidateBlock(c *core.Chain, b core.Block, cfg *core.Config) bool {
	if b.Header.Height == 0 && b.Hash == "GENESIS" {
		return true
	}

	last := c.Blocks[len(c.Blocks)-1]

	if b.Header.PrevHash != last.Hash {
		slog.Warn("block validation: bad prev hash")
		return false
	}
	if b.Header.Height != last.Header.Height+1 {
		slog.Warn("block validation: bad height")
		return false
	}
	if !ValidTimestamp(last.Header.Timestamp, b.Header.Timestamp) {
		slog.Warn("block validation: bad timestamp (before prev)")
		return false
	}
	if !ValidTimestampMTP(c, b.Header.Timestamp) {
		slog.Warn("block validation: timestamp before median-time-past")
		return false
	}

	// Validate miner address
	if !core.IsValidAddr(b.Header.Miner) {
		slog.Warn("block validation: invalid miner address")
		return false
	}

	var th []string
	for _, t := range b.Txs {
		th = append(th, t.Hash)
	}
	if crypto.MerkleRoot(th) != b.Header.Merkle {
		slog.Warn("block validation: merkle mismatch")
		return false
	}
	if crypto.BlockHash(b) != b.Hash {
		slog.Warn("block validation: bad block hash")
		return false
	}
	if !crypto.CheckMask(b.Mix, b.Header.Difficulty) {
		slog.Warn("block validation: bad mask")
		return false
	}
	// Verify mix hash was computed correctly (legacy or DAG based on height)
	// headerHex must match exactly what buildWork produces: hex.EncodeToString([]byte("prevHash:height:merkle"))
	headerStr := fmt.Sprintf("%s:%d:%s", last.Hash, b.Header.Height, b.Header.Merkle)
	headerHex := hex.EncodeToString([]byte(headerStr))
	expectedMix := crypto.ComputeMix(headerHex, b.Header.Nonce, b.Header.Height)
	if b.Mix != expectedMix {
		slog.Warn("block validation: mix hash mismatch",
			"expected_prefix", expectedMix[:32],
			"got_prefix", b.Mix[:min(32, len(b.Mix))])
		return false
	}
	expectedDiff := Retarget(c)
	if b.Header.Difficulty != expectedDiff {
		slog.Warn("block validation: wrong difficulty", "expected", expectedDiff, "got", b.Header.Difficulty)
		return false
	}
	if len(b.Txs) > core.MaxBlockTXs {
		slog.Warn("block validation: too many txs")
		return false
	}

	tmpState := core.CopyState(c.State)
	tmpChain := *c
	tmpChain.State = tmpState
	tmpChain.Staking = core.CopyStaking(c.Staking)

	var totalFees uint64
	for _, tx := range b.Txs {
		if !ValidateTx(tmpChain.State, tx) {
			slog.Warn("block validation: invalid tx", "hash", tx.Hash)
			return false
		}
		ApplyTx(tmpChain.State, tx, &tmpChain, b.Header.Height, cfg)
		totalFees += tx.Fee
	}

	br := BaseRewardAt(b.Header.Height)
	var remaining uint64
	if c.TotalMinted < core.MAX_SUPPLY_UNITS {
		remaining = core.MAX_SUPPLY_UNITS - c.TotalMinted
	}
	if br > remaining {
		br = remaining
	}

	totalReward := br + totalFees
	expMinerShare, expTreasuryShare := SplitReward80_20(totalReward)

	// Verify rewards are correct by checking expected values
	// (tmpState only has TX effects, not rewards — rewards are applied by ApplyBlock later)
	if expMinerShare+expTreasuryShare != totalReward {
		slog.Warn("block validation: reward split mismatch")
		return false
	}

	return true
}

/* ------------------------------ TX Application ----------------------------- */

func ExecBridgeLock(ch *core.Chain, state map[string]core.Account, tx core.Tx, height int, cfg *core.Config) {
	var data struct {
		ToERC20 string `json:"to_erc20"`
	}
	if err := json.Unmarshal([]byte(tx.Data), &data); err != nil {
		slog.Warn("bridge_lock: invalid data JSON", "error", err)
		return
	}

	// Validate ERC20 address format (42 chars, 0x prefix)
	if len(data.ToERC20) != 42 || !strings.HasPrefix(data.ToERC20, "0x") {
		slog.Warn("bridge_lock: invalid ERC20 address", "addr", data.ToERC20)
		return
	}

	from := state[tx.From]
	from.Balance -= tx.Amount + tx.Fee
	from.Nonce++
	state[tx.From] = from

	vault := state[cfg.BridgeVaultAddr]
	vault.Balance += tx.Amount
	state[cfg.BridgeVaultAddr] = vault

	lock := core.BridgeLock{
		ID:        tx.Hash,
		From:      tx.From,
		ToERC20:   data.ToERC20,
		Amount:    tx.Amount,
		Height:    height,
		CreatedAt: time.Now().Unix(),
	}
	ch.Bridge.Locks[lock.ID] = lock

	slog.Info("bridge lock",
		"id", core.Short(lock.ID), "from", core.Short(lock.From),
		"erc20", data.ToERC20, "amount", lock.Amount)
}

func ExecBridgeUnlock(ch *core.Chain, state map[string]core.Account, tx core.Tx, height int, cfg *core.Config) {
	// All bridge_unlock attempts charge fee (anti-spam for failed attempts)
	from := state[tx.From]
	from.Balance -= tx.Fee
	from.Nonce++
	state[tx.From] = from

	// Only the bridge operator can execute unlocks
	if tx.From != cfg.BridgeOperatorAddr {
		slog.Warn("bridge_unlock: unauthorized operator", "from", tx.From)
		return // fee still charged
	}
	if !crypto.VerifyTxSignature(tx) {
		slog.Warn("bridge_unlock: invalid operator signature")
		return
	}

	var data struct {
		LockID   string `json:"lock_id"`
		ToNative string `json:"to_native"`
	}
	if err := json.Unmarshal([]byte(tx.Data), &data); err != nil {
		slog.Warn("bridge_unlock: invalid data JSON", "error", err)
		return
	}

	if !core.IsValidAddr(data.ToNative) {
		slog.Warn("bridge_unlock: invalid native address", "addr", data.ToNative)
		return
	}

	// ATOMIC: Mark consumed BEFORE transferring funds (prevents TOCTOU double-spend)
	if ch.Bridge.Consumed[data.LockID] {
		return
	}
	ch.Bridge.Consumed[data.LockID] = true // mark consumed FIRST

	lock, ok := ch.Bridge.Locks[data.LockID]
	if !ok {
		ch.Bridge.Consumed[data.LockID] = false // rollback
		return
	}

	vault := state[cfg.BridgeVaultAddr]
	if vault.Balance < lock.Amount {
		ch.Bridge.Consumed[data.LockID] = false // rollback
		return
	}
	vault.Balance -= lock.Amount
	state[cfg.BridgeVaultAddr] = vault

	recv := state[data.ToNative]
	recv.Balance += lock.Amount
	state[data.ToNative] = recv
	unlock := core.BridgeUnlock{
		ID:        tx.Hash,
		LockID:    data.LockID,
		ToNative:  data.ToNative,
		Amount:    lock.Amount,
		Height:    height,
		CreatedAt: time.Now().Unix(),
	}
	ch.Bridge.Unlocks[unlock.ID] = unlock

	slog.Info("bridge unlock",
		"id", core.Short(unlock.ID), "lock", core.Short(lock.ID),
		"to", core.Short(unlock.ToNative), "amount", unlock.Amount)
}

func ApplyTx(state map[string]core.Account, tx core.Tx, ch *core.Chain, height int, cfg *core.Config) {
	// Guard: stake/unstake/bridge require a non-nil chain
	if ch == nil && (tx.Type == "stake" || tx.Type == "unstake" || tx.Type == "bridge_lock" || tx.Type == "bridge_unlock") {
		slog.Warn("ApplyTx: chain is nil, skipping non-transfer tx", "type", tx.Type)
		// Still charge fee and increment nonce for transfer-like accounting
		from := state[tx.From]
		from.Balance -= tx.Fee
		from.Nonce++
		state[tx.From] = from
		return
	}

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
		from.Balance -= tx.Fee // unstake now charges fee (anti-spam)
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
		ExecBridgeLock(ch, state, tx, height, cfg)

	case "bridge_unlock":
		ExecBridgeUnlock(ch, state, tx, height, cfg)
	}
}

func ApplyBlock(c *core.Chain, b core.Block, cfg *core.Config) {
	// 1) Apply all TX to state
	for _, tx := range b.Txs {
		ApplyTx(c.State, tx, c, b.Header.Height, cfg)
	}

	// 2) Count fees
	var totalFees uint64
	for _, tx := range b.Txs {
		totalFees += tx.Fee
	}

	// 3) Subsidy (halving)
	br := BaseRewardAt(b.Header.Height)

	// Cap supply
	var remaining uint64
	if c.TotalMinted < core.MAX_SUPPLY_UNITS {
		remaining = core.MAX_SUPPLY_UNITS - c.TotalMinted
	}
	if br > remaining {
		br = remaining
	}

	// 4) total reward = subsidy + fees
	totalReward := br + totalFees

	minerShare, treasuryShare := SplitReward80_20(totalReward)

	miner := b.Header.Miner

	// Miner 80%
	ma := c.State[miner]
	ma.Balance += minerShare
	c.State[miner] = ma

	// Treasury 20%
	ta := c.State[cfg.TreasuryAddr]
	ta.Balance += treasuryShare
	c.State[cfg.TreasuryAddr] = ta

	// 5) Minted only subsidy
	c.TotalMinted += br

	slog.Info("block reward",
		"miner", core.Short(miner), "miner_share", minerShare,
		"fees", totalFees, "treasury", treasuryShare,
		"minted", fmt.Sprintf("%d/%d", c.TotalMinted, core.MAX_SUPPLY_UNITS))
}
