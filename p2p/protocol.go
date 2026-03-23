package p2p

import "log/slog"

/* -------------------------------------------------------------------------- */
/*                           NETWORK PROTOCOL                                  */
/* -------------------------------------------------------------------------- */

const (
	// ProtocolVersion is the current P2P protocol version.
	// Peers with incompatible versions are disconnected.
	ProtocolVersion = 2

	// MinCompatVersion is the minimum protocol version we accept.
	MinCompatVersion = 2
)

// IsCompatibleVersion checks if a peer's protocol version is acceptable.
func IsCompatibleVersion(peerVersion int) bool {
	return peerVersion >= MinCompatVersion
}

/* -------------------------------------------------------------------------- */
/*                              BAN SCORING                                    */
/* -------------------------------------------------------------------------- */
// Peers accumulate ban score for misbehavior. When score exceeds threshold,
// the peer is banned for a duration.
//
// Actions and scores:
//   InvalidBlock      → +20
//   InvalidTx         → +5
//   TimestampFuture   → +10
//   WrongNetwork      → +100 (instant ban)
//   SpamBlocks        → +50
//   TooManyErrors     → +10

const (
	BanScoreThreshold = 100
	BanDurationSec    = 3600 // 1 hour

	ScoreInvalidBlock    = 20
	ScoreInvalidTx       = 5
	ScoreTimestampFuture = 10
	ScoreWrongNetwork    = 100
	ScoreSpamBlocks      = 50
	ScoreTooManyErrors   = 10
)

// AddBanScore adds to a peer's ban score and bans if threshold exceeded.
func (pm *PeerManager) AddBanScore(addr string, score int, reason string) {
	pm.mu.Lock()
	p, ok := pm.peers[addr]
	if !ok {
		pm.mu.Unlock()
		return
	}

	p.BanScore += score
	shouldBan := p.BanScore >= BanScoreThreshold
	banScore := p.BanScore

	if shouldBan {
		delete(pm.peers, addr)
	}
	pm.mu.Unlock()

	if shouldBan {
		slog.Warn("peer banned",
			"addr", addr,
			"score", banScore,
			"reason", reason)
	} else {
		slog.Debug("peer ban score increased",
			"addr", addr,
			"score", banScore,
			"added", score,
			"reason", reason)
	}
}
