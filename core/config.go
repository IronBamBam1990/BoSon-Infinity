package core

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

/* -------------------------------------------------------------------------- */
/*                           CONFIGURATION                                     */
/* -------------------------------------------------------------------------- */

type Config struct {
	// Secrets
	APIKey            string // min 32 chars, hex — used for /submitWork auth
	P2PToken          string // optional — if set, P2P endpoints require it
	WalletPass        string // optional — AES-256-GCM passphrase for wallet.json

	// Addresses (40 hex chars each)
	TreasuryAddr      string
	BridgeOperatorAddr string
	BridgeVaultAddr   string // default: "0000000000000000000000000000000000000001"

	// Network
	RPCPort           int
	P2PPort           int
	RPCBind           string // default: "0.0.0.0"
	P2PBind           string // default: "0.0.0.0"
	AllowedOrigins    string // CORS origins, comma-separated or "*"
	AllowedIPs        string // optional IP whitelist, comma-separated

	// Paths
	DataDir           string // directory for chain data, default "."
	ChainFile         string // override chain filename
	EnergyModelFile   string // override energy model filename

	// Limits
	MaxMempoolSize    int    // max transactions in mempool
	MaxPendingPerAddr int    // max pending TX from one address

	// P2P
	SeedNodes         []string // seed node addresses for peer discovery

	// TLS (optional)
	TLSCertFile       string // path to TLS certificate file
	TLSKeyFile        string // path to TLS private key file
}

// DefaultConfig returns config with safe defaults (no secrets!)
func DefaultConfig() Config {
	return Config{
		BridgeVaultAddr:   "0000000000000000000000000000000000000001",
		RPCPort:           8080,
		P2PPort:           8081,
		RPCBind:           "0.0.0.0",
		P2PBind:           "0.0.0.0",
		AllowedOrigins:    "*",
		DataDir:           ".",
		ChainFile:         "chain.mainnet.json",
		EnergyModelFile:   "energy.model.json",
		MaxMempoolSize:    10000,
		MaxPendingPerAddr: 10,
	}
}

// LoadConfig loads configuration from environment variables, falling back to
// boson.env file in the current directory. ENV always takes priority.
func LoadConfig() (Config, error) {
	// First, try to load boson.env file (does NOT override existing ENV)
	LoadEnvFile("boson.env")

	cfg := DefaultConfig()

	// ---- Secrets ----
	cfg.APIKey = GetEnv("BOSON_API_KEY", "")
	if cfg.APIKey == "" {
		// Generate a random key and warn loudly
		key, err := GenerateSecureToken(32)
		if err != nil {
			return cfg, fmt.Errorf("failed to generate API key: %w", err)
		}
		cfg.APIKey = key
		fmt.Println("[WARN] ============================================================")
		fmt.Println("[WARN] BOSON_API_KEY not set! Generated random key for this session:")
		fmt.Printf("[WARN] %s\n", cfg.APIKey)
		fmt.Println("[WARN] Set BOSON_API_KEY in environment or boson.env for production!")
		fmt.Println("[WARN] ============================================================")
	}

	cfg.P2PToken = GetEnv("BOSON_P2P_TOKEN", "")
	cfg.WalletPass = GetEnv("BOSON_WALLET_PASS", "")

	// ---- Addresses ----
	cfg.TreasuryAddr = GetEnv("BOSON_TREASURY_ADDR", "")
	if cfg.TreasuryAddr == "" {
		return cfg, fmt.Errorf("BOSON_TREASURY_ADDR is required (40 hex chars)")
	}
	if !IsValidAddr(cfg.TreasuryAddr) {
		return cfg, fmt.Errorf("BOSON_TREASURY_ADDR invalid: must be 40 hex characters, got %q", cfg.TreasuryAddr)
	}

	cfg.BridgeOperatorAddr = GetEnv("BOSON_BRIDGE_OPERATOR_ADDR", cfg.TreasuryAddr) // defaults to treasury
	if !IsValidAddr(cfg.BridgeOperatorAddr) {
		return cfg, fmt.Errorf("BOSON_BRIDGE_OPERATOR_ADDR invalid: must be 40 hex characters")
	}

	if v := GetEnv("BOSON_BRIDGE_VAULT_ADDR", ""); v != "" {
		if !IsValidAddr(v) {
			return cfg, fmt.Errorf("BOSON_BRIDGE_VAULT_ADDR invalid: must be 40 hex characters")
		}
		cfg.BridgeVaultAddr = v
	}

	// ---- Network ----
	if v := GetEnv("BOSON_RPC_PORT", ""); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return cfg, fmt.Errorf("BOSON_RPC_PORT invalid: %q", v)
		}
		cfg.RPCPort = p
	}
	if v := GetEnv("BOSON_P2P_PORT", ""); v != "" {
		p, err := strconv.Atoi(v)
		if err != nil || p < 1 || p > 65535 {
			return cfg, fmt.Errorf("BOSON_P2P_PORT invalid: %q", v)
		}
		cfg.P2PPort = p
	}
	if v := GetEnv("BOSON_RPC_BIND", ""); v != "" {
		cfg.RPCBind = v
	}
	if v := GetEnv("BOSON_P2P_BIND", ""); v != "" {
		cfg.P2PBind = v
	}
	if v := GetEnv("BOSON_ALLOWED_ORIGINS", ""); v != "" {
		cfg.AllowedOrigins = v
	}
	cfg.AllowedIPs = GetEnv("BOSON_ALLOWED_IPS", "")

	// ---- Paths ----
	if v := GetEnv("BOSON_DATA_DIR", ""); v != "" {
		cfg.DataDir = v
	}
	if v := GetEnv("BOSON_CHAIN_FILE", ""); v != "" {
		cfg.ChainFile = v
	}
	if v := GetEnv("BOSON_ENERGY_MODEL_FILE", ""); v != "" {
		cfg.EnergyModelFile = v
	}

	// ---- Limits ----
	if v := GetEnv("BOSON_MAX_MEMPOOL", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			cfg.MaxMempoolSize = n
		}
	}
	if v := GetEnv("BOSON_MAX_PENDING_PER_ADDR", ""); v != "" {
		n, err := strconv.Atoi(v)
		if err == nil && n > 0 {
			cfg.MaxPendingPerAddr = n
		}
	}

	// ---- TLS ----
	cfg.TLSCertFile = GetEnv("BOSON_TLS_CERT", "")
	cfg.TLSKeyFile = GetEnv("BOSON_TLS_KEY", "")

	// ---- P2P ----
	if v := GetEnv("BOSON_SEED_NODES", ""); v != "" {
		for _, s := range strings.Split(v, ",") {
			s = strings.TrimSpace(s)
			if s != "" {
				cfg.SeedNodes = append(cfg.SeedNodes, s)
			}
		}
	}

	// Final validation
	if len(cfg.APIKey) < 32 {
		return cfg, fmt.Errorf("BOSON_API_KEY too short: minimum 32 characters required")
	}

	return cfg, nil
}

// ChainFilePath returns full path to chain file
func (c *Config) ChainFilePath() string {
	if c.DataDir == "." || c.DataDir == "" {
		return c.ChainFile
	}
	return c.DataDir + "/" + c.ChainFile
}

// EnergyModelPath returns full path to energy model file
func (c *Config) EnergyModelPath() string {
	if c.DataDir == "." || c.DataDir == "" {
		return c.EnergyModelFile
	}
	return c.DataDir + "/" + c.EnergyModelFile
}

/* -------------------------------------------------------------------------- */
/*                               HELPERS                                       */
/* -------------------------------------------------------------------------- */

func GetEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func IsValidAddr(addr string) bool {
	if len(addr) != 40 {
		return false
	}
	_, err := hex.DecodeString(addr)
	return err == nil
}

func IsValidHex(s string, minLen int) bool {
	if len(s) < minLen {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func GenerateSecureToken(byteLen int) (string, error) {
	b := make([]byte, byteLen)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// LoadEnvFile loads KEY=VALUE pairs from a file. Does NOT override existing env vars.
func LoadEnvFile(path string) {
	f, err := os.Open(path)
	if err != nil {
		return // file doesn't exist, that's fine
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])
		// Remove surrounding quotes
		value = strings.Trim(value, `"'`)
		// Only set if not already in environment
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}
}

// ValidatePeerAddr checks if a peer address is safe (anti-SSRF)
func ValidatePeerAddr(addr string) bool {
	if addr == "" {
		return false
	}

	// Must start with http:// or https://
	if !strings.HasPrefix(addr, "http://") && !strings.HasPrefix(addr, "https://") {
		return false
	}

	// Extract host
	host := addr
	for _, prefix := range []string{"https://", "http://"} {
		host = strings.TrimPrefix(host, prefix)
	}
	// Remove port and path
	if idx := strings.Index(host, "/"); idx != -1 {
		host = host[:idx]
	}
	hostOnly := host
	if h, _, err := net.SplitHostPort(host); err == nil {
		hostOnly = h
	}

	// Block private/reserved IPs
	ip := net.ParseIP(hostOnly)
	if ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
			ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return false
		}
		// Block metadata endpoints (cloud)
		if ip.Equal(net.ParseIP("169.254.169.254")) {
			return false
		}
	}

	// Block localhost hostnames
	lower := strings.ToLower(hostOnly)
	if lower == "localhost" || lower == "ip6-localhost" || lower == "ip6-loopback" {
		return false
	}

	return true
}

func FormatHashrate(v float64) string {
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
