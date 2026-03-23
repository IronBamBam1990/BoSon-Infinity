package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/IronBamBam1990/BoSon-Infinity/core"
	"github.com/IronBamBam1990/BoSon-Infinity/mempool"
	"github.com/IronBamBam1990/BoSon-Infinity/p2p"
	"github.com/IronBamBam1990/BoSon-Infinity/rpc"
	"github.com/IronBamBam1990/BoSon-Infinity/security"
	"github.com/IronBamBam1990/BoSon-Infinity/storage"
)

func main() {
	// Structured logging
	logLevel := slog.LevelInfo
	if os.Getenv("BOSON_DEBUG") != "" {
		logLevel = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})))

	slog.Info("Boson Infinity L0 Node starting", "version", "2.1.0")

	// Load config
	cfg, err := core.LoadConfig()
	if err != nil {
		slog.Error("configuration error", "error", err)
		fmt.Fprintf(os.Stderr, "\n[FATAL] Configuration error: %s\n", err)
		fmt.Fprintf(os.Stderr, "Set required environment variables or create a boson.env file.\n")
		fmt.Fprintf(os.Stderr, "Required: BOSON_API_KEY, BOSON_TREASURY_ADDR\n\n")
		os.Exit(1)
	}

	// Initialize consensus params
	core.InitConsensus()

	// Initialize rate limiter
	rl := security.NewRateLimiterV2()

	if cfg.P2PToken == "" {
		slog.Warn("BOSON_P2P_TOKEN not set — P2P is unauthenticated (dev/test only)")
	}

	currentPH := storage.CurrentParamsHash()

	// Open BBolt database
	db, err := storage.OpenStore(cfg.DataDir)
	if err != nil {
		slog.Error("database open failed", "error", err)
		os.Exit(1)
	}
	defer db.Close()

	// Ensure index buckets exist
	db.EnsureTxIndexBuckets()
	db.EnsureCheckpointBucket()

	// Try to load chain from database first
	var chain *core.Chain

	if db.GetHeight() >= 0 {
		// Database has data — load from it
		chain, err = db.LoadToChain()
		if err != nil {
			slog.Error("load chain from database failed", "error", err)
			os.Exit(1)
		}
		if chain.ParamsHash != currentPH {
			slog.Error("consensus params changed vs stored chain — abort to avoid fork")
			os.Exit(1)
		}
		slog.Info("chain loaded from database", "blocks", len(chain.Blocks))
	} else {
		// Database empty — check for legacy JSON file
		legacyChain := storage.LoadChain(cfg.ChainFilePath(), &cfg)
		if legacyChain != nil {
			// Migrate from JSON to BBolt
			slog.Info("migrating legacy JSON chain to BBolt database...")
			if legacyChain.ParamsHash != currentPH {
				slog.Error("consensus params changed vs stored chain — abort to avoid fork")
				os.Exit(1)
			}
			if err := db.InitFromChain(legacyChain); err != nil {
				slog.Error("migration failed", "error", err)
				os.Exit(1)
			}
			chain = legacyChain
			slog.Info("migration complete — you can remove the old chain.mainnet.json file")
		} else {
			// Fresh start — create genesis
			slog.Info("creating new chain with GENESIS")
			gen := storage.CreateGenesis()
			state := storage.BuildGenesisState(&cfg)
			chain = &core.Chain{
				Blocks:      []core.Block{gen},
				Peers:       []string{},
				State:       state,
				TotalMinted: 0,
				ParamsHash:  currentPH,
				Params: core.ConsensusParams{
					NetworkName:       core.NetworkName,
					Decimals:          core.Decimals,
					RewardInitial:     core.RewardInitialCoins,
					HalvingInterval:   core.HalvingInterval,
					MaxSupply:         core.MaxSupplyCoins,
					TargetBlockSec:    core.TargetBlockSeconds,
					RetargetWindow:    core.RetargetWindow,
					MaxDifficultyStep: core.MaxDifficultyStep,
				},
				Staking: core.StakingState{
					MinStake:    0,
					TotalStaked: 0,
					Validators:  map[string]core.Staker{},
				},
				Contracts: map[string]core.Contract{},
				Bridge: core.BridgeState{
					Locks:    map[string]core.BridgeLock{},
					Unlocks:  map[string]core.BridgeUnlock{},
					Consumed: map[string]bool{},
				},
				GenesisMessage:    core.GenesisMessage,
				GenesisMessageHex: hex.EncodeToString([]byte(core.GenesisMessage)),
			}
			if err := db.InitFromChain(chain); err != nil {
				slog.Error("save genesis to database failed", "error", err)
				os.Exit(1)
			}
		}
	}

	// Create indexed mempool
	pool := mempool.New(cfg.MaxMempoolSize, cfg.MaxPendingPerAddr)

	// Shared node state
	ns := &rpc.NodeState{
		Chain: chain,
		Pool:  pool,
		Cfg:   &cfg,
		Jobs:  rpc.NewSyncMap(),
		DB:    db,
	}

	// Start Peer Manager
	pm := p2p.NewPeerManager(ns, cfg.SeedNodes)
	ns.PeerMgr = pm
	pm.Start()

	// Periodic job cleanup
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			ns.Jobs.Cleanup()
		}
	}()

	// Mining WebSocket hub
	miningHub := rpc.NewMiningHub(ns)
	miningHub.Start()
	ns.MiningHub = miningHub

	broadcastFn := func(b core.Block) {
		p2p.BroadcastBlock(b, ns)
		miningHub.NotifyNewBlock() // push new work to WS miners
	}

	// Wire up TX broadcast to peers
	ns.BroadcastTx = func(tx core.Tx) {
		p2p.BroadcastTx(tx, ns)
	}

	// ---- RPC Server ----
	mux := http.NewServeMux()
	mux.HandleFunc("/health", security.RequireGET(security.HealthHandler(chain, &ns.Mu, ns)))
	mux.HandleFunc("/getWork", security.WithLimit(security.RequireGET(rpc.GetWorkHandler(ns)), 100, rl))
	mux.HandleFunc("/submitWork", security.WithLimit(security.RequireAPIKey(security.RequirePOST(rpc.SubmitWorkHandler(ns, broadcastFn)), &cfg), 50, rl))
	mux.HandleFunc("/tx/submit", security.WithLimit(security.RequirePOST(rpc.SubmitTxHandler(ns)), 100, rl))
	mux.HandleFunc("/tx/pool", security.WithLimit(security.RequireGET(rpc.PoolListHandler(ns)), 100, rl))
	mux.HandleFunc("/tx/pending", security.WithLimit(security.RequireGET(rpc.PendingHandler(ns)), 50, rl))
	mux.HandleFunc("/account", security.WithLimit(security.RequireGET(rpc.GetAccountHandler(ns)), 100, rl))
	mux.HandleFunc("/chain", security.WithLimit(security.RequireGET(rpc.GetChainHandler(ns)), 20, rl))
	mux.HandleFunc("/block", security.WithLimit(security.RequireGET(rpc.GetBlockHandler(ns)), 50, rl))
	mux.HandleFunc("/stats", security.WithLimit(security.RequireGET(rpc.GetStatsHandler(ns)), 50, rl))
	mux.HandleFunc("/bridge/locks", security.WithLimit(security.RequireGET(rpc.ListBridgeLocksHandler(ns)), 20, rl))
	mux.HandleFunc("/bridge/unlocks", security.WithLimit(security.RequireGET(rpc.ListBridgeUnlocksHandler(ns)), 20, rl))
	mux.HandleFunc("/tx/get", security.WithLimit(security.RequireGET(rpc.GetTxHandler(ns)), 100, rl))
	mux.HandleFunc("/address/txs", security.WithLimit(security.RequireGET(rpc.GetAddressTxsHandler(ns)), 50, rl))
	mux.HandleFunc("/address/blocks", security.WithLimit(security.RequireGET(rpc.GetAddressBlocksHandler(ns)), 50, rl))
	mux.HandleFunc("/checkpoints", security.WithLimit(security.RequireGET(rpc.CheckpointsHandler(ns)), 20, rl))
	mux.HandleFunc("/tx/proof", security.WithLimit(security.RequireGET(rpc.MerkleProofHandler(ns)), 50, rl))
	mux.HandleFunc("/storage/info", security.WithLimit(security.RequireGET(rpc.StorageInfoHandler(ns)), 10, rl))
	mux.HandleFunc("/admin/prune", security.WithLimit(security.RequireAPIKey(security.RequirePOST(rpc.PruneHandler(ns)), &cfg), 2, rl))
	mux.HandleFunc("/ws/mining", rpc.MiningWSHandler(ns, miningHub, nil))
	mux.HandleFunc("/explorer", rpc.ExplorerHandler())
	mux.HandleFunc("/metrics", rpc.MetricsHandler(ns))

	rpcAddr := fmt.Sprintf("%s:%d", cfg.RPCBind, cfg.RPCPort)
	rpcHandler := security.ChainMiddleware(mux,
		security.WithSecurityHeaders,
		security.WithRequestID,
		security.WithCORSv2(cfg.AllowedOrigins),
		security.WithBodyLimit(core.MaxJSONKB*1024),
		security.WithIPWhitelist(cfg.AllowedIPs),
	)

	rpcServer := security.NewSecureServer(rpcAddr, rpcHandler)
	go func() {
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			slog.Info("RPC server starting (TLS)", "addr", rpcAddr)
			if err := rpcServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile); err != nil && err != http.ErrServerClosed {
				slog.Error("RPC server TLS error", "error", err)
				os.Exit(1)
			}
		} else {
			slog.Info("RPC server starting", "addr", rpcAddr)
			if err := rpcServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				slog.Error("RPC server error", "error", err)
				os.Exit(1)
			}
		}
	}()

	// ---- P2P Server ----
	p2pMux := http.NewServeMux()
	p2pMux.HandleFunc("/peer/block", security.WithLimit(security.RequirePOST(p2p.PeerReceiveBlockHandler(ns)), 200, rl))
	p2pMux.HandleFunc("/peer/tx", security.WithLimit(security.RequirePOST(p2p.PeerReceiveTxHandler(ns)), 200, rl))
	p2pMux.HandleFunc("/peer/status", security.WithLimit(security.RequireGET(p2p.PeerStatusHandler(ns)), 100, rl))
	p2pMux.HandleFunc("/peer/blocks", security.WithLimit(security.RequireGET(p2p.PeerBlocksHandler(ns)), 20, rl))
	p2pMux.HandleFunc("/peers/add", security.WithLimit(p2p.PeerAddHandler(ns), 50, rl))
	p2pMux.HandleFunc("/peers/list", security.WithLimit(security.RequireGET(p2p.PeerListHandler(ns)), 50, rl))

	p2pAddr := fmt.Sprintf("%s:%d", cfg.P2PBind, cfg.P2PPort)
	p2pHandler := security.ChainMiddleware(p2pMux,
		security.WithSecurityHeaders,
		security.WithRequestID,
		security.WithBodyLimit(core.MaxJSONKB*1024),
	)

	p2pServer := security.NewSecureServer(p2pAddr, p2pHandler)
	go func() {
		slog.Info("P2P server starting", "addr", p2pAddr)
		if err := p2pServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("P2P server error", "error", err)
			os.Exit(1)
		}
	}()

	slog.Info("Boson Infinity node started",
		"network", core.NetworkName,
		"rpc", rpcAddr,
		"p2p", p2pAddr,
		"treasury", core.Short(cfg.TreasuryAddr))

	// Wait for shutdown signal
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	<-ctx.Done()
	slog.Info("shutdown signal received, stopping gracefully...")

	// Stop peer manager
	pm.Stop()

	shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutCancel()

	if err := rpcServer.Shutdown(shutCtx); err != nil {
		slog.Error("RPC server shutdown error", "error", err)
	}
	if err := p2pServer.Shutdown(shutCtx); err != nil {
		slog.Error("P2P server shutdown error", "error", err)
	}

	// Save final state to database
	ns.Mu.Lock()
	if ns.Chain != nil {
		db.SaveState(ns.Chain.State)
		db.SetTotalMinted(ns.Chain.TotalMinted)
		db.SaveStaking(ns.Chain.Staking)
		db.SaveBridge(ns.Chain.Bridge)
		db.SavePeers(ns.Chain.Peers)
		slog.Info("chain saved to database on shutdown", "blocks", len(ns.Chain.Blocks))
	}
	ns.Mu.Unlock()

	slog.Info("Boson Infinity node stopped cleanly")
}
