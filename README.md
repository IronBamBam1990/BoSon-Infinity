
# **Boson Infinity — Windows Miner & Desktop Wallet**

### SHA-512 Proof-of-Work • Fixed 50,000,000 Supply • Testnet Release

This release contains two Windows applications:

* **boson-wallet-gui.exe** — desktop GUI wallet
* **miner_gpu.exe** — mining client

No installation is required.
Both programs are portable `.exe` applications.

---

# 📘 **1. Running the Boson Wallet (boson-wallet-gui.exe)**

1. Simply double-click:

```
boson-wallet-gui.exe
```

2. After launching, the wallet automatically starts a local server and opens:

```
http://127.0.0.1:8090
```

3. On first run, the wallet will:

* load your existing `wallet.json` **OR**
* generate a new Ed25519 keypair
* create a Boson address (SHA-512(pub)[:20])
* store everything locally in `wallet.json`

### Your wallet NEVER sends private keys anywhere.

Everything is stored locally on your computer.

---

# 💳 **2. Your Node Connection**

The wallet automatically connects to:

```
Node URL:
http://94.130.151.250
```

API Key used internally for RPC calls:

```
API Key:
ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669
```

These values are shown in the GUI (“Connected node”).

---

# ⚡ **3. Running the Miner (miner_gpu.exe)**

### The miner takes **3 arguments**:

```
.\miner_gpu.exe  NODE_URL  API_KEY  YOUR_WALLET_ADDRESS
```

### Example (copy/paste):

```
.\miner_gpu.exe http://94.130.151.250 ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669 db92fe3a2720cc19256d9a1bab691346ef823e3a
```

Where:

| Argument                                                           | Meaning                   |
| ------------------------------------------------------------------ | ------------------------- |
| `http://94.130.151.250`                                            | The official testnet node |
| `ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669` | Public testnet API key    |
| `db92fe3a2720cc19256d9a1bab691346ef823e3a`                         | Your wallet address       |

### Expected output:

```
[WORK] difficulty=34 reward=49.99 BOS
[FOUND] nonce=8233433
[SUCCESS] Block submitted!
```

---

# 💸 **4. Sending & receiving BOS**

From the wallet interface:

* enter a recipient address (40-hex)
* enter amount
* click **Send**

The network fee is **0.1%** of the amount (auto-calculated).

---

# 🔋 **5. Network Energy & Cost Dashboard**

The wallet displays real-time parameters:

* block height & difficulty
* network hashrate
* Joules per hash
* FIAT/kWh
* cost to produce 1 BOS
* energy-equivalent value of your balance

These values come from the **energy model oracle** running on the same node.

---

# 🔐 **6. Wallet file location**

Your keys are stored in:

```
wallet.json
```

Keep a backup of this file — it contains:

* private key
* public key
* address
* node URL
* API key

If you delete it, the wallet cannot be recovered.

---

# 🚫 **7. Important Security Notes**

* Do **not** share your wallet.json
* Do **not** run the wallet on infected machines
* Always back up your keys
* BOS transactions are **irreversible**

---

# 🎉 **You’re Ready to Use Boson Infinity Testnet**

Wallet → GUI
Miner → CLI
Node → Hosted and ready at:

```
http://94.130.151.250
API Key: ef5251f535ed7143b31398c1128d3b6a6ecbb011eb45f10205251f7192be1669
```


