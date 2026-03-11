# Localnet on macOS ARM64 (Apple Silicon) — Dilithium Build

This guide documents how to build and run a local NEAR MPC network with Dilithium (ML-DSA-87)
support on an Apple Silicon Mac. It differs from the standard `localnet.md` guide in several
important ways due to platform-specific constraints.

**Tested on:**
- macOS 26.2 (Sequoia), Apple M-series (arm64)
- `neard` 2.10.6 (protocol 82)
- `mpc-node` 3.5.1 (built from `illuzen/dilithium` branch)
- `near-cli-rs` 0.23.6
- `wasm-opt` 126 (binaryen, via Homebrew)
- Rust stable + nightly (managed via `rustup`)

---

## Background: Why this guide differs from the standard one

### 1. WASM bulk-memory operations

The `mpc-contract` WASM, when built with standard tooling, contains `memory.fill` and
`memory.copy` instructions (introduced by LLVM clang 21+ when compiling C dependencies
such as the `ring` crate). The NEAR VM only supports these from protocol version 83
onwards. `neard` 2.10.6 supports a maximum protocol version of 82.

**Solution**: Post-process the WASM with `wasm-opt --llvm-memory-copy-fill-lowering` to
convert these instructions into loop-based equivalents that the NEAR VM accepts.

### 2. Dilithium dependency removed from contract

The `qp-rusty-crystals-dilithium` crate also introduces bulk-memory operations in WASM.
Dilithium signature verification in the contract has been replaced with a stub that returns
`true`. The MPC nodes perform verification before submitting `respond()`.

### 3. Genesis with embedded contract

Due to the WASM size exceeding `neard`'s default RPC `json_payload_max_size` (413 Payload
Too Large), the contract is embedded directly into `genesis.json` rather than deployed
via the CLI.

### 4. Dilithium key registration not yet wired in real indexer

`register_dilithium_key` (which triggers a derived-key DKG) is implemented and tested via
the fake indexer in unit tests, but `crates/node/src/indexer/real.rs` does not yet listen
for this event from the chain. Master Dilithium key generation (DKG) works correctly. The
sign flow for derived keys is pending indexer integration.

---

## Prerequisites

Install the following tools before starting:

```shell
# Homebrew packages
brew install jq gettext binaryen
brew link --force gettext   # makes envsubst available
```

```shell
# Rust (via rustup)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
```

```shell
# near-cli-rs
npm install -g near-cli-rs
```

Set a short alias for the CLI (the binary path is non-standard):

```shell
export NEAR=/opt/homebrew/lib/node_modules/near-cli-rs/node_modules/.bin_real/near
```

Add this to your shell profile to persist it.

---

## Step 1: Clone and prepare the repository

```shell
git clone https://github.com/quantus/near-mpc.git
cd near-mpc
git checkout illuzen/dilithium
```

Also clone the local Dilithium dependency (referenced as `../qp-rusty-crystals` in
the workspace `Cargo.toml`):

```shell
cd ..
git clone https://github.com/quantus/qp-rusty-crystals.git
cd near-mpc
```

---

## Step 2: Install `neard` and `mpc-node`

Build and install from the repository's submodule:

```shell
git submodule update --init --recursive
cargo install --path libs/nearcore/neard --locked
cargo install --path crates/node --locked
```

Verify:

```shell
neard --version   # should print: neard (release 2.10.6) ... (protocol 82)
mpc-node --version  # should print: mpc-node 3.5.1
```

---

## Step 3: Build the MPC contract WASM

The standard `cargo near build` command produces WASM that is incompatible with
`neard` 2.10.6 due to bulk-memory operations. Use the following procedure instead:

### 3a. Build the raw WASM

```shell
RUSTFLAGS="-C target-feature=+bulk-memory" \
  cargo build \
    -p mpc-contract \
    --target wasm32-unknown-unknown \
    --profile release-contract \
    2>&1 | tail -5
```

The output artifact is at:
```
target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm
```

### 3b. Lower bulk-memory instructions with wasm-opt

```shell
/opt/homebrew/bin/wasm-opt \
  --enable-bulk-memory \
  --llvm-memory-copy-fill-lowering \
  -Os \
  target/wasm32-unknown-unknown/release-contract/mpc_contract.wasm \
  -o /tmp/mpc_contract_no_bulk.wasm
```

### 3c. Verify no bulk-memory instructions remain

```shell
wasm-validator /tmp/mpc_contract_no_bulk.wasm && echo "WASM is valid"
```

If validation passes without `[error] unexpected false: Bulk memory operations`, the
contract is compatible.

---

## Step 4: Prepare the localnet genesis

The contract is embedded into `genesis.json` to avoid RPC payload size limits.

### 4a. Copy the checked-in localnet config

```shell
cp -rf deployment/localnet/. ~/.near/mpc-localnet
```

### 4b. Embed the contract into genesis

Run the following Python script to update `genesis.json` with the new WASM:

```shell
python3 << 'PYEOF'
import json, base64, hashlib

ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58encode(data):
    count = sum(1 for b in data if b == 0)
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(ALPHABET[r])
    result.extend([ALPHABET[0]] * count)
    result.reverse()
    return bytes(result).decode('ascii')

with open('/tmp/mpc_contract_no_bulk.wasm', 'rb') as f:
    wasm_bytes = f.read()

code_hash = b58encode(hashlib.sha256(wasm_bytes).digest())
wasm_b64  = base64.b64encode(wasm_bytes).decode()

print(f"WASM size:  {len(wasm_bytes):,} bytes")
print(f"code_hash:  {code_hash}")

for genesis_path in [
    '/Users/cezaryo/.near/mpc-localnet/genesis.json',
    'deployment/localnet/genesis.json',
]:
    with open(genesis_path) as f:
        d = json.load(f)

    d['protocol_version'] = 81   # neard 2.10.6 max supported

    contract_account = 'mpc-contract.test.near'
    for i, record in enumerate(d.get('records', [])):
        if isinstance(record, dict):
            if 'Contract' in record and record['Contract'].get('account_id') == contract_account:
                d['records'][i]['Contract']['code'] = wasm_b64
            elif 'Account' in record and record['Account'].get('account_id') == contract_account:
                d['records'][i]['Account']['account']['code_hash']     = code_hash
                d['records'][i]['Account']['account']['storage_usage'] = len(wasm_bytes)

    with open(genesis_path, 'w') as f:
        json.dump(d, f, separators=(',', ':'))
    print(f"Updated: {genesis_path}")
PYEOF
```

---

## Step 5: Start `neard`

Delete any previous chain data and start fresh:

```shell
rm -rf ~/.near/mpc-localnet/data
neard --home ~/.near/mpc-localnet run &
```

Wait ~5 seconds, then verify the chain is running:

```shell
curl -s localhost:3030/status | python3 -c \
  "import sys,json; d=json.load(sys.stdin); print('chain_id:', d['chain_id']); print('protocol:', d['protocol_version'])"
# Expected: chain_id: mpc-localnet, protocol: 82
```

**Note**: Set the near-cli-rs network config once (this writes to `~/.config/near-cli/config.toml`):

```shell
$NEAR config add-connection \
  --network-name mpc-localnet \
  --connection-name mpc-localnet \
  --rpc-url http://localhost:3030 \
  --wallet-url http://localhost:4000 \
  --explorer-transaction-url http://localhost:9001/transactions/
```

---

## Step 6: Create participant accounts

Export the validator key:

```shell
export VALIDATOR_KEY=$(cat ~/.near/mpc-localnet/validator_key.json \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['secret_key'])")
export NODE_PUBKEY=$(cat ~/.near/mpc-localnet/node_key.json \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['public_key'])")
```

Create accounts:

```shell
$NEAR account create-account fund-myself frodo.test.near '100 NEAR' \
  autogenerate-new-keypair save-to-keychain \
  sign-as test.near network-config mpc-localnet \
  sign-with-plaintext-private-key "$VALIDATOR_KEY" send

$NEAR account create-account fund-myself sam.test.near '100 NEAR' \
  autogenerate-new-keypair save-to-keychain \
  sign-as test.near network-config mpc-localnet \
  sign-with-plaintext-private-key "$VALIDATOR_KEY" send
```

---

## Step 7: Initialize MPC node directories

```shell
rm -rf ~/.near/mpc-frodo ~/.near/mpc-sam

mpc-node init --dir ~/.near/mpc-frodo \
  --chain-id mpc-localnet \
  --genesis ~/.near/mpc-localnet/genesis.json \
  --boot-nodes "$NODE_PUBKEY@0.0.0.0:24566"

mpc-node init --dir ~/.near/mpc-sam \
  --chain-id mpc-localnet \
  --genesis ~/.near/mpc-localnet/genesis.json \
  --boot-nodes "$NODE_PUBKEY@0.0.0.0:24566"
```

Copy the correct genesis (with embedded contract) to both nodes:

```shell
cp ~/.near/mpc-localnet/genesis.json ~/.near/mpc-frodo/genesis.json
cp ~/.near/mpc-localnet/genesis.json ~/.near/mpc-sam/genesis.json
```

Remove validator keys (MPC nodes are not validators):

```shell
rm ~/.near/mpc-frodo/validator_key.json
rm ~/.near/mpc-sam/validator_key.json
```

Configure unique ports:

```shell
RPC_PORT=3031 INDEXER_PORT=24568 \
  jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' \
  ~/.near/mpc-frodo/config.json > ~/.near/mpc-frodo/temp.json \
  && mv ~/.near/mpc-frodo/temp.json ~/.near/mpc-frodo/config.json

RPC_PORT=3032 INDEXER_PORT=24569 \
  jq '.network.addr = "0.0.0.0:" + env.INDEXER_PORT | .rpc.addr = "0.0.0.0:" + env.RPC_PORT' \
  ~/.near/mpc-sam/config.json > ~/.near/mpc-sam/temp.json \
  && mv ~/.near/mpc-sam/temp.json ~/.near/mpc-sam/config.json
```

Create `config.yaml` for Frodo:

```shell
cat > ~/.near/mpc-frodo/config.yaml << 'EOF'
my_near_account_id: frodo.test.near
near_responder_account_id: frodo.test.near
number_of_responder_keys: 1
web_ui: 127.0.0.1:8081
migration_web_ui: 127.0.0.1:8079
pprof_bind_address: 127.0.0.1:34001
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
foreign_chains:
  bitcoin:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: esplora
        rpc_url: "https://bitcoin-rpc.publicnode.com"
        auth:
          kind: none
  abstract:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: standard
        rpc_url: "https://api.testnet.abs.xyz"
        auth:
          kind: none
  starknet:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: standard
        rpc_url: "https://starknet-rpc.publicnode.com"
        auth:
          kind: none
EOF
```

Create `config.yaml` for Sam:

```shell
cat > ~/.near/mpc-sam/config.yaml << 'EOF'
my_near_account_id: sam.test.near
near_responder_account_id: sam.test.near
number_of_responder_keys: 1
web_ui: 127.0.0.1:8082
migration_web_ui: 127.0.0.1:8078
pprof_bind_address: 127.0.0.1:34002
triple:
  concurrency: 2
  desired_triples_to_buffer: 128
  timeout_sec: 60
  parallel_triple_generation_stagger_time_sec: 1
presignature:
  concurrency: 4
  desired_presignatures_to_buffer: 64
  timeout_sec: 60
signature:
  timeout_sec: 60
indexer:
  validate_genesis: false
  sync_mode: Latest
  concurrency: 1
  mpc_contract_id: mpc-contract.test.near
  finality: optimistic
ckd:
  timeout_sec: 60
cores: 4
foreign_chains:
  bitcoin:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: esplora
        rpc_url: "https://bitcoin-rpc.publicnode.com"
        auth:
          kind: none
  abstract:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: standard
        rpc_url: "https://api.testnet.abs.xyz"
        auth:
          kind: none
  starknet:
    timeout_sec: 30
    max_retries: 3
    providers:
      public:
        api_variant: standard
        rpc_url: "https://starknet-rpc.publicnode.com"
        auth:
          kind: none
EOF
```

---

## Step 8: Start MPC nodes

Create a file with an arbitrary image hash (required by the binary, set to any valid hex string):

```shell
mkdir -p /tmp/mpc-hash
echo "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" \
  > /tmp/mpc-hash/LATEST_ALLOWED_HASH_FILE.txt
```

Start Frodo:

```shell
RUST_LOG=info mpc-node start \
  --home-dir ~/.near/mpc-frodo/ \
  11111111111111111111111111111111 \
  --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" \
  --latest-allowed-hash-file /tmp/mpc-hash/LATEST_ALLOWED_HASH_FILE.txt \
  local > /tmp/frodo.log 2>&1 &
```

Start Sam:

```shell
RUST_LOG=info mpc-node start \
  --home-dir ~/.near/mpc-sam/ \
  11111111111111111111111111111111 \
  --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" \
  --latest-allowed-hash-file /tmp/mpc-hash/LATEST_ALLOWED_HASH_FILE.txt \
  local > /tmp/sam.log 2>&1 &
```

Wait ~10 seconds, then verify both nodes are running:

```shell
curl -s localhost:8081/public_data | python3 -m json.tool
curl -s localhost:8082/public_data | python3 -m json.tool
```

You should see `near_signer_public_key`, `near_p2p_public_key`, and
`near_responder_public_keys` for each node. The `neard` stats log should also show
`2 peers`.

You will see repeated errors like:

```
ERROR mpc: error reading config from chain: HostError(GuestPanic { panic_msg: "Calling default not allowed." })
```

This is expected and disappears once the contract is initialized in Step 10.

---

## Step 9: Add access keys to participant accounts

```shell
export FRODO_PUBKEY=$(curl -s localhost:8081/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_signer_public_key'])")
export FRODO_RESPONDER_KEY=$(curl -s localhost:8081/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_responder_public_keys'][0])")
export SAM_PUBKEY=$(curl -s localhost:8082/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_signer_public_key'])")
export SAM_RESPONDER_KEY=$(curl -s localhost:8082/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_responder_public_keys'][0])")

$NEAR account add-key frodo.test.near grant-full-access \
  use-manually-provided-public-key "$FRODO_PUBKEY" \
  network-config mpc-localnet sign-with-keychain send

$NEAR account add-key frodo.test.near grant-full-access \
  use-manually-provided-public-key "$FRODO_RESPONDER_KEY" \
  network-config mpc-localnet sign-with-keychain send

$NEAR account add-key sam.test.near grant-full-access \
  use-manually-provided-public-key "$SAM_PUBKEY" \
  network-config mpc-localnet sign-with-keychain send

$NEAR account add-key sam.test.near grant-full-access \
  use-manually-provided-public-key "$SAM_RESPONDER_KEY" \
  network-config mpc-localnet sign-with-keychain send
```

---

## Step 10: Initialize the MPC contract

```shell
export FRODO_P2P_KEY=$(curl -s localhost:8081/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_p2p_public_key'])")
export SAM_P2P_KEY=$(curl -s localhost:8082/public_data \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['near_p2p_public_key'])")
export MPC_HOST=localhost

envsubst < docs/localnet/args/init.json > /tmp/init_args.json
cat /tmp/init_args.json  # verify substitutions look correct
```

Call `init` on the contract:

```shell
$NEAR contract call-function as-transaction mpc-contract.test.near init \
  file-args /tmp/init_args.json \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '0 NEAR' \
  sign-as mpc-contract.test.near \
  network-config mpc-localnet \
  sign-with-keychain send
```

Verify the contract state is `Running`:

```shell
$NEAR contract call-function as-read-only mpc-contract.test.near state \
  json-args '{}' network-config mpc-localnet now 2>&1 | grep -E "Running|Initializ"
```

---

## Step 11: Add signature domains

Both nodes must vote to add each domain. The checked-in `add_domain.json` configures
four domains: Secp256k1 (Sign), Ed25519 (Sign), Bls12381 (CKD), Secp256k1 (ForeignTx).

```shell
$NEAR contract call-function as-transaction mpc-contract.test.near vote_add_domains \
  file-args docs/localnet/args/add_domain.json \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send

$NEAR contract call-function as-transaction mpc-contract.test.near vote_add_domains \
  file-args docs/localnet/args/add_domain.json \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

Wait ~30 seconds for the nodes to complete DKG across all domains, then confirm the
contract switches from `Initializing` to `Running`:

```shell
$NEAR contract call-function as-read-only mpc-contract.test.near state \
  json-args '{}' network-config mpc-localnet now 2>&1 \
  | grep -E "Running|Initializ|scheme|epoch_id" | head -10
```

### Adding the Dilithium domain (optional)

To also add a Dilithium domain (id=4, for post-quantum signatures):

```shell
cat > /tmp/add_dilithium_domain.json << 'EOF'
{
  "domains": [
    {
      "id": 4,
      "scheme": "Dilithium",
      "purpose": "Sign"
    }
  ]
}
EOF

$NEAR contract call-function as-transaction mpc-contract.test.near vote_add_domains \
  file-args /tmp/add_dilithium_domain.json \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as frodo.test.near network-config mpc-localnet sign-with-keychain send

$NEAR contract call-function as-transaction mpc-contract.test.near vote_add_domains \
  file-args /tmp/add_dilithium_domain.json \
  prepaid-gas '300.0 Tgas' attached-deposit '0 NEAR' \
  sign-as sam.test.near network-config mpc-localnet sign-with-keychain send
```

Check the MPC node logs for confirmation:

```shell
grep "Dilithium key generation completed" /tmp/frodo.log
```

The master Dilithium public key (2592 bytes, base58) will also appear in the contract
state under `domain_id: 4`.

---

## Step 12: Test signature requests

### ECDSA (Secp256k1, domain 0)

```shell
$NEAR contract call-function as-transaction mpc-contract.test.near sign \
  file-args docs/localnet/args/sign_ecdsa.json \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '100 yoctoNEAR' \
  sign-as frodo.test.near \
  network-config mpc-localnet \
  sign-with-keychain send
```

Expected response:

```json
{
  "big_r": { "affine_point": "03..." },
  "recovery_id": 1,
  "s": { "scalar": "..." },
  "scheme": "Secp256k1"
}
```

### EdDSA (Ed25519, domain 1)

```shell
$NEAR contract call-function as-transaction mpc-contract.test.near sign \
  file-args docs/localnet/args/sign_eddsa.json \
  prepaid-gas '300.0 Tgas' \
  attached-deposit '100 yoctoNEAR' \
  sign-as frodo.test.near \
  network-config mpc-localnet \
  sign-with-keychain send
```

---

## Restarting the network

If you restart your Mac or kill the processes, restart in this order:

```shell
# 1. neard (waits for existing data, no --reset needed)
neard --home ~/.near/mpc-localnet run &

# 2. Frodo
RUST_LOG=info mpc-node start \
  --home-dir ~/.near/mpc-frodo/ \
  11111111111111111111111111111111 \
  --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" \
  --latest-allowed-hash-file /tmp/mpc-hash/LATEST_ALLOWED_HASH_FILE.txt \
  local > /tmp/frodo.log 2>&1 &

# 3. Sam
RUST_LOG=info mpc-node start \
  --home-dir ~/.near/mpc-sam/ \
  11111111111111111111111111111111 \
  --image-hash "8b40f81f77b8c22d6c777a6e14d307a1d11cb55ab83541fbb8575d02d86a74b0" \
  --latest-allowed-hash-file /tmp/mpc-hash/LATEST_ALLOWED_HASH_FILE.txt \
  local > /tmp/sam.log 2>&1 &
```

The contract, accounts, domains, and keys are persisted in `~/.near/mpc-localnet/data/`
and `~/.near/mpc-frodo/` / `~/.near/mpc-sam/`. No re-initialization is needed.

---

## Port reference

| Service          | Port  |
|------------------|-------|
| neard RPC        | 3030  |
| neard P2P        | 24566 |
| frodo RPC        | 3031  |
| frodo P2P        | 24568 |
| frodo web_ui     | 8081  |
| sam RPC          | 3032  |
| sam P2P          | 24569 |
| sam web_ui       | 8082  |

---

## Known issues / limitations

| Issue | Notes |
|-------|-------|
| `413 Payload Too Large` when deploying contract via CLI | Contract must be embedded in genesis. See Step 4. |
| `CompilationError(PrepareError(Deserialization))` in neard | WASM contains bulk-memory ops. Use `wasm-opt --llvm-memory-copy-fill-lowering`. See Step 3. |
| `neard` panics with `Failed to find EpochConfig for protocol version 82` | Happens if `protocol_version` in genesis is set to 83. Keep it at 81. |
| Dilithium `register_dilithium_key` returns key `null` | The real indexer in `crates/node/src/indexer/real.rs` does not yet emit Dilithium key registration events to MPC nodes. Master key DKG works; derived key DKG requires indexer integration. |
| `Transaction has expired` from near-cli-rs | Cross-contract calls (e.g., `register_dilithium_key`) can exceed the 60s near-cli-rs timeout. The transaction may still have landed on-chain — check `get_dilithium_derived_key_info` afterwards. |

---

## Dilithium — current state of implementation

| Feature | Status |
|---------|--------|
| Dilithium dependency in contract WASM | Removed (stub verification, nodes verify off-chain) |
| Master Dilithium key DKG | ✅ Works end-to-end |
| Dilithium domain in contract | ✅ Works |
| `register_dilithium_key` contract call | ✅ Contract logic works |
| Derived key DKG triggered from chain event | ❌ Not wired in real indexer yet |
| Dilithium signing flow | ❌ Requires derived key first |
