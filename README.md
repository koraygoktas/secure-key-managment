# Secure Key Management Demo (Foundry)

A working Foundry project comparing four private-key storage methods for
smart contract deployment, going beyond keeping a plaintext key in a
`.env` file: **Cast Keystore (encrypted JSON)**, **Hardware Wallet
(Ledger)**, and **Cloud KMS (AWS KMS)** — all deploying the same contract,
through the same deploy logic, with a different signer each time.

This isn't a hypothetical example: the `.env`, keystore, and KMS methods
were all run end-to-end against a local Anvil chain and verified on-chain
(KMS was tested with a stand-in that mimics real AWS). Below is everything
that came out of building it, including a real Foundry footgun that was
hit and fixed along the way.

## Table of contents

- [Why this project exists](#why-this-project-exists)
- [Security level comparison](#security-level-comparison)
- [The demo contract: SecretCommitmentRegistry](#the-demo-contract-secretcommitmentregistry)
- [Setup](#setup)
- [Method 1 — .env (insecure baseline)](#method-1--env-insecure-baseline)
- [Method 2 — Cast Keystore / Encrypted JSON](#method-2--cast-keystore--encrypted-json)
- [Method 3 — Hardware Wallet (Ledger)](#method-3--hardware-wallet-ledger)
- [Method 4 — Cloud KMS (AWS KMS)](#method-4--cloud-kms-aws-kms)
- [Important Foundry footgun: wrong owner without --sender](#important-foundry-footgun-wrong-owner-without---sender)
- [Tests](#tests)
- [Project structure](#project-structure)

## Why this project exists

The most common "security hole" in Ethereum development isn't the contract
code — it's the deploy process: dropping a private key into a `.env` file
and reading it with `vm.envUint("PRIVATE_KEY")`. That's fine on a local
test chain; on mainnet or in a shared CI environment it's a real risk — the
file can be committed by accident, a dependency's postinstall script can
read it, any process running as your user can access it in plaintext.

This project shows four different security levels without ever changing
the deploy script itself (`script/Deploy.s.sol`) — only the signer changes.

## Security level comparison

| Method | Security Level | Best Suited For |
|---|---|---|
| `.env` File | Low – Medium | Local testing and worthless testnet faucet accounts |
| Cast Keystore / Encrypted JSON | High | Local professional development & testnet/mainnet deployments |
| Hardware Wallet (Ledger, etc.) | Highest | Live mainnet deployments and fund transfers |
| Cloud Secret Manager / KMS | High | Server-side bots, backend APIs, and CI/CD pipelines |

Each row in this project is implemented as its own `scripts/deploy-*.sh`
(or `kms/deploy_with_kms.py` for KMS).

## The demo contract: SecretCommitmentRegistry

`src/SecretCommitmentRegistry.sol` is deliberately small, because this
project isn't really about the contract — it's about **how the key that
deploys/manages the contract is stored**. Still, the contract follows the
same principle at its own scale: no plaintext "secret" is ever written
on-chain. The owner publishes a `keccak256` **commitment** to a secret;
anyone can later prove they know it by revealing it (`verify`) and having
it match the commitment — without the secret ever touching state. This is
the classic "commit-reveal" pattern used across many on-chain systems,
from voting to sealed bids.

```solidity
function setCommitment(bytes32 key, bytes32 commitmentHash) external onlyOwner;
function verify(bytes32 key, bytes calldata revealedSecret) external view returns (bool);
function revoke(bytes32 key) external onlyOwner;
function transferOwnership(address newOwner) external onlyOwner;
```

All 14 tests (11 unit + 1 fuzz test, 256 runs) pass via `forge test`.

## Setup

```bash
# If Foundry isn't installed (requires Git Bash or WSL — PowerShell/cmd are not supported):
curl -L https://getfoundry.sh/install | bash
source ~/.bashrc
foundryup

git clone <this-repo> secure-key-management
cd secure-key-management
forge build
forge test

cp .env.example .env   # only needed for RPC URLs and Method 1
```

## Method 1 — `.env` (insecure baseline)

```bash
# Put ONLY a worthless testnet key in .env
./scripts/deploy-env.sh http://127.0.0.1:8545
```

The private key sits in plaintext on disk, in the shell's process
environment, and (if you ever exported it manually) in shell history.
Use this **only** for local Anvil testing and disposable faucet accounts.

## Method 2 — Cast Keystore / Encrypted JSON

One-time setup (once per machine):

```bash
cast wallet import my-deployer --interactive
cast wallet address --account my-deployer   # write this into DEPLOYER_ADDRESS in .env
```

Deploy:

```bash
./scripts/deploy-keystore.sh my-deployer http://127.0.0.1:8545
```

The private key is only decrypted into memory for the duration of a single
`forge`/`cast` call, when you type the password.

## Method 3 — Hardware Wallet (Ledger)

```bash
cast wallet address --ledger   # write this into DEPLOYER_ADDRESS in .env
./scripts/deploy-ledger.sh http://127.0.0.1:8545
```

The private key **never leaves** the device's secure element. You confirm
the transaction details on the device's own screen.

## Method 4 — Cloud KMS (AWS KMS)

Foundry doesn't natively support KMS signers, so this method is implemented
by a standalone Python script, `kms/deploy_with_kms.py`.

```bash
aws kms create-key \
  --key-usage SIGN_VERIFY \
  --key-spec ECC_SECG_P256K1 \
  --description "eth-deployer-prod"

pip install -r kms/requirements.txt
forge build
./scripts/deploy-kms.sh https://sepolia.infura.io/v3/<project-id>
```

### How it works

1. **Address derivation:** KMS's `GetPublicKey` call returns a DER-encoded
   public key, from which the Ethereum address is derived via keccak256.
2. **Hash to sign:** the transaction is built with `eth_account`'s
   `TypedTransaction` class, and its unsigned keccak256 hash is taken (per
   the EIP-1559 spec).
3. **Signing with KMS:** `kms.sign(..., MessageType="DIGEST",
   SigningAlgorithm="ECDSA_SHA_256")` — the private key never leaves AWS's
   HSM boundary; this script only ever sees a DER-encoded `(r, s)`
   signature.
4. **DER → Ethereum signature:** Ethereum doesn't want the DER format KMS
   returns — it wants raw `(r, s)` plus a recovery id (`v`), and per EIP-2
   it only accepts "low-s" signatures. So the DER is decoded, `s` is
   normalized if needed, and both possible recovery ids (`0`/`1`) are
   tried to find which one recovers back to the KMS-derived address.
5. **Broadcast:** `(v, r, s)` is attached to the transaction, RLP-encoded,
   and sent via `eth_sendRawTransaction`.

### Verifying without real AWS

```bash
python kms/test_signing_logic.py
```

While building this project, the entirety of `kms/deploy_with_kms.py` was
run end-to-end against a local Anvil chain using a fake KMS client — the
deployed contract's `owner()` matched the KMS-derived address exactly.

## Important Foundry footgun: wrong owner without `--sender`

A real bug was hit and fixed while building this project — worth sharing
here because it fails silently:

When using `--account` (keystore) or `--ledger` with `forge script`, if
**`--sender` isn't given explicitly**, the script's simulation (dry-run)
phase uses Foundry's default test address
(`0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38`) as `msg.sender` — not the
real signer. Because the deploy script computes its constructor argument
(`owner = msg.sender`) during that simulation phase, the deployed
contract's owner can end up set to Foundry's default test address **even
though the transaction itself is signed and broadcast with your real
keystore/Ledger key** — with no error message at all.

`scripts/deploy-keystore.sh` and `scripts/deploy-ledger.sh` in this repo
enforce `--sender`. In short: **whenever you use `--account` or
`--ledger`, always pass the real signer's address explicitly via
`--sender`.**

## Tests

```bash
forge test -vv                      # 14 Solidity tests (11 unit + 1 fuzz, 256 runs)
python kms/test_signing_logic.py    # KMS signing pipeline (no AWS required)
```

## Project structure
src/SecretCommitmentRegistry.sol Demo contract (commit-reveal pattern)
test/SecretCommitmentRegistry.t.sol Foundry tests
script/Deploy.s.sol Single deploy script shared by 3 of the 4 methods
scripts/deploy-env.sh Method 1 (.env)
scripts/deploy-keystore.sh Method 2 (encrypted keystore)
scripts/deploy-ledger.sh Method 3 (Ledger)
scripts/deploy-kms.sh Method 4 (AWS KMS) — calls kms/deploy_with_kms.py
kms/kms_signer.py DER→Ethereum signature conversion logic
kms/deploy_with_kms.py Full KMS deploy flow (boto3 + JSON-RPC)
kms/test_signing_logic.py Verifies the KMS signing logic without real AWS
.env.example Example environment variables (real .env is never committed)


## License
MIT