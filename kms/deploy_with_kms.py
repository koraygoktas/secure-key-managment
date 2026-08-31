#!/usr/bin/env python
"""
deploy_with_kms.py
===================

SecretCommitmentRegistry'yi imzalayıcı olarak bir AWS KMS asimetrik
anahtarını kullanarak deploy eder. Private key hiçbir zaman KMS'ten
çıkmaz -- bu script sadece DER-encoded bir public key ve DER-encoded
imzalar görür.

Ön koşullar
-----------
1. `forge build` çalıştırılmış olmalı (bu script, bytecode'u
   out/SecretCommitmentRegistry.sol/SecretCommitmentRegistry.json'dan okur).
2. Şu özelliklerde bir AWS KMS asimetrik imzalama anahtarı olmalı:
       KeyUsage = SIGN_VERIFY
       KeySpec  = ECC_SECG_P256K1
   Oluşturmak için:
       aws kms create-key \\
         --key-usage SIGN_VERIFY \\
         --key-spec ECC_SECG_P256K1 \\
         --description "eth-deployer-prod"
3. AWS kimlik bilgilerinin (env değişkenleri / profile / instance role)
   o key üzerinde kms:GetPublicKey ve kms:Sign izni olmalı -- ve tercihen
   başka hiçbir şey.
4. pip install -r kms/requirements.txt

Kullanım
--------
    python kms/deploy_with_kms.py \\
        --key-id alias/eth-deployer-prod \\
        --rpc-url https://sepolia.infura.io/v3/<project-id>

Burada bilerek "PRIVATE_KEY env değişkeni" yedeği YOK: gerçek bir KMS key'i
için AWS kimlik bilgilerin yapılandırılmamışsa, çalıştırman gereken script
bu değil (diğer üç yöntem için scripts/deploy-*.sh dosyalarına bak).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from urllib.request import Request, urlopen

from eth_abi import encode as abi_encode
from eth_account.typed_transactions import TypedTransaction
from eth_utils import to_bytes, to_checksum_address, to_int

sys.path.insert(0, str(Path(__file__).resolve().parent))
from kms_signer import get_eth_address_from_kms, sign_digest_with_kms

REPO_ROOT = Path(__file__).resolve().parent.parent
ARTIFACT_PATH = REPO_ROOT / "out" / "SecretCommitmentRegistry.sol" / "SecretCommitmentRegistry.json"


def rpc_call(rpc_url: str, method: str, params: list) -> object:
    payload = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = Request(rpc_url, data=payload, headers={"Content-Type": "application/json"})
    with urlopen(req, timeout=30) as resp:
        body = json.loads(resp.read())
    if "error" in body:
        raise RuntimeError(f"RPC hatasi ({method}): {body['error']}")
    return body["result"]


def load_creation_bytecode() -> bytes:
    if not ARTIFACT_PATH.exists():
        raise SystemExit(
            f"Derlenmis artifact bulunamadi: {ARTIFACT_PATH}.\n"
            "Once proje kok klasorunde `forge build` calistir."
        )
    artifact = json.loads(ARTIFACT_PATH.read_text())
    bytecode_hex = artifact["bytecode"]["object"]
    return to_bytes(hexstr=bytecode_hex)


def build_deployment_data(owner_address: str) -> bytes:
    creation_code = load_creation_bytecode()
    constructor_args = abi_encode(["address"], [owner_address])
    return creation_code + constructor_args


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--key-id", required=True, help="KMS key id ya da alias, orn. alias/eth-deployer-prod")
    parser.add_argument("--rpc-url", required=True, help="Broadcast icin JSON-RPC endpoint")
    parser.add_argument("--gas-limit", type=int, default=600_000)
    parser.add_argument("--priority-fee-gwei", type=float, default=1.5)
    parser.add_argument("--max-fee-gwei", type=float, default=None, help="Varsayilan: guncel base fee'nin 2 kati + priority fee")
    parser.add_argument("--dry-run", action="store_true", help="Islemi kur ve imzala ama broadcast etme")
    args = parser.parse_args()

    import boto3  # burada import ediliyor ki boto3 kurulu olmasa bile --help calissin

    kms_client = boto3.client("kms")

    print(f"[1/6] KMS key {args.key_id} icin Ethereum adresi turetiliyor ...")
    deployer_address = get_eth_address_from_kms(kms_client, args.key_id)
    print(f"      Deployer / gelecekteki owner: {deployer_address}")

    print("[2/6] Zincir durumu okunuyor (chainId, nonce, base fee) ...")
    chain_id = to_int(hexstr=rpc_call(args.rpc_url, "eth_chainId", []))
    nonce = to_int(hexstr=rpc_call(args.rpc_url, "eth_getTransactionCount", [deployer_address, "pending"]))
    latest_block = rpc_call(args.rpc_url, "eth_getBlockByNumber", ["pending", False])
    base_fee = to_int(hexstr=latest_block["baseFeePerGas"]) if latest_block.get("baseFeePerGas") else to_int(hexstr=rpc_call(args.rpc_url, "eth_gasPrice", []))
    priority_fee = int(args.priority_fee_gwei * 1e9)
    max_fee = int(args.max_fee_gwei * 1e9) if args.max_fee_gwei else base_fee * 2 + priority_fee
    print(f"      chainId={chain_id} nonce={nonce} baseFee={base_fee/1e9:.3f} gwei maxFee={max_fee/1e9:.3f} gwei")

    print("[3/6] Imzasiz EIP-1559 kontrat-olusturma islemi kuruluyor ...")
    deployment_data = build_deployment_data(deployer_address)
    unsigned_tx = {
        "type": 2,
        "chainId": chain_id,
        "nonce": nonce,
        "maxPriorityFeePerGas": priority_fee,
        "maxFeePerGas": max_fee,
        "gas": args.gas_limit,
        "to": b"",  # bos `to` = kontrat olusturma
        "value": 0,
        "data": deployment_data,
        "accessList": [],
    }
    typed_tx = TypedTransaction.from_dict(unsigned_tx)
    signing_hash = typed_tx.hash()
    print(f"      Imzalanacak hash: 0x{signing_hash.hex()}")

    print(f"[4/6] KMS key {args.key_id} icin imza isteniyor (anahtar materyali AWS disina cikmiyor) ...")
    eth_sig = sign_digest_with_kms(kms_client, args.key_id, signing_hash, deployer_address)
    print(f"      v={eth_sig.v} (recovery id yerel olarak cozuldu; r,s KMS'ten geldi)")

    print("[5/6] Imzali ham islem birlestiriliyor ...")
    signed_tx_dict = {**unsigned_tx, "v": eth_sig.v, "r": eth_sig.r, "s": eth_sig.s}
    signed_typed_tx = TypedTransaction.from_dict(signed_tx_dict)
    raw_tx = signed_typed_tx.encode()
    raw_tx_hex = "0x" + raw_tx.hex()

    if args.dry_run:
        print("[6/6] --dry-run verildi: broadcast edilmiyor. Imzali ham islem:")
        print(f"      {raw_tx_hex}")
        return

    print("[6/6] eth_sendRawTransaction ile broadcast ediliyor ...")
    tx_hash = rpc_call(args.rpc_url, "eth_sendRawTransaction", [raw_tx_hex])
    print(f"      tx hash: {tx_hash}")

    print("      Receipt bekleniyor ...")
    receipt = None
    for _ in range(60):
        receipt = rpc_call(args.rpc_url, "eth_getTransactionReceipt", [tx_hash])
        if receipt is not None:
            break
        time.sleep(2)

    if receipt is None:
        print("      2 dakika sonra hala pending -- bir explorer'da tx hash'i kontrol et.")
        return

    contract_address = to_checksum_address(receipt["contractAddress"])
    status = to_int(hexstr=receipt["status"])
    print(f"      status={'success' if status == 1 else 'FAILED'}  contractAddress={contract_address}")


if __name__ == "__main__":
    main()