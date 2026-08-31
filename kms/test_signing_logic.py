#!/usr/bin/env python
"""
test_signing_logic.py
======================

kms_signer.py'deki KMS imzalama boru hattını GERÇEK bir AWS hesabı ya da
gerçek bir KMS key'i olmadan doğrular.

Bu projenin zor kısmı "boto3.client('kms') çağır" değil -- asıl zor kısım,
KMS'in verdiği şeyi (recovery id olmadan, ham public key üzerinden
DER-encoded bir ECDSA imzası) doğru şekilde geçerli, low-s bir Ethereum
imzasına çevirmek. Bu mantık -- DER çözme, low-s normalizasyonu, recovery-id
arama -- saf matematik, gerçek AWS gerektirmiyor.

Bu test, `ecdsa` paketiyle (bilerek eth-* yığınından ayrı tutulan) yerel
olarak üretilmiş bir secp256k1 anahtar çiftine dayanan sahte bir "KMS
istemcisi" kuruyor. Bu sahte istemci, projenin kullandığı iki KMS
çağrısını taklit ediyor:

    get_public_key(KeyId=...) -> {"PublicKey": <DER SPKI bytes>, "KeySpec": ...}
    sign(KeyId=..., Message=..., MessageType=..., SigningAlgorithm=...)
        -> {"Signature": <DER (r,s) bytes>}

ve bunu gerçek deploy script'inin kullandığı aynı kms_signer.py
fonksiyonlarından uçtan uca geçiriyor:

    1. sahte "KMS" public key'inden bir Ethereum adresi türet
    2. sahte "KMS" private key'iyle bir işlem-hash'i şeklinde bir digest'i imzala
    3. DER -> low-s -> recovery-id boru hattımızı çalıştır
    4. eth_account'un bağımsız olarak aynı adresi (v, r, s)'den geri
       kurtardığını doğrula -- yani gerçek bir Ethereum node'u bu imzayı
       kabul ederdi.

Çalıştır: python kms/test_signing_logic.py
"""

from __future__ import annotations

import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from ecdsa import SECP256k1, SigningKey
from eth_account import Account
from eth_utils import keccak, to_checksum_address

from kms_signer import (
    SECP256K1_N,
    eth_address_from_der_public_key,
    kms_signature_to_eth_signature,
)


class FakeKmsClient:
    """boto3'ün KMS istemcisinin yerine geçiyor. Bu process dışına hiç
    çıkmayan gerçek bir secp256k1 anahtar çiftine dayanıyor -- tıpkı gerçek
    KMS key'inin AWS dışına hiç çıkmadığı gibi."""

    def __init__(self):
        self._signing_key = SigningKey.generate(curve=SECP256k1)
        self._verifying_key = self._signing_key.get_verifying_key()

    def get_public_key(self, KeyId: str):
        assert KeyId == "fake-key-id"
        x = self._verifying_key.pubkey.point.x()
        y = self._verifying_key.pubkey.point.y()
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
        der_bytes = public_numbers.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        return {"PublicKey": der_bytes, "KeySpec": "ECC_SECG_P256K1"}

    def sign(self, KeyId: str, Message: bytes, MessageType: str, SigningAlgorithm: str):
        assert KeyId == "fake-key-id"
        assert MessageType == "DIGEST"
        assert SigningAlgorithm == "ECDSA_SHA_256"
        assert len(Message) == 32

        r, s, _order = self._signing_key.sign_digest(
            Message, sigencode=lambda r, s, order: (r, s, order), k=None
        )
        der_signature = encode_dss_signature(r, s)
        return {"Signature": der_signature}


def main() -> None:
    print("[1/5] Sahte bir KMS anahtar çifti üretiliyor (process dışına çıkmıyor, gerçek KMS gibi) ...")
    kms = FakeKmsClient()

    print("[2/5] (Sahte) KMS public key'inden Ethereum adresi türetiliyor ...")
    pubkey_response = kms.get_public_key(KeyId="fake-key-id")
    address = eth_address_from_der_public_key(pubkey_response["PublicKey"])
    print(f"      Turetilen adres: {address}")

    print("[3/5] Gerçekçi 32 byte'lık bir digest oluşturuluyor (bir işlem hash'iymiş gibi) ...")
    fake_tx_payload = b"deploy(SecretCommitmentRegistry, owner=" + address.encode() + b")" + secrets.token_bytes(8)
    digest = keccak(fake_tx_payload)
    print(f"      digest = 0x{digest.hex()}")

    print("[4/5] Sahte KMS'e digest'i imzalatıp kms_signer.py'den geçiriliyor ...")
    successes = 0
    trials = 25
    for _ in range(trials):
        sign_response = kms.sign(
            KeyId="fake-key-id", Message=digest, MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256"
        )
        eth_sig = kms_signature_to_eth_signature(sign_response["Signature"], digest, address)

        assert eth_sig.v in (0, 1), f"v 0 ya da 1 olmali, {eth_sig.v} geldi"
        assert eth_sig.s <= SECP256K1_N // 2, "imza low-s degil"

        recovered = Account._recover_hash(
            digest, vrs=(eth_sig.v + 27, eth_sig.r, eth_sig.s)
        )
        assert to_checksum_address(recovered) == address, (
            f"eth_account {recovered} kurtardi, beklenen {address}"
        )
        successes += 1

    print(f"      {successes}/{trials} imza, KMS-türetilmiş adrese geri kurtarılabilen "
          f"geçerli low-s Ethereum imzası olarak doğrulandı.")

    print("[5/5] Tüm kontroller geçti. kms/deploy_with_kms.py tarafından kullanılan")
    print("      DER -> low-s -> recovery-id boru hattı, gerçek bir Ethereum node'unun")
    print("      kabul edeceği imzalar üretiyor -- gerçek AWS kimlik bilgisi olmadan.")


if __name__ == "__main__":
    main()