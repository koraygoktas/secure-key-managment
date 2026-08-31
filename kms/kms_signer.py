"""
kms_signer.py
==============

AWS KMS içinde yaşayan ve ORADAN HİÇBİR ZAMAN ÇIKMAYAN bir private key ile
Ethereum işlemlerini imzalamanın temel mantığı.

Bunun "bulut secret manager / KMS" satırı olmasının sebebi: KMS key'i
`KeyUsage=SIGN_VERIFY` ve `KeySpec=ECC_SECG_P256K1` (Ethereum'un kullandığı
secp256k1 eğrisi) ile oluşturuluyor. KMS senin için ECDSA imzası hesaplıyor
ve açık anahtarı (public key) veriyor, ama private key'i asla dışarı
vermiyor -- sana da, AWS destek ekibine de, kimseye. Erişim tamamen IAM
policy ile kontrol ediliyor ve her Sign çağrısı CloudTrail'e (AWS'nin
denetim logu) düşüyor.

Bu modül, bir KMS asimetrik imzalama anahtarını geçerli bir Ethereum
imzalayıcısına dönüştüren (yaygın kullanılan, dokümante edilmiş) tekniği
uyguluyor:

  1. KMS'in döndürdüğü DER-encoded public key'den Ethereum adresini türet.
  2. KMS'ten, imzasız bir işlemin keccak256 hash'ini imzalamasını iste
     (MessageType="DIGEST", SigningAlgorithm="ECDSA_SHA_256").
  3. KMS, DER-encoded bir ECDSA imzası (r, s) döndürür. Ethereum DER
     imzası kullanmaz -- ham (r, s) artı bir recovery id (`v`) ister, ve
     sadece "low-s" imzaları kabul eder (EIP-2). O yüzden:
       a. DER'i çözüp (r, s)'i çıkarıyoruz.
       b. Gerekirse s'yi eğri mertebesinin alt yarısına normalize ediyoruz.
       c. İki olası recovery id'yi (0/1) deneyip hangisinin gerçekten
          bizim KMS-türetilmiş adresimize geri kurtarıldığını buluyoruz.
  4. (v, r, s)'i işleme ekleyip broadcast için RLP encode ediyoruz.

Bu modülde hiçbir zaman gerçek private key materyali okunmuyor,
yazdırılmıyor ya da saklanmıyor.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import utils as crypto_utils
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    load_der_public_key,
)
from eth_keys.datatypes import Signature as EthKeysSignature
from eth_utils import keccak, to_checksum_address

# secp256k1 eğrisinin mertebesi (n)
SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP256K1_HALF_N = SECP256K1_N // 2


class KmsSigningError(RuntimeError):
    """KMS'in döndürdüğü imza geçerli bir Ethereum imzasına dönüştürülemediğinde
    fırlatılır (doğru yapılandırılmış bir ECC_SECG_P256K1 KMS key'i için bu
    hiç olmamalı; olursa bunu görmezden gelinecek bir şey değil, bir bug
    olarak ele alın)."""


@dataclass(frozen=True)
class EthSignature:
    v: int  # 0 ya da 1 (yParity) -- eski 27/28 formatı DEĞİL
    r: int
    s: int


def eth_address_from_der_public_key(der_public_key: bytes) -> str:
    """KMS'in GetPublicKey çağrısının döndürdüğü DER-encoded
    SubjectPublicKeyInfo'yu checksum'lı bir Ethereum adresine çevirir.

    Ethereum adresleri, keccak256(sıkıştırılmamış EC noktası, baştaki 0x04
    prefix'i olmadan) değerinin son 20 byte'ıdır.
    """
    public_key = load_der_public_key(der_public_key)
    uncompressed = public_key.public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
    if uncompressed[0] != 0x04:
        raise KmsSigningError("sıkıştırılmamış bir EC noktası bekleniyordu (0x04 prefix)")
    point_bytes = uncompressed[1:]  # 0x04'ü at, geriye 32 byte X || 32 byte Y kalır
    address_bytes = keccak(point_bytes)[-20:]
    return to_checksum_address(address_bytes)


def der_signature_to_rs(der_signature: bytes) -> tuple[int, int]:
    """DER-encoded bir ECDSA imzasını (hem KMS'in hem çoğu HSM'in döndürdüğü
    format) ham (r, s) tam sayı bileşenlerine çözer."""
    r, s = crypto_utils.decode_dss_signature(der_signature)
    return r, s


def normalize_low_s(s: int) -> int:
    """Ethereum (EIP-2 sonrası) sadece s değeri eğri mertebesinin alt
    yarısında olan imzaları kabul ediyor. (r, s) ve (r, n - s) imzaları
    aynı mesaj/anahtar için matematiksel olarak ikisi de geçerli, o yüzden
    KMS bize "high-s" bir imza verirse yeniden imzalatmadan onu çeviriyoruz."""
    return SECP256K1_N - s if s > SECP256K1_HALF_N else s


def recover_signature_with_v(
    digest: bytes, r: int, s: int, expected_address: str
) -> EthSignature:
    """Bir mesaj hash'i ve `expected_address`'in private key'i tarafından
    üretildiğini bildiğimiz (low-s) bir (r, s) çifti verildiğinde, hangi
    recovery id'nin (0 ya da 1) doğru olduğunu ikisini de deneyip hangisinin
    beklenen adrese geri kurtarıldığını kontrol ederek buluyoruz.

    KMS bize recovery id'yi söylemiyor (bu bir Ethereum/Bitcoin kavramı,
    genel ECDSA'nın parçası değil), o yüzden her KMS tabanlı Ethereum
    imzalayıcı bu aynı "iki değeri de dene" adımını yapmak zorunda.
    """
    expected = expected_address.lower()
    for candidate_v in (0, 1):
        sig = EthKeysSignature(vrs=(candidate_v, r, s))
        try:
            recovered_pubkey = sig.recover_public_key_from_msg_hash(digest)
        except Exception:
            continue
        if recovered_pubkey.to_checksum_address().lower() == expected:
            return EthSignature(v=candidate_v, r=r, s=s)

    raise KmsSigningError(
        "KMS imzasından beklenen adres kurtarılamadı; "
        "key gerçekten ECC_SECG_P256K1 SIGN_VERIFY tipinde mi?"
    )


def kms_signature_to_eth_signature(
    der_signature: bytes, digest: bytes, expected_address: str
) -> EthSignature:
    """Tam boru hattı: DER imza (KMS'ten) -> low-s normalize edilmiş ->
    recovery id çözülmüş -> bir Ethereum işlemine gömülmeye hazır."""
    r, s = der_signature_to_rs(der_signature)
    s = normalize_low_s(s)
    return recover_signature_with_v(digest, r, s, expected_address)


def get_eth_address_from_kms(kms_client, key_id: str) -> str:
    """Bir KMS key'inin public key'ini alır ve Ethereum adresini türetir.
    Hiçbir private key materyaline dokunmaz -- GetPublicKey salt-okunur,
    gizli olmayan bir KMS API çağrısıdır."""
    response = kms_client.get_public_key(KeyId=key_id)
    key_spec = response.get("KeySpec")
    if key_spec != "ECC_SECG_P256K1":
        raise KmsSigningError(
            f"KMS key {key_id} icin KeySpec={key_spec!r}, beklenen "
            "'ECC_SECG_P256K1' (Ethereum'un kullandigi secp256k1 egrisi)"
        )
    return eth_address_from_der_public_key(response["PublicKey"])


def sign_digest_with_kms(kms_client, key_id: str, digest: bytes, expected_address: str) -> EthSignature:
    """KMS'ten `digest`'i (zaten imzasız işlemin 32 byte'lık keccak256
    hash'i olmalı) imzalamasını ister ve sonucu Ethereum uyumlu bir
    (v, r, s) imzasına çevirir."""
    if len(digest) != 32:
        raise KmsSigningError(f"digest 32 byte olmali, {len(digest)} geldi")

    response = kms_client.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm="ECDSA_SHA_256",
    )
    der_signature = response["Signature"]
    return kms_signature_to_eth_signature(der_signature, digest, expected_address)