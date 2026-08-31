#!/usr/bin/env bash
# ==============================================================================
# Yöntem 4/4: Bulut Secret Manager / KMS (AWS KMS) -- Güvenlik Düzeyi: Yüksek
#
# Private key AWS KMS'in İÇİNDE üretiliyor (KeySpec=ECC_SECG_P256K1) ve
# dışa aktarılamaz olarak işaretleniyor -- KMS'in HSM destekli sınırının
# dışına hiç çıkmıyor, AWS'nin kendisi için bile. Bu process (ya da herhangi
# bir geliştiricinin laptopu) sadece bir public key ve, istek üzerine, bir
# imza görüyor.
#
# forge/cast KMS imzalayıcılarını native desteklemiyor, o yüzden bu yöntem
# boto3 ile KMS'e konuşan ve imzalı işlemi elle birleştiren bağımsız bir
# Python script'iyle (kms/deploy_with_kms.py) hallediliyor. İmzalama mantığı
# için kms/kms_signer.py'ye, gerçek AWS olmadan doğruluk kontrolü için
# kms/test_signing_logic.py'ye bak.
#
# Uygun olduğu yer: sunucu taraflı botlar, backend API'ler, işlemleri
# gözetimsiz imzalaması gereken CI/CD hatları -- bir insanın donanım
# cüzdanına dokunmasının mümkün olmadığı ama yine de .env'de ham bir
# anahtar istemediğin her yer. Erişim IAM policy ile kontrol ediliyor ve
# her Sign çağrısı CloudTrail'e düşüyor.
#
# Ön koşullar:
#   pip install -r kms/requirements.txt
#   forge build            (kms/deploy_with_kms.py'nin bytecode'u okuyabilmesi için)
#   AWS kimlik bilgileri yapılandırılmış olmalı (aws configure / SSO /
#   instance role), hedef key üzerinde kms:GetPublicKey + kms:Sign izniyle.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

RPC_URL="${1:-${SEPOLIA_RPC_URL:?Ilk argüman olarak bir RPC URL ver ya da .env'de SEPOLIA_RPC_URL'i ayarla}}"
: "${KMS_KEY_ID:?.env icinde KMS_KEY_ID'yi ayarla, orn. alias/eth-deployer-prod}"

forge build

python kms/deploy_with_kms.py \
  --key-id "$KMS_KEY_ID" \
  --rpc-url "$RPC_URL" \
  "$@"