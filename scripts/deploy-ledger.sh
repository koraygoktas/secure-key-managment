set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

RPC_URL="${1:-${SEPOLIA_RPC_URL:-http://127.0.0.1:8545}}"

: "${DEPLOYER_ADDRESS:?.env icinde DEPLOYER_ADDRESS'i ayarla, ya da calistir: cast wallet address --ledger}"

echo "==> Ledger donanım cüzdanı ($DEPLOYER_ADDRESS) ile $RPC_URL adresine deploy ediliyor"
echo "    İstendiğinde işlemi cihaz ekranında onayla."

forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" \
  --ledger \
  --sender "$DEPLOYER_ADDRESS" \
  --broadcast \
  -vvvv

# Farklı bir türetme yolu (derivation path) ya da birden fazla Ledger hesabı
# kullanıyorsan ekle:
#   --mnemonic-derivation-paths "m/44'/60'/0'/0/0"