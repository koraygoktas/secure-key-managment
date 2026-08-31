set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

ACCOUNT_NAME="${1:?Kullanım: $0 <keystore-hesap-adi> [rpc-url]}"
RPC_URL="${2:-${SEPOLIA_RPC_URL:-http://127.0.0.1:8545}}"

: "${DEPLOYER_ADDRESS:?.env içinde DEPLOYER_ADDRESS'i keystore hesabının adresine ayarla (calistir: cast wallet address --account $ACCOUNT_NAME). Bu gizli değil -- sadece Foundry'nin simülasyonunun gerçek imzalayanla eşleşmesi için kullanılıyor.}"

echo "==> Şifreli keystore '$ACCOUNT_NAME' ($DEPLOYER_ADDRESS) ile $RPC_URL adresine deploy ediliyor"
echo "    Keystore parolası sorulacak."

forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" \
  --account "$ACCOUNT_NAME" \
  --sender "$DEPLOYER_ADDRESS" \
  --broadcast \
  -vvvv