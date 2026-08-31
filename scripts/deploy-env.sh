set -euo pipefail
cd "$(dirname "$0")/.."

if [ -f .env ]; then
  set -a
  source .env
  set +a
fi

: "${PRIVATE_KEY:?PRIVATE_KEY'i .env içinde ayarla (.env.example'a bak). Sadece değersiz bir testnet anahtarı kullan.}"
RPC_URL="${1:-${SEPOLIA_RPC_URL:-http://127.0.0.1:8545}}"

echo "==> .env PRIVATE_KEY ile (güvensiz temel yöntem) $RPC_URL adresine deploy ediliyor"
forge script script/Deploy.s.sol:Deploy \
  --rpc-url "$RPC_URL" \
  --private-key "$PRIVATE_KEY" \
  --broadcast \
  -vvvv