#!/usr/bin/env bash
# Infinity Remote - build Linux (Flutter) dentro do container infinity-remote-build:linux.
#
# No host (raiz do repo):
#   docker build -t infinity-remote-build:linux -f build-env/docker/Dockerfile.linux .github/patches
#   C=$HOME/.cache/infinity-remote-build
#   docker run --rm --cpus=3 --memory=12g -u $(id -u):$(id -g) \
#     -v "$PWD":/workspace -v "$C":/cache -v "$C/vcpkg-installed":/opt/vcpkg/installed \
#     infinity-remote-build:linux bash build-env/docker/build-linux.sh [homolog]
#
# Etapas: vcpkg (manifest) -> ponte flutter_rust_bridge 1.80.1 -> cargo (features do
# workflow) -> python3 build.py --flutter --skip-cargo (gera infinity-remote-<versão>.deb).
set -euo pipefail

ENV_NAME="${1:-homolog}"
cd /workspace

export CARGO_HOME=/cache/cargo
export PATH=/cache/cargo/bin:/opt/cargo/bin:/opt/flutter/bin:$PATH
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-3}"
export VCPKG_MAX_CONCURRENCY="${VCPKG_MAX_CONCURRENCY:-3}"
export CARGO_INCREMENTAL=0
export DEB_ARCH=amd64
mkdir -p "$CARGO_HOME" "$HOME" "$PUB_CACHE" "$VCPKG_DEFAULT_BINARY_CACHE" "$VCPKG_DOWNLOADS"
# cargo/rustup instalados na imagem; o CARGO_HOME do volume só guarda registry/git.
[ -e "$CARGO_HOME/bin" ] || ln -s /opt/cargo/bin "$CARGO_HOME/bin"

# Servidor e chave embutidos (option_env! em tempo de compilação).
set -a
# shellcheck disable=SC1090
. "build-env/${ENV_NAME}.env"
set +a
for v in RENDEZVOUS_SERVER RS_PUB_KEY API_SERVER; do
  [ -n "${!v:-}" ] || { echo "ERRO: ${v} vazio em build-env/${ENV_NAME}.env"; exit 1; }
done
echo "== env de build: ${ENV_NAME} (RENDEZVOUS_SERVER=${RENDEZVOUS_SERVER}; API_SERVER=${API_SERVER})"

t0=$(date +%s)
step() { echo; echo "== [$(( $(date +%s) - t0 ))s] $*"; }

step "vcpkg install (x64-linux, manifest)"
"$VCPKG_ROOT/vcpkg" install --triplet x64-linux --x-install-root="$VCPKG_ROOT/installed"

step "ponte flutter_rust_bridge"
if [ ! -f src/bridge_generated.rs ] || [ src/flutter_ffi.rs -nt src/bridge_generated.rs ]; then
  (cd flutter && flutter pub get)
  flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
    --dart-output ./flutter/lib/generated_bridge.dart \
    --c-output ./flutter/macos/Runner/bridge_generated.h
  cp ./flutter/macos/Runner/bridge_generated.h ./flutter/ios/Runner/bridge_generated.h
fi

step "cargo build (hwcodec,flutter,unix-file-copy-paste)"
cargo build --locked --lib --features hwcodec,flutter,unix-file-copy-paste --release

step "flutter build linux + .deb"
python3 ./build.py --flutter --skip-cargo

step "fim"
ls -la infinity-remote-*.deb flutter/build/linux/x64/release/bundle/
