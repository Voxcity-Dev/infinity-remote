# Infinity Remote

Fork do [RustDesk](https://github.com/rustdesk/rustdesk) rebrandado para a Vox (épico VoxPlan #34133).

- **Origem:** `upstream` = https://github.com/rustdesk/rustdesk, tag `1.4.9` (commit `6c578292e`).
  Branch de trabalho: `infinity/main`. O submódulo `libs/hbb_common` tem commits locais na
  branch `infinity/main` dele (ainda não publicados: sem remote próprio até o GO do dono).
- **Licença:** AGPL-3.0, igual ao upstream (`LICENCE` intacto). Quem distribuir o binário
  precisa oferecer o código-fonte correspondente.

## O que mudou em relação ao upstream

| Item | Onde |
|---|---|
| Nome `Infinity Remote` (`APP_NAME`) | `libs/hbb_common/src/config.rs` |
| Esquema `infinity-remote://` (espaço do nome vira hífen) | `src/common.rs` (`get_uri_prefix`), `src/core_main.rs` |
| Título da janela e `.desktop` do Linux | `flutter/linux/my_application.cc`, `res/rustdesk.desktop`, `res/rustdesk-link.desktop` |
| Servidor e chave pública via build (`option_env!`) | `libs/hbb_common/src/config.rs` (`RENDEZVOUS_SERVER`, `RS_PUB_KEY`) |
| URL da API via build (`API_SERVER`; vazio = `http://<RENDEZVOUS_SERVER>:21114`) | `src/common.rs` (`get_api_server_`) |
| Ícone placeholder (∞ `#9ac31c` sobre `#020817`) | `res/infinity/`, `res/*.png`, `res/icon.ico`, `res/scalable.svg`, `flutter/assets/icon.svg` |

Identificadores internos (binário `rustdesk`, pacote, serviço systemd, `com.carriez.flutter_hbb`)
continuam os do upstream de propósito.

## Ambientes de build

`build-env/<ambiente>.env` guarda as variáveis lidas em tempo de compilação. Hoje só existe
`homolog.env` (`RENDEZVOUS_SERVER=186.237.58.169`, chave pública do hbbs). Sem as variáveis o
binário cai nos servidores públicos do RustDesk.

## Como buildar (Linux, Flutter)

Versões do `.github/workflows/flutter-build.yml`: Rust 1.75, Flutter 3.24.5 (com
`.github/patches/flutter_3.24.4_dropdown_menu_enableFilter.diff`), vcpkg
`120deac3062162151622ca4860575a33844ba10b`, flutter_rust_bridge_codegen 1.80.1.
Pacotes apt: os da etapa "Build rustdesk" do job `build-rustdesk-linux` do workflow.

```bash
export VCPKG_ROOT=~/vcpkg PATH=~/flutter/bin:$PATH
$VCPKG_ROOT/vcpkg install --triplet x64-linux --x-install-root=$VCPKG_ROOT/installed
# bridge (uma vez, ou quando src/flutter_ffi.rs mudar)
cargo install flutter_rust_bridge_codegen --version 1.80.1 --features uuid --locked
(cd flutter && flutter pub get)
flutter_rust_bridge_codegen --rust-input ./src/flutter_ffi.rs \
  --dart-output ./flutter/lib/generated_bridge.dart \
  --c-output ./flutter/macos/Runner/bridge_generated.h
# build com o servidor do ambiente
set -a; . build-env/homolog.env; set +a
CARGO_BUILD_JOBS=3 nice -n 10 python3 build.py --flutter
```

Artefato: `flutter/build/linux/x64/release/bundle/rustdesk` e `rustdesk-<versão>.deb`.
