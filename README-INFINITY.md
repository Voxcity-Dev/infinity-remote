# Infinity Remote

Fork do [RustDesk](https://github.com/rustdesk/rustdesk) rebrandado para a Vox (épico VoxPlan #34133).

- **Repositório:** https://github.com/Voxcity-Dev/infinity-remote, branch de trabalho `infinity/main`.
- **Origem:** `upstream` = https://github.com/rustdesk/rustdesk, tag `1.4.9` (commit `6c578292e`).
- **Submódulo `libs/hbb_common`:** publicado em
  https://github.com/Voxcity-Dev/infinity-remote-hbb-common, branch `infinity/main`. O
  `.gitmodules` aponta para ele.
- **Licença:** AGPL-3.0, igual ao upstream (`LICENCE` intacto). Quem distribuir o binário
  precisa oferecer o código-fonte correspondente; o campo `Homepage` do `.deb` aponta para
  este repositório.

## Como clonar

```bash
git clone --recurse-submodules -b infinity/main https://github.com/Voxcity-Dev/infinity-remote
# clone já feito sem os submódulos:
git submodule update --init --recursive
```

## O que mudou em relação ao upstream

| Item | Onde |
|---|---|
| Nome `Infinity Remote` (`APP_NAME`) | `libs/hbb_common/src/config.rs` |
| Esquema `infinity-remote://` (espaço do nome vira hífen) | `src/common.rs` (`get_uri_prefix`), `src/core_main.rs` |
| Identificador Linux `infinity-remote` (binário, pacote, serviço systemd, `.desktop`, `/usr/share/infinity-remote`, `/etc/infinity-remote`, `pam.d`) | `src/common.rs` (`get_app_slug`), `flutter/linux/CMakeLists.txt` (`BINARY_NAME`), `build.py` (`linux_slug`), `res/DEBIAN/*`, `src/platform/linux.rs` |
| Título da janela | `flutter/linux/my_application.cc` |
| `.desktop` e unidade systemd do Linux | `res/infinity-remote.desktop`, `res/infinity-remote-link.desktop`, `res/infinity-remote.service` |
| Servidor e chave pública via build (`option_env!`) | `libs/hbb_common/src/config.rs` (`RENDEZVOUS_SERVER`, `RS_PUB_KEY`) |
| URL da API via build (`API_SERVER`; vazio = `http://<RENDEZVOUS_SERVER>:21114`) | `src/common.rs` (`get_api_server_`) |
| Ícone placeholder (∞ `#9ac31c` sobre `#020817`) | `res/infinity/`, `res/*.png`, `res/icon.ico`, `res/scalable.svg`, `flutter/assets/icon.svg` |
| Pacote `.deb`: nome, mantenedor, descrição e `Homepage` | `build.py` (`generate_control_file`) |

O `APPLICATION_ID` Flutter (`com.carriez.flutter_hbb`) continua o do upstream de propósito.
Os arquivos `res/rustdesk*.desktop` e `res/rustdesk.service` também continuam no repo, mas o
`.deb` Flutter não os usa.

## Pacote suportado

Só o **`.deb` Flutter** (Linux x64) é suportado. RPM (`res/rpm*.spec`), AppImage
(`appimage/`), Arch (`res/PKGBUILD`), Flatpak (`flatpak/`) e o `.deb` sciter ainda usam os
nomes `rustdesk` e ficaram fora depois do rename: não foram ajustados nem testados.

## Ambientes de build

`build-env/<ambiente>.env` guarda as variáveis lidas em tempo de compilação. Hoje só existe
`homolog.env`:

| Variável | Valor |
|---|---|
| `RENDEZVOUS_SERVER` | `186.237.58.169` (hbbs da homolog) |
| `RS_PUB_KEY` | chave **pública** do hbbs (não é segredo) |
| `API_SERVER` | vazio, a definir; vazio = `http://<RENDEZVOUS_SERVER>:21114` |

Sem as variáveis o binário cai nos servidores públicos do RustDesk.

## Como buildar (Linux, Flutter) — container

O caminho suportado é a imagem `build-env/docker/Dockerfile.linux` (ubuntu:22.04, Rust 1.75,
Flutter 3.24.5 com o patch de `.github/patches`, vcpkg `120deac3062162151622ca4860575a33844ba10b`,
flutter_rust_bridge_codegen 1.80.1) e o script `build-env/docker/build-linux.sh`. Na raiz do repo:

```bash
# imagem (contexto = .github/patches, só para o patch do Flutter)
docker build -t infinity-remote-build:linux -f build-env/docker/Dockerfile.linux .github/patches

# build; o argumento é o nome do ambiente em build-env/ (padrão: homolog)
C=$HOME/.cache/infinity-remote-build
docker run --rm --cpus=3 --memory=12g -u $(id -u):$(id -g) \
  -v "$PWD":/workspace -v "$C":/cache -v "$C/vcpkg-installed":/opt/vcpkg/installed \
  infinity-remote-build:linux bash build-env/docker/build-linux.sh homolog
```

Limites: o container roda com `--cpus=3 --memory=12g`, e o script usa `CARGO_BUILD_JOBS=3` e
`VCPKG_MAX_CONCURRENCY=3` (dá para sobrescrever pelas variáveis de mesmo nome). O cache de
cargo, vcpkg e pub fica em `~/.cache/infinity-remote-build`.

Etapas do script: carrega `build-env/<ambiente>.env` → `vcpkg install` (triplet `x64-linux`,
manifest) → ponte flutter_rust_bridge (só se `src/flutter_ffi.rs` mudou) →
`cargo build --locked --lib --features hwcodec,flutter,unix-file-copy-paste --release` →
`python3 build.py --flutter --skip-cargo`.

A imagem é ubuntu:22.04 (o workflow do upstream usa 18.04), então o `.deb` exige
glibc >= 2.35 (Ubuntu 22.04+ / Debian 12+).

Artefatos, na raiz do repo:

- `flutter/build/linux/x64/release/bundle/infinity-remote` (binário)
- `infinity-remote-<versão>.deb`
