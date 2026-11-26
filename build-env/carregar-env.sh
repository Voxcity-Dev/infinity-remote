# Infinity Remote - carrega e confere build-env/<ambiente>.env (homolog | prod).
# Fonte única do servidor, da chave pública e da API embutidos no programa
# (option_env! em libs/hbb_common/src/config.rs e src/common.rs).
#
# Uso (sempre com ".", de dentro da raiz do repo):
#   . build-env/carregar-env.sh prod
# Sai com RENDEZVOUS_SERVER, RS_PUB_KEY e API_SERVER exportadas, ou falha (return 1)
# sem exportar nada. Não imprime valores, só tamanhos: o log do Actions do fork é público.

infinity_carregar_env() {
  local amb="${1:-}" arq
  case "$amb" in
    homolog|prod) ;;
    *) echo "ERRO: ambiente '${amb}' inválido (use homolog ou prod)" >&2; return 1 ;;
  esac
  arq="build-env/${amb}.env"
  [ -f "$arq" ] || { echo "ERRO: ${arq} não existe (rode da raiz do repo)" >&2; return 1; }

  # lê num subshell: um arquivo incompleto não deixa variável pela metade no chamador
  local rv pk api
  { IFS= read -r rv; IFS= read -r pk; IFS= read -r api; } < <(
    unset RENDEZVOUS_SERVER RS_PUB_KEY API_SERVER
    # shellcheck disable=SC1090
    . "./${arq}"
    printf '%s\n%s\n%s\n' "${RENDEZVOUS_SERVER:-}" "${RS_PUB_KEY:-}" "${API_SERVER:-}"
  )

  [ -n "$rv" ] || { echo "ERRO: RENDEZVOUS_SERVER vazio em ${arq}" >&2; return 1; }
  [ -n "$pk" ] || { echo "ERRO: RS_PUB_KEY vazio em ${arq} (a de prod nasce na 1ª subida do hbbs de prod)" >&2; return 1; }
  [ -n "$api" ] || { echo "ERRO: API_SERVER vazio em ${arq} (sem ele o cliente cai em http://<rendezvous>:21114)" >&2; return 1; }
  # chave pública ed25519 do hbbs: 32 bytes em base64 = 43 caracteres + "="
  [[ "$pk" =~ ^[A-Za-z0-9+/]{43}=$ ]] || {
    echo "ERRO: RS_PUB_KEY de ${arq} não tem a forma de chave pública do hbbs (base64 de 32 bytes)" >&2; return 1; }
  # a API do Infinity só por HTTPS (o cliente recusa http:, src/infinity.rs)
  case "$api" in https://*) ;; *) echo "ERRO: API_SERVER de ${arq} tem de começar com https://" >&2; return 1 ;; esac

  if [ "$amb" = prod ]; then
    # prod pelo nome, nunca pelo IP: o host é provisório (#34137)
    [[ "$rv" =~ ^[0-9.:]+$ ]] && { echo "ERRO: RENDEZVOUS_SERVER de prod é IP; use o nome (remote.voxcity.com.br)" >&2; return 1; }
    # chave do homolog copiada para prod = programa de prod que não fala com o hbbs de prod
    local pk_h
    pk_h=$(sed -n 's/^RS_PUB_KEY=//p' build-env/homolog.env 2>/dev/null | tail -1)
    [ "$pk" != "$pk_h" ] || { echo "ERRO: RS_PUB_KEY de prod é igual à do homolog" >&2; return 1; }
  fi

  export RENDEZVOUS_SERVER="$rv" RS_PUB_KEY="$pk" API_SERVER="$api"
  echo "== env de build: ${amb} (RENDEZVOUS_SERVER len=${#rv}; RS_PUB_KEY len=${#pk}; API_SERVER len=${#api})"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  echo "ERRO: use com '.': . build-env/carregar-env.sh <homolog|prod>" >&2
  exit 1
fi
infinity_carregar_env "$@"
