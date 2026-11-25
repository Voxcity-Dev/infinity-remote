//! Infinity Remote: o que o fork fala com a API do Infinity além do upstream
//! (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md, "Remote no ticket").
//!
//! - Segredo do computador (`ird_`): pedido com `x-infinity-segredo: novo` no sysinfo,
//!   guardado na config e mandado em sysinfo, heartbeat e auditoria de conexão.
//! - Chave da empresa (`irk_`): colada pelo admin em Configurações (ou no aviso da janela
//!   principal) ou gravada por `--infinity-chave` na instalação em massa. O servidor
//!   (rendezvous, chave pública e API) é sempre o do build: nada disso vem de fora.
//! - Endurecimento: chamada à API do Infinity só com certificado verificado e nunca pelo
//!   desvio TCP do servidor de rendezvous (o upstream faz as duas coisas quando o HTTPS falha:
//!   a primeira com `allow-insecure-tls-fallback`, a segunda por padrão).
//! - Convite (`ric_`): do nome do instalador (Windows) ou do link `infinity-remote://convite/<token>`.
//! - Acesso sem ninguém: o técnico leva a prova (`irp_`) no LoginRequest; o computador com o
//!   consentimento a confere em `/api/autorizar-acesso` (com o segredo).
//!
//! Nenhum valor de chave, segredo, convite, prova ou token vai para log.

#[cfg(not(any(target_os = "android", target_os = "ios")))]
use hbb_common::tokio;
use hbb_common::{
    anyhow::anyhow,
    bail,
    config::{Config, LocalConfig},
    log,
    tls::TlsType,
    ResultType,
};
use serde_json::{json, Map, Value};
use std::time::Duration;

/// Chave de instalação da empresa (`irk_…`). Nunca em log.
pub const OPCAO_CHAVE: &str = "infinity-chave";
/// Troca de empresa pelo caminho elevado (`--infinity-chave` como admin, ou o cartão de
/// Segurança desbloqueado): o serviço grava a chave nova e apaga o segredo, que é pedido de
/// novo. Nunca fica guardada.
pub const OPCAO_TROCA_DE_CHAVE: &str = "infinity-chave-troca";
/// Segredo do computador (`ird_…`). Só o serviço escreve. Nunca em log.
pub const OPCAO_SEGREDO: &str = "infinity-segredo";

/// Convite do ticket (`ric_…`) ainda não entregue ao Infinity.
pub const OPCAO_CONVITE: &str = "infinity-convite";
/// sha256 (hex) do último convite já entregue: o mesmo instalador aberto de novo não o repete.
pub const OPCAO_CONVITE_GASTO: &str = "infinity-convite-gasto";
/// Nome da empresa, quando o Infinity o manda (cabeçalho `x-infinity-empresa`).
pub const OPCAO_EMPRESA: &str = "infinity-empresa";
/// Consentimento "técnicos da empresa acessam sem alguém aqui": "Y", "N" ou vazio (não perguntado).
pub const OPCAO_SEM_NINGUEM: &str = "infinity-acesso-sem-ninguem";
/// Lado do técnico: pedido do ticket (`<rustdesk_id>:<pedido_uuid>`) vindo do link de conexão.
pub const OPCAO_LOCAL_PEDIDO: &str = "infinity-pedido";

pub const CABECALHO_SEGREDO: &str = "x-infinity-segredo";
pub const CABECALHO_EMPRESA: &str = "x-infinity-empresa";
const PEDIDO_DE_SEGREDO: &str = "novo";

pub const PREFIXO_SEGREDO: &str = "ird_";
pub const PREFIXO_CHAVE: &str = "irk_";
pub const PREFIXO_CONVITE: &str = "ric_";
pub const PREFIXO_PROVA: &str = "irp_";
const PREFIXO_TOKEN_TECNICO: &str = "irm_";
/// 32 bytes em base64url sem preenchimento.
const TAMANHO_TOKEN: usize = 43;

const TEMPO_LIMITE: Duration = Duration::from_secs(12);
const TEMPO_LIMITE_PROVA: Duration = Duration::from_secs(6);

#[inline]
fn caractere_de_token(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '-'
}

/// `prefixo` + 43 caracteres base64url, nada mais.
pub fn token_valido(s: &str, prefixo: &str) -> bool {
    s.len() == prefixo.len() + TAMANHO_TOKEN
        && s.starts_with(prefixo)
        && s[prefixo.len()..].chars().all(caractere_de_token)
}

pub fn sha256_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(s.as_bytes());
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// A chave da empresa como o admin a colou (espaços e quebras de linha das pontas fora),
/// se tiver o formato `irk_` + 43 caracteres base64url.
pub fn chave_colada(s: &str) -> Option<String> {
    let s = s.trim();
    if token_valido(s, PREFIXO_CHAVE) {
        Some(s.to_owned())
    } else {
        None
    }
}

/// A chave guardada que vai no sysinfo (valor fora do formato não sai do computador).
pub fn chave() -> Option<String> {
    chave_colada(&Config::get_option(OPCAO_CHAVE))
}

/// O build traz o servidor (RENDEZVOUS_SERVER): rendezvous, relay, chave pública e API não
/// vêm de fora (nome do executável, `--config`, `--option`, `--import-config`, IPC ou
/// registro): as opções `custom-rendezvous-server`, `relay-server`, `key` e `api-server`
/// são ignoradas.
pub fn servidor_so_do_build() -> bool {
    option_env!("RENDEZVOUS_SERVER").map_or(false, |s| !s.trim().is_empty())
}

/// A API do Infinity do build (API_SERVER), se houver: vence qualquer opção `api-server`.
pub fn api_do_build() -> Option<&'static str> {
    option_env!("API_SERVER").filter(|s| !s.trim().is_empty())
}

/// A URL base da API do Infinity (a mesma que o upstream usa para sysinfo e auditoria).
pub fn api_base() -> String {
    crate::common::get_api_server(
        Config::get_option("api-server"),
        Config::get_option("custom-rendezvous-server"),
    )
}

fn prefixo_de_url(base: &str) -> Option<String> {
    let b = sem_porta_padrao(&base.trim().trim_end_matches('/').to_ascii_lowercase());
    if b.is_empty() || crate::common::is_public(&b) {
        None
    } else {
        Some(b)
    }
}

/// A URL vai para a API do Infinity? Confere contra a API do build, a da config deste
/// processo e a que a interface conhece (o processo da interface tem a config sincronizada).
pub fn eh_api_do_infinity(url: &str) -> bool {
    let u = sem_porta_padrao(&url.to_ascii_lowercase());
    let mut bases = vec![api_base()];
    if let Some(s) = option_env!("API_SERVER") {
        bases.push(s.to_owned());
    }
    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    bases.push(crate::ui_interface::get_api_server());
    bases
        .iter()
        .filter_map(|b| prefixo_de_url(b))
        .any(|b| e_da_base(&u, &b))
}

/// `https://host:443/...` é o mesmo destino que `https://host/...`: tira o `:443` explícito
/// (só do host, e só em https) para a comparação com a base.
fn sem_porta_padrao(url: &str) -> String {
    const ESQUEMA: &str = "https://";
    let Some(resto) = url.strip_prefix(ESQUEMA) else {
        return url.to_owned();
    };
    let fim = resto.find(|c| c == '/' || c == '?').unwrap_or(resto.len());
    let (autoridade, caminho) = resto.split_at(fim);
    match autoridade.strip_suffix(":443") {
        Some(host) => format!("{}{}{}", ESQUEMA, host, caminho),
        None => url.to_owned(),
    }
}

/// `url` (minúscula) é a própria base ou um caminho/consulta debaixo dela.
fn e_da_base(url: &str, base: &str) -> bool {
    url == base
        || url.strip_prefix(base).map_or(false, |resto| {
            resto.starts_with('/') || resto.starts_with('?')
        })
}

pub struct Resposta {
    pub status: u16,
    pub corpo: String,
    pub cabecalhos: Vec<(String, String)>,
}

impl Resposta {
    pub fn cabecalho(&self, nome: &str) -> Option<&str> {
        self.cabecalhos
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(nome))
            .map(|(_, v)| v.as_str())
    }
}

/// Cliente HTTP só para a API do Infinity: sem proxy nenhum (nem o socks da config nem o
/// HTTP(S)_PROXY do ambiente), sem seguir redirecionamento (o segredo e o token não saltam
/// de host) e só HTTPS, com o certificado sempre verificado. Falhou montar: erro (nunca cai
/// num cliente padrão, como o `create_http_client*` do upstream faz).
macro_rules! cliente_estrito {
    ($builder:expr, $tls:expr) => {{
        let b = $builder
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true);
        #[cfg(not(any(target_os = "android", target_os = "ios")))]
        let b = match $tls {
            TlsType::NativeTls => b.use_native_tls(),
            _ => b.use_rustls_tls(),
        };
        #[cfg(any(target_os = "android", target_os = "ios"))]
        let b = {
            let _ = $tls;
            match hbb_common::verifier::client_config(false) {
                Ok(c) => b.use_preconfigured_tls(c),
                Err(_) => bail!("TLS da API do Infinity indisponível"),
            }
        };
        b.build()
            .map_err(|_| anyhow!("cliente HTTP da API do Infinity não montou"))?
    }};
}

fn cliente_estrito_async(tls: TlsType) -> ResultType<reqwest::Client> {
    Ok(cliente_estrito!(reqwest::Client::builder(), tls))
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn cliente_estrito_bloqueante(tls: TlsType) -> ResultType<reqwest::blocking::Client> {
    Ok(cliente_estrito!(reqwest::blocking::Client::builder(), tls))
}

/// Chamada à API do Infinity sem os desvios do upstream: só HTTPS, certificado sempre
/// verificado (Rustls e, se o handshake falhar, o TLS nativo do sistema, também verificando),
/// sem proxy, sem redirecionamento e nunca pelo proxy TCP do servidor de rendezvous.
pub async fn requisicao_estrita(
    metodo: &str,
    url: &str,
    corpo: Option<String>,
    cabecalhos: &[(String, String)],
    tempo_limite: Duration,
) -> ResultType<Resposta> {
    if !url.to_ascii_lowercase().starts_with("https://") {
        bail!("A API do Infinity só é chamada por HTTPS");
    }
    let mut ultimo_erro = None;
    for tls in [TlsType::Rustls, TlsType::NativeTls] {
        let cliente = cliente_estrito_async(tls)?;
        let mut req = match metodo.to_ascii_lowercase().as_str() {
            "get" => cliente.get(url),
            "post" => cliente.post(url),
            "put" => cliente.put(url),
            "delete" => cliente.delete(url),
            _ => bail!("Método HTTP não suportado"),
        };
        let mut tem_tipo = false;
        for (k, v) in cabecalhos {
            if k.eq_ignore_ascii_case("content-type") {
                tem_tipo = true;
            }
            req = req.header(k.as_str(), v.as_str());
        }
        if !tem_tipo && corpo.is_some() {
            req = req.header("Content-Type", "application/json");
        }
        if let Some(b) = corpo.clone() {
            req = req.body(b);
        }
        match req.timeout(tempo_limite).send().await {
            Ok(r) => {
                let status = r.status().as_u16();
                let cabecalhos = r
                    .headers()
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_owned()))
                    .collect();
                let corpo = r.text().await?;
                return Ok(Resposta {
                    status,
                    corpo,
                    cabecalhos,
                });
            }
            Err(e) => {
                // Só o tipo do erro: a URL, os cabeçalhos e o corpo não vão para o log.
                let conexao = e.is_connect() || e.is_request();
                log::warn!(
                    "API do Infinity: falha com {:?} (timeout={}, conexão={})",
                    tls,
                    e.is_timeout(),
                    conexao
                );
                ultimo_erro = Some(anyhow!("falha na chamada à API do Infinity"));
                if e.is_timeout() || !conexao {
                    break;
                }
            }
        }
    }
    Err(ultimo_erro.unwrap_or_else(|| anyhow!("falha na chamada à API do Infinity")))
}

/// Cabeçalho "Nome: valor" (formato do `post_request` do upstream) em pares.
fn cabecalho_simples(header: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    if let Some((k, val)) = header.split_once(": ") {
        if !k.is_empty() {
            v.push((k.to_owned(), val.to_owned()));
        }
    }
    v
}

/// O `post_request` do upstream, quando o destino é a API do Infinity.
pub async fn post_estrito(url: &str, corpo: String, header: &str) -> ResultType<String> {
    let r = requisicao_estrita(
        "post",
        url,
        Some(corpo),
        &cabecalho_simples(header),
        TEMPO_LIMITE,
    )
    .await?;
    Ok(r.corpo)
}

/// O `http_request_sync` do upstream (cabeçalhos em JSON, resposta em JSON
/// `{status_code, headers, body}`), quando o destino é a API do Infinity.
pub async fn http_estrito(
    url: &str,
    metodo: &str,
    corpo: Option<String>,
    header_json: &str,
) -> ResultType<String> {
    let mut cabecalhos = Vec::new();
    if !header_json.trim().is_empty() {
        // Cabeçalhos que não são um objeto JSON de textos: falha sem mandar nada (o upstream
        // também recusa em parse_json_header_entries); nunca manda sem o Authorization.
        let Ok(Value::Object(obj)) = serde_json::from_str::<Value>(header_json) else {
            bail!("Cabeçalhos da chamada à API do Infinity inválidos");
        };
        for (k, v) in obj {
            let Some(v) = v.as_str() else {
                bail!("Cabeçalhos da chamada à API do Infinity inválidos");
            };
            cabecalhos.push((k, v.to_owned()));
        }
    }
    let r = requisicao_estrita(metodo, url, corpo, &cabecalhos, TEMPO_LIMITE).await?;
    let mut h = Map::new();
    for (k, v) in r.cabecalhos.iter() {
        h.insert(k.to_lowercase(), json!(v));
    }
    let mut res = Map::new();
    res.insert("status_code".into(), json!(r.status));
    res.insert("headers".into(), Value::Object(h));
    res.insert("body".into(), json!(r.corpo));
    Ok(serde_json::to_string(&res)?)
}

// ───────────────────────── lado do computador atendido ─────────────────────────

/// O segredo guardado, se tiver o formato certo.
pub fn segredo() -> Option<String> {
    let s = Config::get_option(OPCAO_SEGREDO);
    if token_valido(&s, PREFIXO_SEGREDO) {
        Some(s)
    } else {
        None
    }
}

/// O cabeçalho do segredo no formato "Nome: valor" do `post_request` (vazio sem segredo).
pub fn cabecalho_segredo() -> String {
    match segredo() {
        Some(s) => format!("{}: {}", CABECALHO_SEGREDO, s),
        None => String::new(),
    }
}

/// O convite pendente, se válido; um valor estragado é apagado.
pub fn convite_pendente() -> Option<String> {
    let c = Config::get_option(OPCAO_CONVITE);
    if c.is_empty() {
        return None;
    }
    if token_valido(&c, PREFIXO_CONVITE) {
        Some(c)
    } else {
        Config::set_option(OPCAO_CONVITE.to_owned(), "".to_owned());
        None
    }
}

/// O convite saiu do Infinity (aceito ou recusado): não volta a ser mandado.
pub fn convite_entregue(convite: &str) {
    Config::set_option(OPCAO_CONVITE_GASTO.to_owned(), sha256_hex(convite));
    if Config::get_option(OPCAO_CONVITE) == convite {
        Config::set_option(OPCAO_CONVITE.to_owned(), "".to_owned());
    }
}

/// Grava um convite novo (do nome do instalador ou do link). Devolve false se o token
/// é inválido ou já foi entregue.
pub fn gravar_convite(convite: &str) -> bool {
    if !token_valido(convite, PREFIXO_CONVITE) {
        return false;
    }
    if Config::get_option(OPCAO_CONVITE_GASTO) == sha256_hex(convite) {
        return false;
    }
    if Config::get_option(OPCAO_CONVITE) != convite {
        Config::set_option(OPCAO_CONVITE.to_owned(), convite.to_owned());
    }
    true
}

/// O mapa de opções que chega pela IPC (`Data::Options`) vem inteiro da interface e pode
/// estar atrasado em relação ao que o serviço acabou de gravar. O segredo só o serviço
/// escreve: fica com o valor dele (a interface não o cria, troca nem apaga).
///
/// A chave da empresa: com o computador numa empresa (há segredo), a interface não a troca
/// pelo mapa (fica a do serviço). Trocar de empresa só por `OPCAO_TROCA_DE_CHAVE`, que vem
/// do caminho elevado: grava a chave nova e apaga o segredo (o próximo sysinfo pede um
/// novo). A troca com a mesma chave de hoje é ignorada (a interface pode reenviar o mapa).
pub fn preservar_opcoes_do_servico(novas: &mut std::collections::HashMap<String, String>) {
    let manter = |novas: &mut std::collections::HashMap<String, String>, k: &str| {
        let atual = Config::get_option(k);
        if atual.is_empty() {
            novas.remove(k);
        } else {
            novas.insert(k.to_owned(), atual);
        }
    };
    manter(novas, OPCAO_SEGREDO);
    manter(novas, OPCAO_CONVITE_GASTO);
    manter(novas, OPCAO_EMPRESA);
    let gasto = Config::get_option(OPCAO_CONVITE_GASTO);
    if let Some(c) = novas.get(OPCAO_CONVITE) {
        if !c.is_empty() && !gasto.is_empty() && sha256_hex(c) == gasto {
            novas.remove(OPCAO_CONVITE);
        }
    }
    let troca = novas
        .remove(OPCAO_TROCA_DE_CHAVE)
        .and_then(|c| chave_colada(&c));
    let chave_atual = Config::get_option(OPCAO_CHAVE);
    match troca {
        Some(nova) if nova != chave_atual.trim() => {
            novas.insert(OPCAO_CHAVE.to_owned(), nova);
            novas.remove(OPCAO_SEGREDO);
            // O nome e o consentimento eram da empresa antiga: na nova, pergunta de novo.
            novas.remove(OPCAO_EMPRESA);
            novas.remove(OPCAO_SEM_NINGUEM);
            log::info!("Infinity: chave da empresa trocada; o segredo será pedido de novo");
        }
        _ => {
            if segredo().is_some() {
                manter(novas, OPCAO_CHAVE);
            }
        }
    }
}

/// Caminho elevado (`--infinity-chave`): pede ao serviço, só pela IPC, a troca da chave da
/// empresa. Diferente de `ipc::set_option`/`get_options`, não grava a config local deste
/// processo (que guardaria o pedido de troca e o segredo ird_ no arquivo do admin).
#[cfg(not(any(target_os = "android", target_os = "ios")))]
#[tokio::main(flavor = "current_thread")]
pub async fn pedir_troca_de_chave(chave: &str) -> ResultType<()> {
    use crate::ipc::{connect, Data};
    // Lê as opções do serviço direto pela IPC: `ipc::get_options_async` as gravaria na
    // config deste processo (o admin), com o segredo ird_ junto.
    let mut c = connect(1000, "").await?;
    c.send(&Data::Options(None)).await?;
    let Some(Data::Options(Some(mut opcoes))) = c.next_timeout(1000).await? else {
        bail!("O serviço não respondeu");
    };
    opcoes.insert(OPCAO_TROCA_DE_CHAVE.to_owned(), chave.to_owned());
    let mut c = connect(1000, "").await?;
    c.send(&Data::Options(Some(opcoes))).await?;
    c.next_timeout(1000).await.ok();
    Ok(())
}

pub struct RespostaSysinfo {
    pub texto: String,
}

/// POST /api/sysinfo com o segredo (ou o pedido de um novo). Guarda o segredo que vier no
/// cabeçalho da resposta, só se ainda não havia um.
pub async fn post_sysinfo(url: &str, corpo: String) -> ResultType<RespostaSysinfo> {
    let tinha = segredo();
    let valor = tinha
        .clone()
        .unwrap_or_else(|| PEDIDO_DE_SEGREDO.to_owned());
    let r = requisicao_estrita(
        "post",
        url,
        Some(corpo),
        &[(CABECALHO_SEGREDO.to_owned(), valor)],
        TEMPO_LIMITE,
    )
    .await?;
    if tinha.is_none() {
        if let Some(s) = r.cabecalho(CABECALHO_SEGREDO) {
            let s = s.trim();
            if token_valido(s, PREFIXO_SEGREDO) {
                Config::set_option(OPCAO_SEGREDO.to_owned(), s.to_owned());
                log::info!("Infinity: segredo do computador recebido e guardado");
            } else {
                log::warn!("Infinity: cabeçalho de segredo fora do formato, ignorado");
            }
        }
    }
    if let Some(e) = r.cabecalho(CABECALHO_EMPRESA) {
        let nome = nome_de_empresa(e);
        if !nome.is_empty() && Config::get_option(OPCAO_EMPRESA) != nome {
            Config::set_option(OPCAO_EMPRESA.to_owned(), nome);
        }
    }
    Ok(RespostaSysinfo {
        texto: r.corpo.trim().to_owned(),
    })
}
/// O nome da empresa vem codificado em URL (cabeçalho HTTP é ASCII). Texto hostil: sem
/// controle, até 80 caracteres.
fn nome_de_empresa(cru: &str) -> String {
    let decodificado = percent_decode(cru.trim());
    decodificado
        .chars()
        .filter(|c| !c.is_control())
        .take(80)
        .collect::<String>()
        .trim()
        .to_owned()
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            // Pelos bytes: fatiar o &str no meio de um caractere multibyte entra em pânico.
            let hex = std::str::from_utf8(&b[i + 1..i + 3]).ok();
            if let Some(v) = hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                out.push(v);
                i += 3;
                continue;
            }
        }
        out.push(b[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// O consentimento "técnicos da empresa acessam sem alguém aqui" foi dado.
pub fn consentimento_dado() -> bool {
    Config::get_option(OPCAO_SEM_NINGUEM) == "Y"
}

/// Por que o acesso sem ninguém não abriu. `pelo_infinity`: o Infinity respondeu e recusou
/// (ou a prova veio fora do formato); falso = não deu para perguntar (rede, sem API).
pub struct Recusa {
    pub mensagem: String,
    pub pelo_infinity: bool,
}

/// Chegou conexão com prova e o consentimento está dado: o Infinity aprova?
/// Ok(nome do técnico) ou Err(a recusa).
pub async fn autorizar_acesso(peer_id: &str, prova: &str) -> Result<String, Recusa> {
    if !token_valido(prova, PREFIXO_PROVA) {
        return Err(Recusa {
            mensagem: "A prova de acesso do Infinity é inválida.".to_owned(),
            pelo_infinity: true,
        });
    }
    let base = api_base();
    if base.is_empty() {
        return Err(Recusa {
            mensagem: "Este computador não está ligado ao Infinity.".to_owned(),
            pelo_infinity: false,
        });
    }
    let corpo = json!({
        "id": Config::get_id(),
        "uuid": crate::encode64(hbb_common::get_uuid()),
        "prova": prova,
        "peer_id": peer_id,
    })
    .to_string();
    let mut cabecalhos = Vec::new();
    if let Some(s) = segredo() {
        cabecalhos.push((CABECALHO_SEGREDO.to_owned(), s));
    }
    let r = match requisicao_estrita(
        "post",
        &format!("{}/api/autorizar-acesso", base),
        Some(corpo),
        &cabecalhos,
        TEMPO_LIMITE,
    )
    .await
    {
        Ok(r) => r,
        Err(_) => {
            return Err(Recusa {
                mensagem: "Não foi possível falar com o Infinity para autorizar o acesso."
                    .to_owned(),
                pelo_infinity: false,
            })
        }
    };
    let v: Value = serde_json::from_str(&r.corpo).unwrap_or(Value::Null);
    if r.status == 200 && v["permitido"].as_bool() == Some(true) {
        return Ok(v["tecnico"]["nome"].as_str().unwrap_or_default().to_owned());
    }
    let motivo = v["motivo"].as_str().unwrap_or_default().to_owned();
    log::warn!(
        "Infinity: acesso sem ninguém recusado (status {}, motivo {:?})",
        r.status,
        motivo
    );
    let mensagem = v["mensagem"]
        .as_str()
        .map(|s| {
            s.chars()
                .filter(|c| !c.is_control())
                .take(200)
                .collect::<String>()
        })
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| {
            "O Infinity não autorizou o acesso sem alguém no computador.".to_owned()
        });
    // 200 com permitido:false é recusa; outro status (5xx, gateway) é falha de quem responde.
    Err(Recusa {
        mensagem,
        pelo_infinity: r.status == 200,
    })
}

// ───────────────────────────── lado do técnico ─────────────────────────────

pub fn id_do_computador_valido(id: &str) -> bool {
    (6..=12).contains(&id.len()) && id.chars().all(|c| c.is_ascii_digit())
}

fn uuid_valido(s: &str) -> bool {
    s.len() == 36 && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

fn pedido_para(rustdesk_id: &str) -> Option<String> {
    let v = LocalConfig::get_option(OPCAO_LOCAL_PEDIDO);
    let (id, pedido) = v.split_once(':')?;
    if id != rustdesk_id {
        return None;
    }
    LocalConfig::set_option(OPCAO_LOCAL_PEDIDO.to_owned(), "".to_owned());
    if uuid_valido(pedido) {
        Some(pedido.to_owned())
    } else {
        None
    }
}

/// Antes de conectar: o técnico logado no Infinity pede a prova de acesso (vale 2 min, uso
/// único) para este computador. Sem login, computador de outra empresa ou API fora do ar:
/// None, e a conexão segue o fluxo normal (senha ou o Permitir de quem está no PC).
pub async fn pedir_prova(rustdesk_id: &str) -> Option<String> {
    if !id_do_computador_valido(rustdesk_id) {
        return None;
    }
    let token = LocalConfig::get_option("access_token");
    if !token.starts_with(PREFIXO_TOKEN_TECNICO) {
        return None;
    }
    let base = api_base();
    if base.is_empty() {
        return None;
    }
    let mut corpo = json!({ "rustdesk_id": rustdesk_id });
    if let Some(p) = pedido_para(rustdesk_id) {
        corpo["pedido_id"] = json!(p);
    }
    let r = requisicao_estrita(
        "post",
        &format!("{}/api/acessos/prova", base),
        Some(corpo.to_string()),
        &[("Authorization".to_owned(), format!("Bearer {}", token))],
        TEMPO_LIMITE_PROVA,
    )
    .await
    .ok()?;
    if r.status != 200 {
        log::info!(
            "Infinity: sem prova de acesso para esta conexão (status {})",
            r.status
        );
        return None;
    }
    let v: Value = serde_json::from_str(&r.corpo).ok()?;
    let prova = v["prova"].as_str()?.to_owned();
    if token_valido(&prova, PREFIXO_PROVA) {
        log::info!("Infinity: prova de acesso obtida para a conexão");
        Some(prova)
    } else {
        None
    }
}

// ───────────────────── técnico: gravação da sessão (#34141) ─────────────────────
//
// Com a empresa gravando (`GET /api/gravacao/config` → `gravar:true`), o programa do técnico
// grava a sessão inteira numa pasta só dela (`<vídeos>/Infinity/<id>-<início>`), em MP4
// (VP9 pelo `scrap::mp4`, H264/H265 pelo ffmpeg). Ao fim da sessão sobe o arquivo em
// `POST /api/sessoes/:id/gravacao` (multipart, campo `file`) com o token do técnico, pela
// mesma regra estrita da API (HTTPS, certificado verificado, sem proxy nem rendezvous), e
// apaga o arquivo local só depois do 2xx. Recusa (4xx) ou falha: o arquivo fica na pasta.

#[cfg(not(any(target_os = "android", target_os = "ios")))]
pub use gravacao::*;

#[cfg(not(any(target_os = "android", target_os = "ios")))]
mod gravacao {
    use super::*;
    use std::io::Read;
    use std::path::{Path, PathBuf};
    use std::time::Instant;

    const SUFIXO_PARCIAL: &str = ".parcial.mp4";
    const ESPERA_FECHAR: Duration = Duration::from_secs(120);
    const TEMPO_LIMITE_UPLOAD: Duration = Duration::from_secs(60 * 60);
    /// A sessão do core começa antes da 1ª imagem; folga para o relógio dos dois lados.
    const FOLGA_DO_INICIO_SEG: i64 = 120;

    #[derive(Debug, Clone, PartialEq)]
    pub struct ConfigDaGravacao {
        pub gravar: bool,
        pub max_bytes: u64,
    }

    pub(super) fn token_do_tecnico() -> Option<String> {
        let t = LocalConfig::get_option("access_token");
        if t.starts_with(PREFIXO_TOKEN_TECNICO) {
            Some(t)
        } else {
            None
        }
    }

    pub fn ler_config_da_gravacao(corpo: &str) -> Option<ConfigDaGravacao> {
        let v: Value = serde_json::from_str(corpo).ok()?;
        Some(ConfigDaGravacao {
            gravar: v["gravar"].as_bool()?,
            max_bytes: v["max_bytes"].as_u64().unwrap_or(0),
        })
    }

    /// Antes de conectar: a empresa do técnico grava as sessões? Sem login no Infinity ou
    /// API fora do ar: None (não grava pelo Infinity).
    pub async fn config_da_gravacao() -> Option<ConfigDaGravacao> {
        let token = token_do_tecnico()?;
        let base = api_base();
        if base.is_empty() {
            return None;
        }
        let r = requisicao_estrita(
            "get",
            &format!("{}/api/gravacao/config", base),
            None,
            &[("Authorization".to_owned(), format!("Bearer {}", token))],
            TEMPO_LIMITE_PROVA,
        )
        .await
        .ok()?;
        if r.status != 200 {
            log::info!("Infinity: sem configuração de gravação (status {})", r.status);
            return None;
        }
        ler_config_da_gravacao(&r.corpo)
    }

    /// Pasta só desta conexão: `<vídeos>/Infinity/<id do computador>-<início em segundos>`.
    pub fn pasta_da_gravacao(rustdesk_id: &str) -> String {
        let inicio = hbb_common::chrono::Utc::now().timestamp();
        Path::new(&crate::ui_interface::video_save_directory(false))
            .join("Infinity")
            .join(format!("{}-{}", rustdesk_id, inicio))
            .to_string_lossy()
            .to_string()
    }

    fn inicio_da_pasta(pasta: &str) -> Option<i64> {
        let nome = Path::new(pasta).file_name()?.to_str()?;
        nome.rsplit_once('-')?.1.parse().ok()
    }

    /// A sessão do Infinity desta gravação: a do técnico com este computador iniciada mais
    /// perto do início da gravação (e não antes de início − folga). A lista vem de `/api/sessoes/recentes`.
    pub fn escolher_sessao(lista: &str, rustdesk_id: &str, inicio: i64) -> Option<String> {
        let v: Value = serde_json::from_str(lista).ok()?;
        let mut melhor: Option<(i64, String)> = None;
        for s in v.as_array()? {
            if s["rustdesk_id"].as_str() != Some(rustdesk_id) {
                continue;
            }
            let Some(id) = s["id"].as_str().filter(|x| uuid_valido(x)) else {
                continue;
            };
            let Some(quando) = s["iniciada_em"]
                .as_str()
                .and_then(|t| hbb_common::chrono::DateTime::parse_from_rfc3339(t).ok())
                .map(|t| t.timestamp())
            else {
                continue;
            };
            if quando < inicio - FOLGA_DO_INICIO_SEG {
                continue;
            }
            // A mais próxima do início desta gravação: numa reconexão ou com outra aba ao
            // mesmo computador, a mais recente seria a de outra conexão.
            let distancia = (quando - inicio).abs();
            if melhor.as_ref().map_or(true, |(d, _)| distancia < *d) {
                melhor = Some((distancia, id.to_owned()));
            }
        }
        melhor.map(|(_, id)| id)
    }

    /// Os pedaços do multipart (campo `file`, MP4) em volta do arquivo.
    pub fn moldura_multipart(fronteira: &str) -> (String, String) {
        (
            format!(
                "--{}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"gravacao.mp4\"\r\nContent-Type: video/mp4\r\n\r\n",
                fronteira
            ),
            format!("\r\n--{}--\r\n", fronteira),
        )
    }

    fn arquivos(pasta: &Path) -> (Vec<(PathBuf, u64)>, usize) {
        let mut prontos = Vec::new();
        let mut abertos = 0;
        if let Ok(rd) = std::fs::read_dir(pasta) {
            for e in rd.flatten() {
                let nome = e.file_name().to_string_lossy().to_string();
                if nome.ends_with(SUFIXO_PARCIAL) {
                    abertos += 1;
                } else if nome.ends_with(".mp4") {
                    let tamanho = e.metadata().map(|m| m.len()).unwrap_or(0);
                    prontos.push((e.path(), tamanho));
                }
            }
        }
        (prontos, abertos)
    }

    /// Chamada estrita bloqueante (o upload vai em fluxo, sem carregar o arquivo na memória).
    /// `corpo` monta o corpo de novo a cada tentativa de TLS.
    fn requisicao_estrita_bloqueante(
        metodo: &str,
        url: &str,
        cabecalhos: &[(String, String)],
        corpo: &dyn Fn() -> ResultType<Option<reqwest::blocking::Body>>,
        tempo_limite: Duration,
    ) -> ResultType<Resposta> {
        if !url.to_ascii_lowercase().starts_with("https://") {
            bail!("A API do Infinity só é chamada por HTTPS");
        }
        let mut ultimo_erro = None;
        for tls in [TlsType::Rustls, TlsType::NativeTls] {
            let cliente = super::cliente_estrito_bloqueante(tls)?;
            let mut req = match metodo {
                "get" => cliente.get(url),
                "post" => cliente.post(url),
                _ => bail!("Método HTTP não suportado"),
            };
            for (k, v) in cabecalhos {
                req = req.header(k.as_str(), v.as_str());
            }
            if let Some(b) = corpo()? {
                req = req.body(b);
            }
            match req.timeout(tempo_limite).send() {
                Ok(r) => {
                    let status = r.status().as_u16();
                    let corpo = r.text().unwrap_or_default();
                    return Ok(Resposta {
                        status,
                        corpo,
                        cabecalhos: Vec::new(),
                    });
                }
                Err(e) => {
                    let conexao = e.is_connect() || e.is_request();
                    log::warn!(
                        "API do Infinity: falha com {:?} (timeout={}, conexão={})",
                        tls,
                        e.is_timeout(),
                        conexao
                    );
                    ultimo_erro = Some(anyhow!("falha na chamada à API do Infinity"));
                    if e.is_timeout() || !conexao {
                        break;
                    }
                }
            }
        }
        Err(ultimo_erro.unwrap_or_else(|| anyhow!("falha na chamada à API do Infinity")))
    }

    fn mensagem_de_erro(corpo: &str) -> String {
        serde_json::from_str::<Value>(corpo)
            .ok()
            .and_then(|v| v["error"].as_str().map(|s| s.to_owned()))
            .unwrap_or_default()
            .chars()
            .filter(|c| !c.is_control())
            .take(200)
            .collect()
    }

    type Gravador = std::sync::Arc<std::sync::Mutex<Option<scrap::record::Recorder>>>;

    lazy_static::lazy_static! {
        /// Os gravadores vivos de cada pasta (conexão). Fraco: não segura o gravador.
        static ref GRAVADORES: std::sync::Mutex<
            std::collections::HashMap<String, Vec<std::sync::Weak<std::sync::Mutex<Option<scrap::record::Recorder>>>>>,
        > = Default::default();
    }

    /// Guarda o gravador da empresa desta pasta, para o fim da conexão fechá-lo.
    pub fn registrar_gravador(pasta: &str, gravador: &Gravador) {
        let mut g = GRAVADORES.lock().unwrap();
        let v = g.entry(pasta.to_owned()).or_default();
        v.retain(|w| w.strong_count() > 0);
        v.push(std::sync::Arc::downgrade(gravador));
    }

    /// Fim da conexão: fecha os gravadores desta pasta pelo mutex deles. A thread de vídeo do
    /// técnico pode ficar presa depois que a janela da sessão fecha (o upstream não a acorda),
    /// então não dá para esperar que ela troque o gravador: fechado aqui, o `.parcial.mp4`
    /// vira `.mp4`. Um quadro que chegue depois não grava (o gravador já é None).
    pub fn fechar_gravadores(pasta: &str) {
        let fracos = GRAVADORES.lock().unwrap().remove(pasta).unwrap_or_default();
        for w in fracos {
            if let Some(g) = w.upgrade() {
                let antigo = g.lock().unwrap().take();
                drop(antigo); // Drop do gravador: finaliza o MP4 e renomeia
            }
        }
    }

    /// Fim da conexão: sobe a gravação desta pasta numa thread própria (a do io_loop acaba).
    pub fn enviar_gravacao_ao_fim(rustdesk_id: String, pasta: String) {
        std::thread::spawn(move || {
            if let Err(e) = enviar_gravacao(&rustdesk_id, &pasta) {
                log::warn!("Infinity: gravação não enviada: {}", e);
            }
        });
    }

    fn enviar_gravacao(rustdesk_id: &str, pasta: &str) -> ResultType<()> {
        let dir = Path::new(pasta);
        // 1. Espera os gravadores fecharem (o `.parcial.mp4` vira `.mp4` no Drop).
        let t0 = Instant::now();
        loop {
            std::thread::sleep(Duration::from_secs(1));
            let (_, abertos) = arquivos(dir);
            if abertos == 0 || t0.elapsed() > ESPERA_FECHAR {
                break;
            }
        }
        let (mut prontos, abertos) = arquivos(dir);
        if prontos.is_empty() {
            std::fs::remove_dir(dir).ok(); // só se estiver vazia
            log::info!("Infinity: sessão sem gravação em MP4 para enviar");
            return Ok(());
        }
        // 2. Uma gravação por sessão no core: vai a maior (troca de resolução ou de tela
        //    abre arquivo novo); as outras ficam na pasta.
        prontos.sort_by(|a, b| b.1.cmp(&a.1));
        if prontos.len() > 1 || abertos > 0 {
            log::warn!(
                "Infinity: {} arquivo(s) de gravação nesta sessão ({} aberto(s)); sobe o maior, o resto fica na pasta",
                prontos.len(),
                abertos
            );
        }
        let (arquivo, tamanho) = prontos[0].clone();

        let token = token_do_tecnico().ok_or_else(|| anyhow!("técnico sem login no Infinity"))?;
        let base = api_base();
        if base.is_empty() {
            bail!("sem API do Infinity");
        }
        let autorizacao = ("Authorization".to_owned(), format!("Bearer {}", token));
        let sem_corpo = || -> ResultType<Option<reqwest::blocking::Body>> { Ok(None) };

        // 3. A empresa ainda grava, e o teto.
        let r = requisicao_estrita_bloqueante(
            "get",
            &format!("{}/api/gravacao/config", base),
            &[autorizacao.clone()],
            &sem_corpo,
            TEMPO_LIMITE,
        )?;
        let config = (r.status == 200)
            .then(|| ler_config_da_gravacao(&r.corpo))
            .flatten()
            .ok_or_else(|| anyhow!("configuração de gravação indisponível (status {})", r.status))?;
        if !config.gravar {
            bail!("a empresa deixou de gravar; o arquivo fica na pasta");
        }
        if config.max_bytes > 0 && tamanho > config.max_bytes {
            bail!(
                "gravação de {} bytes acima do teto de {}; o arquivo fica na pasta",
                tamanho,
                config.max_bytes
            );
        }

        // 4. A sessão do Infinity (a auditoria do computador pode chegar um pouco depois).
        let inicio = inicio_da_pasta(pasta).unwrap_or(0);
        let mut sessao = None;
        for tentativa in 0..4 {
            if tentativa > 0 {
                std::thread::sleep(Duration::from_secs(5));
            }
            let r = requisicao_estrita_bloqueante(
                "get",
                &format!("{}/api/sessoes/recentes", base),
                &[autorizacao.clone()],
                &sem_corpo,
                TEMPO_LIMITE,
            )?;
            if r.status == 200 {
                sessao = escolher_sessao(&r.corpo, rustdesk_id, inicio);
                if sessao.is_some() {
                    break;
                }
            }
        }
        let sessao = sessao.ok_or_else(|| anyhow!("sessão do Infinity não encontrada; o arquivo fica na pasta"))?;

        // 5. Sobe em fluxo; 503 ou rede: tenta de novo (o core pede "tente de novo").
        let fronteira = format!(
            "infinity-{}",
            &sha256_hex(&format!("{}{}{:?}", sessao, tamanho, Instant::now()))[..32]
        );
        let (antes, depois) = moldura_multipart(&fronteira);
        let total = antes.len() as u64 + tamanho + depois.len() as u64;
        let corpo = || -> ResultType<Option<reqwest::blocking::Body>> {
            let f = std::fs::File::open(&arquivo)?;
            let leitor = std::io::Cursor::new(antes.clone().into_bytes())
                .chain(f.take(tamanho))
                .chain(std::io::Cursor::new(depois.clone().into_bytes()));
            Ok(Some(reqwest::blocking::Body::sized(leitor, total)))
        };
        let cabecalhos = [
            autorizacao.clone(),
            (
                "Content-Type".to_owned(),
                format!("multipart/form-data; boundary={}", fronteira),
            ),
        ];
        let url = format!("{}/api/sessoes/{}/gravacao", base, sessao);
        for (n, espera) in [0u64, 15, 60].iter().enumerate() {
            if *espera > 0 {
                std::thread::sleep(Duration::from_secs(*espera));
            }
            match requisicao_estrita_bloqueante("post", &url, &cabecalhos, &corpo, TEMPO_LIMITE_UPLOAD) {
                Ok(r) if (200..300).contains(&r.status) => {
                    log::info!("Infinity: gravação da sessão enviada ({} bytes)", tamanho);
                    if let Err(e) = std::fs::remove_file(&arquivo) {
                        log::warn!("Infinity: gravação enviada, mas não apagada: {:?}", e.kind());
                    }
                    std::fs::remove_dir(dir).ok();
                    return Ok(());
                }
                Ok(r) if r.status == 503 => {
                    log::warn!("Infinity: storage indisponível na tentativa {} da gravação", n + 1);
                }
                Ok(r) => {
                    bail!(
                        "o Infinity recusou a gravação (status {}: {}); o arquivo fica na pasta",
                        r.status,
                        mensagem_de_erro(&r.corpo)
                    );
                }
                Err(_) => {
                    log::warn!("Infinity: falha de rede na tentativa {} da gravação", n + 1);
                }
            }
        }
        bail!("gravação não enviada depois de 3 tentativas; o arquivo fica na pasta")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn valida_tokens() {
        let t = format!("ird_{}", "A".repeat(43));
        assert!(token_valido(&t, PREFIXO_SEGREDO));
        assert!(!token_valido(&t, "irk_"));
        assert!(!token_valido(
            &format!("ird_{}", "A".repeat(42)),
            PREFIXO_SEGREDO
        ));
        assert!(!token_valido(
            &format!("ird_{}=", "A".repeat(42)),
            PREFIXO_SEGREDO
        ));
        assert!(!token_valido(
            &format!("ird_{}é", "A".repeat(41)),
            PREFIXO_SEGREDO
        ));
        assert!(!token_valido(PEDIDO_DE_SEGREDO, PREFIXO_SEGREDO));
    }

    #[test]
    fn chave_da_empresa() {
        let corpo = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789-_abcde";
        let k = format!("irk_{}", corpo);
        assert_eq!(chave_colada(&k).as_deref(), Some(k.as_str()));
        assert_eq!(
            chave_colada(&format!("  {}\r\n", k)).as_deref(),
            Some(k.as_str())
        );
        assert!(chave_colada(&format!("ird_{}", corpo)).is_none());
        assert!(chave_colada(&format!("irk_{}x", corpo)).is_none());
        assert!(chave_colada(&format!("irk_{} host=evil", corpo)).is_none());
        assert!(chave_colada("").is_none());
    }

    #[test]
    fn url_da_base() {
        let b = "https://gateway.exemplo.com.br/core/remote";
        assert!(e_da_base(b, b));
        assert!(e_da_base(&format!("{}/api/heartbeat", b), b));
        assert!(e_da_base(&format!("{}?x=1", b), b));
        // outro host com o mesmo começo não é a API do Infinity
        assert!(!e_da_base(
            "https://gateway.exemplo.com.br/core/remotex/api",
            b
        ));
        assert!(!e_da_base(
            "https://gateway.exemplo.com.br.evil.io/core/remote/api",
            b
        ));
        // :443 explícito é o mesmo destino (na URL ou na base)
        assert_eq!(
            sem_porta_padrao("https://gateway.exemplo.com.br:443/core/remote/api/sysinfo"),
            format!("{}/api/sysinfo", b)
        );
        assert_eq!(
            prefixo_de_url("https://Gateway.exemplo.com.br:443/core/remote/").as_deref(),
            Some(b)
        );
        assert_eq!(sem_porta_padrao("https://h:4430/x"), "https://h:4430/x");
        assert_eq!(sem_porta_padrao("http://h:443/x"), "http://h:443/x");
        assert_eq!(sem_porta_padrao("https://h:443"), "https://h");
        assert!(prefixo_de_url("https://admin.rustdesk.com").is_none());
        assert!(prefixo_de_url("  ").is_none());
        assert_eq!(
            prefixo_de_url("https://A.b/c/").as_deref(),
            Some("https://a.b/c")
        );
    }

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    #[test]
    fn gravacao_config_sessao_e_multipart() {
        assert_eq!(
            ler_config_da_gravacao(r#"{"gravar":true,"max_bytes":2147483648}"#),
            Some(ConfigDaGravacao { gravar: true, max_bytes: 2147483648 })
        );
        assert_eq!(ler_config_da_gravacao(r#"{"max_bytes":1}"#), None);
        assert_eq!(ler_config_da_gravacao("<html>"), None);

        let inicio = 1_795_600_000; // 2026-11-25T...Z
        let lista = format!(
            r#"[
              {{"id":"11111111-1111-4111-8111-111111111111","rustdesk_id":"900000001","iniciada_em":"{}"}},
              {{"id":"22222222-2222-4222-8222-222222222222","rustdesk_id":"900000001","iniciada_em":"{}"}},
              {{"id":"33333333-3333-4333-8333-333333333333","rustdesk_id":"900000002","iniciada_em":"{}"}},
              {{"id":"44444444-4444-4444-8444-444444444444","rustdesk_id":"900000001","iniciada_em":"{}"}},
              {{"id":"nao-e-uuid","rustdesk_id":"900000001","iniciada_em":"{}"}}
            ]"#,
            hbb_common::chrono::DateTime::from_timestamp(inicio - 10, 0).unwrap().to_rfc3339(),
            hbb_common::chrono::DateTime::from_timestamp(inicio - 3600, 0).unwrap().to_rfc3339(),
            hbb_common::chrono::DateTime::from_timestamp(inicio + 5, 0).unwrap().to_rfc3339(),
            hbb_common::chrono::DateTime::from_timestamp(inicio + 300, 0).unwrap().to_rfc3339(),
            hbb_common::chrono::DateTime::from_timestamp(inicio + 9, 0).unwrap().to_rfc3339(),
        );
        // a de 1 h antes e a de 5 min depois (reconexão) são de outras conexões; a de outro
        // computador e o id inválido não contam
        assert_eq!(
            escolher_sessao(&lista, "900000001", inicio).as_deref(),
            Some("11111111-1111-4111-8111-111111111111")
        );
        assert_eq!(escolher_sessao(&lista, "900000009", inicio), None);
        assert_eq!(escolher_sessao("{}", "900000001", inicio), None);

        let (a, d) = moldura_multipart("xyz");
        assert!(a.starts_with("--xyz\r\n"));
        assert!(a.contains("name=\"file\""));
        assert!(a.ends_with("Content-Type: video/mp4\r\n\r\n"));
        assert_eq!(d, "\r\n--xyz--\r\n");
    }

    #[test]
    fn nome_da_empresa_decodificado_e_limpo() {
        assert_eq!(nome_de_empresa("Acme%20Ltda"), "Acme Ltda");
        assert_eq!(nome_de_empresa("Jo%C3%A3o%0A%0Dx"), "Joãox");
        assert_eq!(nome_de_empresa("%"), "%");
        assert_eq!(nome_de_empresa("a%2"), "a%2");
        assert_eq!(nome_de_empresa("%aé"), "%aé");
    }

    #[test]
    fn ids_e_pedidos() {
        assert!(id_do_computador_valido("142098166"));
        assert!(!id_do_computador_valido("12345"));
        assert!(!id_do_computador_valido("12a456789"));
        assert!(uuid_valido("3f0c0000-0000-4000-8000-000000000000"));
        assert!(!uuid_valido("3f0c"));
    }

    #[test]
    fn convite_no_formato() {
        let c = format!("ric_{}", "A".repeat(43));
        assert!(token_valido(&c, PREFIXO_CONVITE));
        assert!(!token_valido(&c, PREFIXO_SEGREDO));
        assert!(!token_valido(
            &format!("ric_{}", "A".repeat(42)),
            PREFIXO_CONVITE
        ));
    }

    #[test]
    fn cabecalho_simples_em_pares() {
        assert_eq!(
            cabecalho_simples("x-infinity-segredo: ird_x"),
            vec![("x-infinity-segredo".to_owned(), "ird_x".to_owned())]
        );
        assert!(cabecalho_simples("").is_empty());
    }
}
