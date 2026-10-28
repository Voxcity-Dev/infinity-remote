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

/// Chamada à API do Infinity sem os desvios do upstream: só HTTPS, certificado sempre
/// verificado (Rustls e, se o handshake falhar, o TLS nativo do sistema, também verificando)
/// e nunca pelo proxy TCP do servidor de rendezvous.
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
        // false = certificado inválido NUNCA é aceito (danger_accept_invalid_cert).
        let cliente = crate::hbbs_http::create_http_client_async(tls, false);
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

/// Chegou conexão com prova e o consentimento está dado: o Infinity aprova?
/// Ok(nome do técnico) ou Err(mensagem para mostrar a quem conecta).
pub async fn autorizar_acesso(peer_id: &str, prova: &str) -> Result<String, String> {
    if !token_valido(prova, PREFIXO_PROVA) {
        return Err("A prova de acesso do Infinity é inválida.".to_owned());
    }
    let base = api_base();
    if base.is_empty() {
        return Err("Este computador não está ligado ao Infinity.".to_owned());
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
            return Err("Não foi possível falar com o Infinity para autorizar o acesso.".to_owned())
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
    Err(mensagem)
}

// ───────────────────────────── lado do técnico ─────────────────────────────

fn id_do_computador_valido(id: &str) -> bool {
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
