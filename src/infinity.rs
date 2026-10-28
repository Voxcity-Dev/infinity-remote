//! Infinity Remote: o que o fork fala com a API do Infinity além do upstream
//! (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md, "Remote no ticket").
//!
//! - Segredo do computador (`ird_`): pedido com `x-infinity-segredo: novo` no sysinfo,
//!   guardado na config e mandado em sysinfo, heartbeat e auditoria de conexão.
//! - Endurecimento: chamada à API do Infinity só com certificado verificado e nunca pelo
//!   desvio TCP do servidor de rendezvous (o upstream faz as duas coisas quando o HTTPS falha:
//!   a primeira com `allow-insecure-tls-fallback`, a segunda por padrão).
//!
//! Nenhum valor de chave, segredo ou token vai para log.

use hbb_common::{anyhow::anyhow, bail, config::Config, log, tls::TlsType, ResultType};
use serde_json::{json, Map, Value};
use std::time::Duration;

/// Chave de instalação da empresa (`irk_…`).
pub const OPCAO_CHAVE: &str = "infinity-chave";
/// Segredo do computador (`ird_…`). Só o serviço escreve. Nunca em log.
pub const OPCAO_SEGREDO: &str = "infinity-segredo";

pub const CABECALHO_SEGREDO: &str = "x-infinity-segredo";
const PEDIDO_DE_SEGREDO: &str = "novo";

pub const PREFIXO_SEGREDO: &str = "ird_";
/// 32 bytes em base64url sem preenchimento.
const TAMANHO_TOKEN: usize = 43;

const TEMPO_LIMITE: Duration = Duration::from_secs(12);

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

/// O mapa de opções que chega pela IPC (`Data::Options`) vem inteiro da interface e pode
/// estar atrasado em relação ao que o serviço acabou de gravar. O segredo só o serviço
/// escreve: fica com o valor dele (a interface não o cria, troca nem apaga).
pub fn preservar_opcoes_do_servico(novas: &mut std::collections::HashMap<String, String>) {
    for k in [OPCAO_SEGREDO] {
        let atual = Config::get_option(k);
        if atual.is_empty() {
            novas.remove(k);
        } else {
            novas.insert(k.to_owned(), atual);
        }
    }
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
    Ok(RespostaSysinfo {
        texto: r.corpo.trim().to_owned(),
    })
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
    fn cabecalho_simples_em_pares() {
        assert_eq!(
            cabecalho_simples("x-infinity-segredo: ird_x"),
            vec![("x-infinity-segredo".to_owned(), "ird_x".to_owned())]
        );
        assert!(cabecalho_simples("").is_empty());
    }
}
