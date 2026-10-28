//! Infinity Remote: o que o fork fala com a API do Infinity além do upstream
//! (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md, "Remote no ticket").
//!
//! - Segredo do computador (`ird_`): pedido com `x-infinity-segredo: novo` no sysinfo,
//!   guardado na config e mandado em sysinfo, heartbeat e auditoria de conexão.
//!
//! Nenhum valor de chave, segredo ou token vai para log.

use hbb_common::{anyhow::anyhow, bail, config::Config, log, tls::TlsType, ResultType};
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
}
