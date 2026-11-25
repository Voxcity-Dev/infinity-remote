//! Infinity Remote (#34141): MP4 mínimo (ISO BMFF) com uma faixa de vídeo VP9.
//!
//! O core do Infinity só aceita a gravação da sessão em MP4, e o gravador do upstream põe
//! VP8/VP9/AV1 em WebM (só H264/H265 saem em MP4, pelo ffmpeg do `hwcodec`). Sem placa de
//! vídeo, a sessão vem em VP9: este escritor guarda os quadros VP9 como chegam (sem
//! recodificar) num MP4 com a entrada `vp09` + `vpcC` ("VP Codec ISO Media File Format
//! Binding"), que Chrome, Edge e Firefox tocam.
//!
//! Formato: `ftyp`, `mdat` (tamanho de 64 bits, corrigido no fim) e `moov` no fim do
//! arquivo, um quadro por pedaço (`co64`). Tempo em milissegundos (o `pts` do RustDesk).
//! Só a biblioteca padrão.

use std::io::{self, Seek, SeekFrom, Write};

const ESCALA_DE_TEMPO: u32 = 1000;
const DURACAO_PADRAO_MS: u32 = 33;

struct Amostra {
    posicao: u64,
    tamanho: u32,
    chave: bool,
    pts: i64,
}

pub struct Mp4Vp9<W: Write + Seek> {
    saida: W,
    largura: u16,
    altura: u16,
    inicio_do_mdat: u64,
    posicao: u64,
    amostras: Vec<Amostra>,
    perfil: u8,
    fechado: bool,
}

impl<W: Write + Seek> Mp4Vp9<W> {
    pub fn new(mut saida: W, largura: usize, altura: usize) -> io::Result<Self> {
        let ftyp = caixa(
            b"ftyp",
            &[&b"isom"[..], &0x200u32.to_be_bytes(), b"isom", b"iso2", b"mp41"].concat(),
        );
        saida.write_all(&ftyp)?;
        let inicio_do_mdat = ftyp.len() as u64;
        // tamanho 1 = o tamanho real vem nos 8 bytes seguintes (largesize), corrigido no fim
        saida.write_all(&1u32.to_be_bytes())?;
        saida.write_all(b"mdat")?;
        saida.write_all(&0u64.to_be_bytes())?;
        Ok(Self {
            saida,
            largura: largura.min(u16::MAX as usize) as u16,
            altura: altura.min(u16::MAX as usize) as u16,
            inicio_do_mdat,
            posicao: inicio_do_mdat + 16,
            amostras: Vec::new(),
            perfil: 0,
            fechado: false,
        })
    }

    /// Um quadro VP9 (ou superquadro). Antes do primeiro quadro-chave, nada entra.
    /// Devolve se o quadro foi escrito.
    pub fn escrever(&mut self, dados: &[u8], chave: bool, pts: i64) -> io::Result<bool> {
        if self.fechado || dados.is_empty() || (self.amostras.is_empty() && !chave) {
            return Ok(false);
        }
        if dados.len() > u32::MAX as usize {
            return Ok(false);
        }
        if self.amostras.is_empty() {
            self.perfil = perfil_vp9(dados[0]);
        }
        self.saida.write_all(dados)?;
        self.amostras.push(Amostra {
            posicao: self.posicao,
            tamanho: dados.len() as u32,
            chave,
            pts,
        });
        self.posicao += dados.len() as u64;
        Ok(true)
    }

    pub fn quadros(&self) -> usize {
        self.amostras.len()
    }

    /// Fecha o arquivo (tamanho do `mdat` e o `moov`), uma vez. Sem quadro nenhum, só
    /// devolve false.
    pub fn finalizar(&mut self) -> io::Result<bool> {
        if self.fechado {
            return Ok(!self.amostras.is_empty());
        }
        self.fechado = true;
        if self.amostras.is_empty() {
            self.saida.flush()?;
            return Ok(false);
        }
        let tamanho_mdat = self.posicao - self.inicio_do_mdat;
        self.saida.seek(SeekFrom::Start(self.inicio_do_mdat + 8))?;
        self.saida.write_all(&tamanho_mdat.to_be_bytes())?;
        self.saida.seek(SeekFrom::Start(self.posicao))?;
        let moov = self.moov();
        self.saida.write_all(&moov)?;
        self.saida.flush()?;
        Ok(true)
    }

    pub fn into_inner(self) -> W {
        self.saida
    }

    fn duracoes(&self) -> Vec<u32> {
        let n = self.amostras.len();
        let mut d = Vec::with_capacity(n);
        for i in 0..n {
            let delta = if i + 1 < n {
                let x = self.amostras[i + 1].pts - self.amostras[i].pts;
                x.clamp(1, u32::MAX as i64) as u32
            } else {
                *d.last().unwrap_or(&DURACAO_PADRAO_MS)
            };
            d.push(delta);
        }
        d
    }

    fn moov(&self) -> Vec<u8> {
        let duracoes = self.duracoes();
        let total: u64 = duracoes.iter().map(|x| *x as u64).sum();
        let total = total.min(u32::MAX as u64) as u32;
        let matriz: Vec<u8> = [0x0001_0000u32, 0, 0, 0, 0x0001_0000, 0, 0, 0, 0x4000_0000]
            .iter()
            .flat_map(|v| v.to_be_bytes())
            .collect();

        let mvhd = caixa_cheia(
            b"mvhd",
            0,
            0,
            &[
                &0u32.to_be_bytes()[..],
                &0u32.to_be_bytes(),
                &ESCALA_DE_TEMPO.to_be_bytes(),
                &total.to_be_bytes(),
                &0x0001_0000u32.to_be_bytes(),
                &0x0100u16.to_be_bytes(),
                &[0u8; 10],
                &matriz,
                &[0u8; 24],
                &2u32.to_be_bytes(),
            ]
            .concat(),
        );
        let tkhd = caixa_cheia(
            b"tkhd",
            0,
            3,
            &[
                &0u32.to_be_bytes()[..],
                &0u32.to_be_bytes(),
                &1u32.to_be_bytes(),
                &0u32.to_be_bytes(),
                &total.to_be_bytes(),
                &[0u8; 8],
                &0u16.to_be_bytes(),
                &0u16.to_be_bytes(),
                &0u16.to_be_bytes(),
                &0u16.to_be_bytes(),
                &matriz,
                &((self.largura as u32) << 16).to_be_bytes(),
                &((self.altura as u32) << 16).to_be_bytes(),
            ]
            .concat(),
        );
        let mdhd = caixa_cheia(
            b"mdhd",
            0,
            0,
            &[
                &0u32.to_be_bytes()[..],
                &0u32.to_be_bytes(),
                &ESCALA_DE_TEMPO.to_be_bytes(),
                &total.to_be_bytes(),
                &0x55C4u16.to_be_bytes(), // "und"
                &0u16.to_be_bytes(),
            ]
            .concat(),
        );
        let hdlr = caixa_cheia(
            b"hdlr",
            0,
            0,
            &[&0u32.to_be_bytes()[..], b"vide", &[0u8; 12], b"VideoHandler\0"].concat(),
        );
        let vmhd = caixa_cheia(b"vmhd", 0, 1, &[0u8; 8]);
        let dinf = caixa(
            b"dinf",
            &caixa_cheia(
                b"dref",
                0,
                0,
                &[&1u32.to_be_bytes()[..], &caixa_cheia(b"url ", 0, 1, &[])].concat(),
            ),
        );
        let stbl = caixa(
            b"stbl",
            &[
                self.stsd(),
                stts(&duracoes),
                self.stss(),
                caixa_cheia(
                    b"stsc",
                    0,
                    0,
                    &[
                        &1u32.to_be_bytes()[..],
                        &1u32.to_be_bytes(),
                        &1u32.to_be_bytes(),
                        &1u32.to_be_bytes(),
                    ]
                    .concat(),
                ),
                self.stsz(),
                self.co64(),
            ]
            .concat(),
        );
        let minf = caixa(b"minf", &[vmhd, dinf, stbl].concat());
        let mdia = caixa(b"mdia", &[mdhd, hdlr, minf].concat());
        let trak = caixa(b"trak", &[tkhd, mdia].concat());
        caixa(b"moov", &[mvhd, trak].concat())
    }

    fn stsd(&self) -> Vec<u8> {
        let (profundidade, crominancia) = match self.perfil {
            0 => (8u8, 1u8), // 4:2:0
            1 => (8, 3),     // 4:4:4 (o "I444" do RustDesk)
            2 => (10, 1),
            _ => (10, 3),
        };
        let vpcc = caixa_cheia(
            b"vpcC",
            1,
            0,
            &[
                self.perfil,
                nivel_vp9(self.largura as u32 * self.altura as u32),
                (profundidade << 4) | (crominancia << 1),
                2, // cores, transferência e matriz: não especificadas
                2,
                2,
                0, // codecInitializationDataSize (u16) = 0
                0,
            ],
        );
        let mut nome = [0u8; 32];
        nome[..11].copy_from_slice(b"\x0aInfinity R");
        let vp09 = caixa(
            b"vp09",
            &[
                &[0u8; 6][..],
                &1u16.to_be_bytes(),
                &[0u8; 16],
                &self.largura.to_be_bytes(),
                &self.altura.to_be_bytes(),
                &0x0048_0000u32.to_be_bytes(),
                &0x0048_0000u32.to_be_bytes(),
                &0u32.to_be_bytes(),
                &1u16.to_be_bytes(),
                &nome,
                &0x0018u16.to_be_bytes(),
                &0xFFFFu16.to_be_bytes(),
                &vpcc,
            ]
            .concat(),
        );
        caixa_cheia(b"stsd", 0, 0, &[&1u32.to_be_bytes()[..], &vp09].concat())
    }

    fn stss(&self) -> Vec<u8> {
        let chaves: Vec<u32> = self
            .amostras
            .iter()
            .enumerate()
            .filter(|(_, a)| a.chave)
            .map(|(i, _)| i as u32 + 1)
            .collect();
        let mut corpo = (chaves.len() as u32).to_be_bytes().to_vec();
        for c in chaves {
            corpo.extend_from_slice(&c.to_be_bytes());
        }
        caixa_cheia(b"stss", 0, 0, &corpo)
    }

    fn stsz(&self) -> Vec<u8> {
        let mut corpo = Vec::with_capacity(8 + 4 * self.amostras.len());
        corpo.extend_from_slice(&0u32.to_be_bytes());
        corpo.extend_from_slice(&(self.amostras.len() as u32).to_be_bytes());
        for a in &self.amostras {
            corpo.extend_from_slice(&a.tamanho.to_be_bytes());
        }
        caixa_cheia(b"stsz", 0, 0, &corpo)
    }

    fn co64(&self) -> Vec<u8> {
        let mut corpo = Vec::with_capacity(4 + 8 * self.amostras.len());
        corpo.extend_from_slice(&(self.amostras.len() as u32).to_be_bytes());
        for a in &self.amostras {
            corpo.extend_from_slice(&a.posicao.to_be_bytes());
        }
        caixa_cheia(b"co64", 0, 0, &corpo)
    }
}

fn stts(duracoes: &[u32]) -> Vec<u8> {
    let mut corridas: Vec<(u32, u32)> = Vec::new();
    for d in duracoes {
        match corridas.last_mut() {
            Some((n, x)) if x == d => *n += 1,
            _ => corridas.push((1, *d)),
        }
    }
    let mut corpo = (corridas.len() as u32).to_be_bytes().to_vec();
    for (n, d) in corridas {
        corpo.extend_from_slice(&n.to_be_bytes());
        corpo.extend_from_slice(&d.to_be_bytes());
    }
    caixa_cheia(b"stts", 0, 0, &corpo)
}

/// Perfil VP9 do cabeçalho descomprimido: frame_marker (2 bits = 0b10), profile_low_bit,
/// profile_high_bit. Fora do formato, 0.
fn perfil_vp9(b: u8) -> u8 {
    if b >> 6 != 0b10 {
        return 0;
    }
    ((b >> 5) & 1) | (((b >> 4) & 1) << 1)
}

/// Nível VP9 aproximado pelo tamanho da imagem (tabela de níveis do VP9).
fn nivel_vp9(pixels: u32) -> u8 {
    match pixels {
        0..=36_864 => 10,
        36_865..=73_728 => 11,
        73_729..=122_880 => 20,
        122_881..=245_760 => 21,
        245_761..=552_960 => 30,
        552_961..=983_040 => 31,
        983_041..=2_228_224 => 41,
        2_228_225..=8_912_896 => 51,
        _ => 61,
    }
}

fn caixa(tipo: &[u8; 4], corpo: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(8 + corpo.len());
    v.extend_from_slice(&((8 + corpo.len()) as u32).to_be_bytes());
    v.extend_from_slice(tipo);
    v.extend_from_slice(corpo);
    v
}

fn caixa_cheia(tipo: &[u8; 4], versao: u8, flags: u32, corpo: &[u8]) -> Vec<u8> {
    let mut c = Vec::with_capacity(4 + corpo.len());
    c.push(versao);
    c.extend_from_slice(&flags.to_be_bytes()[1..]);
    c.extend_from_slice(corpo);
    caixa(tipo, &c)
}

/// `nome.parcial.mp4` (gravação ainda aberta) -> `nome.mp4`.
pub fn nome_final(parcial: &str) -> Option<String> {
    parcial
        .strip_suffix(SUFIXO_PARCIAL)
        .map(|base| format!("{}.mp4", base))
}

/// Sufixo da gravação do Infinity enquanto o arquivo está aberto (o ffmpeg do `hwcodec`
/// escolhe o formato pela extensão, por isso termina em `.mp4`).
pub const SUFIXO_PARCIAL: &str = ".parcial.mp4";

#[cfg(test)]
mod test {
    use super::*;
    use std::io::Cursor;

    fn u32_em(b: &[u8], i: usize) -> u32 {
        u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]])
    }

    /// Caixas de primeiro nível: (tipo, início, tamanho).
    fn caixas(b: &[u8], mut i: usize, fim: usize) -> Vec<(String, usize, usize)> {
        let mut v = Vec::new();
        while i + 8 <= fim {
            let mut t = u32_em(b, i) as usize;
            let tipo = String::from_utf8_lossy(&b[i + 4..i + 8]).to_string();
            if t == 1 {
                t = u64::from_be_bytes(b[i + 8..i + 16].try_into().unwrap()) as usize;
            }
            assert!(t >= 8 && i + t <= fim, "caixa {} fora do arquivo", tipo);
            v.push((tipo, i, t));
            i += t;
        }
        assert_eq!(i, fim, "sobrou byte depois da última caixa");
        v
    }

    fn achar(b: &[u8], tipo: &str) -> usize {
        b.windows(4)
            .position(|w| w == tipo.as_bytes())
            .expect(tipo)
            - 4
    }

    #[test]
    fn mp4_com_tres_quadros() {
        let mut m = Mp4Vp9::new(Cursor::new(Vec::new()), 1280, 800).unwrap();
        // antes do quadro-chave não entra
        assert!(!m.escrever(&[0x86, 1, 2], false, 0).unwrap());
        assert!(m.escrever(&[0x82, 0x49, 0x83, 0x42, 0x00], true, 100).unwrap());
        assert!(m.escrever(&[0x86, 7, 7], false, 133).unwrap());
        assert!(m.escrever(&[0x86, 8, 8, 8], false, 166).unwrap());
        assert_eq!(m.quadros(), 3);
        assert!(m.finalizar().unwrap());
        assert!(m.finalizar().unwrap()); // de novo não reescreve
        assert!(!m.escrever(&[0x82, 1], true, 200).unwrap()); // fechado não aceita
        let saida = m.into_inner().into_inner();
        let b = &saida[..];
        let top = caixas(b, 0, b.len());
        let tipos: Vec<&str> = top.iter().map(|(t, _, _)| t.as_str()).collect();
        assert_eq!(tipos, vec!["ftyp", "mdat", "moov"]);
        assert_eq!(top[1].2, 16 + 5 + 3 + 4);
        // stsz: 3 amostras com os tamanhos certos
        let stsz = achar(b, "stsz");
        assert_eq!(u32_em(b, stsz + 16), 3);
        assert_eq!(
            [u32_em(b, stsz + 20), u32_em(b, stsz + 24), u32_em(b, stsz + 28)],
            [5, 3, 4]
        );
        // co64: o primeiro pedaço começa logo depois do cabeçalho do mdat
        let co64 = achar(b, "co64");
        let p0 = u64::from_be_bytes(b[co64 + 16..co64 + 24].try_into().unwrap()) as usize;
        assert_eq!(p0, 32 + 16);
        assert_eq!(&b[p0..p0 + 5], &[0x82, 0x49, 0x83, 0x42, 0x00]);
        // stss: só o 1º é chave
        let stss = achar(b, "stss");
        assert_eq!(u32_em(b, stss + 12), 1);
        assert_eq!(u32_em(b, stss + 16), 1);
        // stts: 33, 33, 33 (o último repete o anterior)
        let stts_i = achar(b, "stts");
        assert_eq!(u32_em(b, stts_i + 12), 1);
        assert_eq!((u32_em(b, stts_i + 16), u32_em(b, stts_i + 20)), (3, 33));
        // vpcC v1, perfil 0, 8 bits 4:2:0
        let vpcc = achar(b, "vpcC");
        assert_eq!(b[vpcc + 8], 1);
        assert_eq!(b[vpcc + 12], 0);
        assert_eq!(b[vpcc + 14], (8 << 4) | (1 << 1));
        // mvhd: duração 99 ms
        let mvhd = achar(b, "mvhd");
        assert_eq!(u32_em(b, mvhd + 24), 99);
    }

    #[test]
    fn sem_quadro_chave_nao_fecha() {
        let mut m = Mp4Vp9::new(Cursor::new(Vec::new()), 640, 480).unwrap();
        assert!(!m.escrever(&[0x86, 1], false, 0).unwrap());
        assert!(!m.finalizar().unwrap());
    }

    #[test]
    fn perfis_e_nomes() {
        assert_eq!(perfil_vp9(0x82), 0);
        assert_eq!(perfil_vp9(0xA2), 1);
        assert_eq!(perfil_vp9(0x92), 2);
        assert_eq!(perfil_vp9(0x02), 0);
        assert_eq!(
            nome_final("/v/outgoing_1_2_display0_vp9.parcial.mp4").as_deref(),
            Some("/v/outgoing_1_2_display0_vp9.mp4")
        );
        assert_eq!(nome_final("/v/a.mp4"), None);
    }
}
