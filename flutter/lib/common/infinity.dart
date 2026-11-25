// Infinity Remote: telas e links do Infinity que o upstream não tem
// (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md, "Remote no ticket").
//
// - link infinity-remote://convite/<token>: grava o convite; o serviço o manda no
//   próximo sysinfo (src/hbbs_http/sync.rs) e o apaga depois da resposta.
// - consentimento "técnicos da empresa acessam sem alguém aqui": pergunta única no
//   computador atendido, revogável em Configurações › Segurança. Só com o nome da
//   empresa (cabeçalho x-infinity-empresa, validado no core) na pergunta, e a resposta
//   vale para aquele nome: um convite repassado por outra empresa não aparece como "a
//   empresa que atende você" (Card VoxPlan #34143, A1).
// - "Ligado a <empresa>" fixo na janela principal; o aviso de cada sessão sem ninguém
//   (gerenciador de conexões) também diz a empresa.
// - "O que foi feito?": ao encerrar a sessão, o técnico pode anotar o que fez; vai
//   para o resumo do atendimento no ticket.
// - Chave da empresa (irk_): o admin a copia no assistente "Adicionar computador"
//   (Infinity Remote › Computadores) e cola aqui, em Configurações › Geral › Chave da empresa
//   ou no aviso da janela principal, enquanto o computador não está numa empresa. O serviço
//   reenvia o sysinfo com ela no próximo ciclo (src/hbbs_http/sync.rs). Trocar de empresa
//   só pelo caminho elevado: Configurações › Segurança desbloqueada (ou --infinity-chave
//   como admin); o serviço então apaga o segredo e pede um novo. Só a chave entra: o
//   servidor é sempre o do build.
//
// Nenhum valor de chave, segredo, convite, prova ou token vai para log ou tela.

import 'dart:async';
import 'dart:convert';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:get/get.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/model.dart';
import 'package:flutter_hbb/models/platform_model.dart';
import 'package:flutter_hbb/models/state_model.dart';
import 'package:flutter_hbb/utils/http_service.dart' as http;

const kInfinityOpcaoConvite = 'infinity-convite';
const kInfinityOpcaoSegredo = 'infinity-segredo';
const kInfinityOpcaoChave = 'infinity-chave';
// Troca de empresa (caminho elevado); o serviço a aplica e não a guarda (src/infinity.rs).
const kInfinityOpcaoTrocaDeChave = 'infinity-chave-troca';
// Local (só desta interface): o aviso da janela principal foi dispensado.
const kInfinityOpcaoLocalAvisoChave = 'infinity-aviso-chave-dispensado';

const kInfinityOpcaoEmpresa = 'infinity-empresa';
const kInfinityOpcaoSemNinguem = 'infinity-acesso-sem-ninguem';
// O nome da empresa que a pessoa viu ao responder (src/infinity.rs, OPCAO_SEM_NINGUEM_EMPRESA).
const kInfinityOpcaoSemNinguemEmpresa = 'infinity-acesso-sem-ninguem-empresa';
const kInfinityOpcaoLocalPedido = 'infinity-pedido';
const kInfinityOQueFoiFeitoMax = 500;

final _reChave = RegExp(r'^irk_[A-Za-z0-9_-]{43}$');
final _reCorpoDoToken = RegExp(r'^[A-Za-z0-9_-]{43}$');
final _reIdDoComputador = RegExp(r'^\d{6,12}$');
final _reUuid = RegExp(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$');

bool _ehTokenDoInfinity(String s, String prefixo) =>
    s.startsWith(prefixo) &&
    _reCorpoDoToken.hasMatch(s.substring(prefixo.length));

// ───────────────────────────── links ─────────────────────────────

/// infinity-remote://convite/<ric_…>. Devolve true se o link era de convite (válido
/// ou não): quem chama não segue com ele.
bool infinityTratarLinkDeConvite(Uri uri) {
  if (uri.authority != 'convite') return false;
  final token = uri.pathSegments.isNotEmpty ? uri.pathSegments.first : '';
  if (!_ehTokenDoInfinity(token, 'ric_')) {
    Timer(const Duration(seconds: 1),
        () => showToast(translate('infinity-convite-invalido')));
    return true;
  }
  // Vai pelo serviço (IPC): o sysinfo que leva o convite sai de lá.
  bind.mainSetOption(key: kInfinityOpcaoConvite, value: token);
  Timer(const Duration(seconds: 1),
      () => showToast(translate('infinity-convite-recebido')));
  return true;
}

/// infinity-remote://connect/<id>?pedido=<uuid> (botão Conectar do ticket): guarda o
/// pedido para a prova da próxima conexão a esse computador. Devolve false quando o
/// "id" do link é um uuid (link sem o código do computador): não dá para conectar.
bool infinityTratarPedidoDoLink(String id, Map<String, String> query) {
  if (_reUuid.hasMatch(id)) {
    Timer(const Duration(seconds: 1),
        () => showToast(translate('infinity-link-sem-computador')));
    return false;
  }
  final pedido = query['pedido'];
  if (pedido != null &&
      _reUuid.hasMatch(pedido) &&
      _reIdDoComputador.hasMatch(id)) {
    bind.mainSetLocalOption(
        key: kInfinityOpcaoLocalPedido, value: '$id:$pedido');
  }
  return true;
}

// ─────────────────── computador atendido: consentimento ───────────────────

/// O computador já entrou numa empresa (recebeu o segredo do Infinity).
bool infinityComputadorNaEmpresa() =>
    bind.mainGetOptionSync(key: kInfinityOpcaoSegredo).isNotEmpty;

/// O nome da empresa que o Infinity mandou (validado no core), ou vazio.
String infinityEmpresa() =>
    bind.mainGetOptionSync(key: kInfinityOpcaoEmpresa).trim();

/// A resposta ao consentimento foi dada com o nome da empresa de hoje na tela.
bool _respostaDaEmpresaDeHoje() {
  final empresa = infinityEmpresa();
  return empresa.isNotEmpty &&
      bind.mainGetOptionSync(key: kInfinityOpcaoSemNinguemEmpresa).trim() ==
          empresa;
}

/// Igual ao serviço (src/infinity.rs, consentimento_dado): "sim", com nome, da empresa de hoje.
bool infinityConsentimentoDado() =>
    bind.mainGetOptionSync(key: kInfinityOpcaoSemNinguem) == 'Y' &&
    _respostaDaEmpresaDeHoje();

/// Grava a resposta junto com o nome que estava na tela. Sem nome, não grava "sim".
/// A resposta vai ANTES do nome: entre as duas gravações (ou se a segunda se perder), o
/// que fica é a resposta nova com o nome antigo, que não vale para a empresa de hoje. Na
/// ordem inversa, o "sim" antigo ficaria valendo para o nome novo.
Future<void> infinityGravarConsentimento(bool permitido) async {
  final empresa = infinityEmpresa();
  if (permitido && empresa.isEmpty) return;
  await bind.mainSetOption(
      key: kInfinityOpcaoSemNinguem, value: permitido ? 'Y' : 'N');
  await bind.mainSetOption(key: kInfinityOpcaoSemNinguemEmpresa, value: empresa);
}

/// Dá para oferecer o consentimento: o computador está numa empresa e o nome dela chegou.
bool infinityConsentimentoDisponivel() =>
    infinityComputadorNaEmpresa() && infinityEmpresa().isNotEmpty;

/// Rótulo da opção em Configurações: "Técnicos de <empresa> acessam este computador sem
/// ninguém na frente". Sem o nome, diz que a opção espera o nome (e ela fica desligada).
String infinityTextoDoConsentimento() {
  final empresa = infinityEmpresa();
  if (empresa.isEmpty) {
    return translate('infinity-sem-ninguem-sem-nome');
  }
  return translate('infinity-sem-ninguem-opcao')
      .replaceAll('{empresa}', empresa);
}

bool _consentimentoPerguntado = false;
bool _consentimentoAberto = false;
// O nome da empresa na última vez que o relógio olhou: mudou, a pergunta pode voltar.
String _empresaVista = '';
const _kTagConsentimento = 'infinity-consentimento';

/// Chamado pelo relógio da janela principal: quando o computador entra numa empresa e o
/// consentimento nunca foi respondido, pergunta uma vez. Nunca com alguém conectado: quem
/// está no controle remoto (o técnico) não pode responder pelo dono do computador. Se uma
/// conexão chega com a pergunta aberta, ela fecha sem resposta e volta depois.
bool _temConexaoEntrando() =>
    stateGlobal.videoConnCount.value > 0 || gFFI.serverModel.clients.isNotEmpty;

void infinityTalvezPerguntarConsentimento() {
  final temConexao = _temConexaoEntrando();
  if (_consentimentoAberto && temConexao) {
    gFFI.dialogManager.dismissByTag(_kTagConsentimento);
    _consentimentoAberto = false;
    _consentimentoPerguntado = false;
    return;
  }
  final empresaAgora = infinityEmpresa();
  if (empresaAgora != _empresaVista) {
    _empresaVista = empresaAgora;
    if (!_consentimentoAberto) _consentimentoPerguntado = false;
  }
  if (_consentimentoPerguntado || temConexao) return;
  if (bind.isOutgoingOnly()) {
    _consentimentoPerguntado = true;
    return;
  }
  // Sem o nome da empresa, não pergunta: espera o nome chegar (o relógio volta aqui).
  if (!infinityConsentimentoDisponivel()) return;
  // Já respondida para esta empresa. Resposta sem nome ou de outro nome: pergunta de novo.
  if (bind.mainGetOptionSync(key: kInfinityOpcaoSemNinguem).isNotEmpty &&
      _respostaDaEmpresaDeHoje()) {
    _consentimentoPerguntado = true;
    return;
  }
  final empresaNaTela = infinityEmpresa();
  _consentimentoPerguntado = true;
  _consentimentoAberto = true;
  gFFI.dialogManager.show((setState, close, context) {
    responder(bool permitido) async {
      // Uma conexão chegou enquanto o diálogo estava na tela: o clique não vale.
      if (_temConexaoEntrando()) {
        _consentimentoAberto = false;
        _consentimentoPerguntado = false;
        close();
        return;
      }
      // O nome mudou com a pergunta aberta: a resposta era para o nome de antes.
      if (infinityEmpresa() != empresaNaTela) {
        _consentimentoAberto = false;
        _consentimentoPerguntado = false;
        close();
        return;
      }
      await infinityGravarConsentimento(permitido);
      _consentimentoAberto = false;
      close();
    }

    return CustomAlertDialog(
      title: Row(children: [
        const Icon(Icons.verified_user_outlined, color: MyTheme.accent)
            .marginOnly(right: 8),
        Expanded(child: Text(translate('infinity-sem-ninguem-titulo'))),
      ]),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
                translate('infinity-sem-ninguem-permitir')
                    .replaceAll('{empresa}', empresaNaTela),
                style: const TextStyle(fontWeight: FontWeight.w600)),
            const SizedBox(height: 12),
            Text(translate('infinity-sem-ninguem-explicacao')),
          ],
        ),
      ),
      actions: [
        dialogButton('infinity-agora-nao',
            onPressed: () => responder(false), isOutline: true),
        dialogButton('infinity-permitir', onPressed: () => responder(true)),
      ],
      onCancel: () => responder(false),
    );
  }, tag: _kTagConsentimento);
}

// ─────────────────────── técnico: "O que foi feito?" ───────────────────────

String _tokenDoTecnico() {
  final t = bind.mainGetLocalOption(key: 'access_token');
  return t.startsWith('irm_') ? t : '';
}

/// A sessão do Infinity desta conexão: a mais recente do técnico com este computador
/// ainda sem "o que foi feito".
Future<String?> _sessaoRecente(String api, String peerId) async {
  try {
    final r = await http
        .get(Uri.parse('$api/api/sessoes/recentes'), headers: getHttpHeaders())
        .timeout(const Duration(seconds: 5));
    if (r.statusCode != 200) return null;
    final lista = jsonDecode(r.body);
    if (lista is! List) return null;
    // A mais recente deste computador ainda sem anotação (a lista não vem ordenada).
    String? id;
    DateTime? quando;
    for (final s in lista) {
      if (s is Map &&
          s['rustdesk_id'] == peerId &&
          s['o_que_foi_feito_registrado'] != true &&
          s['id'] is String) {
        final t = DateTime.tryParse('${s['iniciada_em']}');
        if (id == null || (t != null && (quando == null || t.isAfter(quando)))) {
          id = s['id'] as String;
          quando = t;
        }
      }
    }
    return id;
  } catch (e) {
    debugPrint('Infinity: sessões recentes indisponíveis');
  }
  return null;
}

/// Ao fechar a sessão no lado do técnico. Devolve true se o técnico desistiu de fechar.
/// Sem login no Infinity ou sem sessão registrada, não pergunta nada.
Future<bool> infinityPerguntarOQueFoiFeito(FFI ffi, String peerId) async {
  if (_tokenDoTecnico().isEmpty || !_reIdDoComputador.hasMatch(peerId)) {
    return false;
  }
  final api = await bind.mainGetApiServer();
  if (api.isEmpty) return false;
  final sessaoId = await _sessaoRecente(api, peerId);
  if (sessaoId == null) return false;

  final controller = TextEditingController();
  var enviando = false;
  var erro = '';
  final res = await ffi.dialogManager.show<bool>((setState, close, context) {
    voltar() => close(true);
    encerrar() => close(false);

    enviar() async {
      final texto = controller.text.trim();
      if (texto.isEmpty) {
        encerrar();
        return;
      }
      setState(() {
        enviando = true;
        erro = '';
      });
      try {
        final headers = getHttpHeaders();
        headers['Content-Type'] = 'application/json';
        final r = await http
            .post(Uri.parse('$api/api/sessoes/$sessaoId/o-que-foi-feito'),
                headers: headers, body: jsonEncode({'texto': texto}))
            .timeout(const Duration(seconds: 8));
        if (r.statusCode == 200) {
          showToast(translate('infinity-o-que-foi-feito-enviado'));
          encerrar();
          return;
        }
        var msg = '';
        try {
          final b = jsonDecode(r.body);
          if (b is Map && b['error'] is String) msg = b['error'] as String;
        } catch (_) {}
        setState(() {
          enviando = false;
          erro = msg.isNotEmpty ? msg : translate('infinity-falha-envio');
        });
      } catch (_) {
        setState(() {
          enviando = false;
          erro = translate('infinity-falha-envio');
        });
      }
    }

    return CustomAlertDialog(
      title: Row(children: [
        const Icon(Icons.task_alt, color: MyTheme.accent).marginOnly(right: 8),
        Expanded(child: Text(translate('infinity-o-que-foi-feito'))),
      ]),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate('infinity-o-que-foi-feito-dica'),
                style: const TextStyle(fontSize: 13)),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              autofocus: true,
              minLines: 4,
              maxLines: 6,
              maxLength: kInfinityOQueFoiFeitoMax,
              keyboardType: TextInputType.multiline,
              inputFormatters: [
                LengthLimitingTextInputFormatter(kInfinityOQueFoiFeitoMax),
              ],
              decoration: InputDecoration(
                hintText: translate('infinity-o-que-foi-feito-exemplo'),
                errorText: erro.isEmpty ? null : erro,
                errorMaxLines: 3,
              ),
            ),
            if (enviando) const LinearProgressIndicator().marginOnly(top: 4),
          ],
        ),
      ),
      actions: [
        dialogButton('Cancel',
            onPressed: enviando ? null : voltar, isOutline: true),
        dialogButton('infinity-encerrar-sem-anotar',
            onPressed: enviando ? null : encerrar, isOutline: true),
        dialogButton('infinity-enviar-e-encerrar',
            onPressed: enviando ? null : enviar),
      ],
      onCancel: enviando ? null : voltar,
    );
  }, tag: 'infinity-o-que-foi-feito');
  return res == true;
}

// ───────────────────── computador atendido: chave da empresa ─────────────────────

bool infinityChaveValida(String s) => _reChave.hasMatch(s.trim());

/// Há uma chave da empresa (no formato certo) gravada neste computador.
bool infinityTemChave() =>
    infinityChaveValida(bind.mainGetOptionSync(key: kInfinityOpcaoChave));

/// O texto do estado da chave, para Configurações.
String infinityEstadoDaChave() {
  if (infinityComputadorNaEmpresa()) {
    return translate('infinity-chave-estado-ligado');
  }
  if (infinityTemChave()) {
    return translate('infinity-chave-estado-aguardando');
  }
  return translate('infinity-chave-estado-vazia');
}

/// "Cole a chave da empresa": grava a opção infinity-chave no serviço (IPC), só com o
/// computador fora de empresa. Com `troca` (Segurança desbloqueada), pede a troca de
/// empresa. `depois` é chamado quando a chave foi gravada, para a tela se redesenhar.
Future<void> infinityPedirChave({bool troca = false, VoidCallback? depois}) async {
  if (!troca && infinityComputadorNaEmpresa()) {
    showToast(translate('infinity-chave-trocar-dica'));
    return;
  }
  final controller = TextEditingController();
  var erro = '';
  var gravando = false;
  await gFFI.dialogManager.show((setState, close, context) {
    gravar() async {
      if (gravando) return;
      final chave = controller.text.trim();
      if (!infinityChaveValida(chave)) {
        setState(() => erro = translate('infinity-chave-invalida'));
        return;
      }
      gravando = true;
      await bind.mainSetOption(
          key: troca ? kInfinityOpcaoTrocaDeChave : kInfinityOpcaoChave,
          value: chave);
      controller.clear();
      close();
      showToast(translate('infinity-chave-gravada'));
      depois?.call();
    }

    colar() async {
      final dados = await Clipboard.getData(Clipboard.kTextPlain);
      final texto = dados?.text?.trim() ?? '';
      if (texto.isNotEmpty) {
        controller.text = texto;
        setState(() => erro = '');
      }
    }

    return CustomAlertDialog(
      title: Row(children: [
        const Icon(Icons.vpn_key_outlined, color: MyTheme.accent)
            .marginOnly(right: 8),
        Expanded(child: Text(translate('infinity-chave-titulo'))),
      ]),
      content: SizedBox(
        width: 420,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(translate('infinity-chave-explicacao')),
            const SizedBox(height: 12),
            TextField(
              controller: controller,
              autofocus: true,
              obscureText: true,
              enableSuggestions: false,
              autocorrect: false,
              decoration: InputDecoration(
                hintText: 'irk_…',
                errorText: erro.isEmpty ? null : erro,
                errorMaxLines: 3,
                suffixIcon: IconButton(
                  icon: const Icon(Icons.content_paste),
                  tooltip: translate('Paste'),
                  onPressed: colar,
                ),
              ),
            ),
          ],
        ),
      ),
      actions: [
        dialogButton('Cancel', onPressed: close, isOutline: true),
        dialogButton('OK', onPressed: gravar),
      ],
      onSubmit: gravar,
      onCancel: close,
    );
  }, tag: 'infinity-chave');
  controller.dispose();
}

/// Aviso da janela principal: o computador ainda não está numa empresa e não tem chave.
/// Some quando a chave é gravada, quando o computador entra (convite) ou se dispensado.
Widget infinityAvisoDaChave(BuildContext context, VoidCallback atualizar) {
  if (bind.isOutgoingOnly() ||
      infinityTemChave() ||
      infinityComputadorNaEmpresa() ||
      bind.mainGetLocalOption(key: kInfinityOpcaoLocalAvisoChave) == 'Y') {
    return const Offstage();
  }
  final cor = Theme.of(context).textTheme.titleLarge?.color;
  return Container(
    margin: const EdgeInsets.fromLTRB(20, 16, 16, 0),
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(
      border: Border.all(color: MyTheme.accent.withOpacity(0.5)),
      borderRadius: BorderRadius.circular(8),
    ),
    child: Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(translate('infinity-chave-aviso'),
            style: TextStyle(fontSize: 12, height: 1.4, color: cor)),
        const SizedBox(height: 8),
        Wrap(spacing: 8, runSpacing: 4, children: [
          ElevatedButton(
            onPressed: () => infinityPedirChave(depois: atualizar),
            child: Text(translate('infinity-chave-colar')),
          ),
          TextButton(
            onPressed: () async {
              await bind.mainSetLocalOption(
                  key: kInfinityOpcaoLocalAvisoChave, value: 'Y');
              atualizar();
            },
            child: Text(translate('infinity-agora-nao')),
          ),
        ]),
      ],
    ),
  );
}

/// "Ligado a <empresa>", fixo na janela principal enquanto o computador está numa empresa
/// e o nome dela chegou do Infinity.
Widget infinityLigadoA(BuildContext context) {
  if (bind.isOutgoingOnly() || !infinityComputadorNaEmpresa()) {
    return const Offstage();
  }
  final empresa = infinityEmpresa();
  if (empresa.isEmpty) return const Offstage();
  final cor = Theme.of(context).textTheme.titleLarge?.color;
  return Container(
    margin: const EdgeInsets.fromLTRB(20, 12, 16, 0),
    padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
    decoration: BoxDecoration(
      border: Border.all(color: MyTheme.accent.withOpacity(0.5)),
      borderRadius: BorderRadius.circular(8),
    ),
    child: Row(children: [
      const Icon(Icons.business_outlined, size: 16, color: MyTheme.accent)
          .marginOnly(right: 8),
      Expanded(
        child: Text(
          translate('infinity-ligado-a').replaceAll('{empresa}', empresa),
          style: TextStyle(
              fontSize: 12, fontWeight: FontWeight.w600, color: cor),
          maxLines: 2,
          overflow: TextOverflow.ellipsis,
        ),
      ),
    ]),
  );
}
