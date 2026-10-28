// Infinity Remote: telas e links do Infinity que o upstream não tem
// (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md, "Remote no ticket").
//
// - link infinity-remote://convite/<token>: grava o convite; o serviço o manda no
//   próximo sysinfo (src/hbbs_http/sync.rs) e o apaga depois da resposta.
// - consentimento "técnicos da empresa acessam sem alguém aqui": pergunta única no
//   computador atendido, revogável em Configurações › Segurança.
// - "O que foi feito?": ao encerrar a sessão, o técnico pode anotar o que fez; vai
//   para o resumo do atendimento no ticket.
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
import 'package:flutter_hbb/utils/http_service.dart' as http;

const kInfinityOpcaoConvite = 'infinity-convite';
const kInfinityOpcaoSegredo = 'infinity-segredo';
const kInfinityOpcaoEmpresa = 'infinity-empresa';
const kInfinityOpcaoSemNinguem = 'infinity-acesso-sem-ninguem';
const kInfinityOpcaoLocalPedido = 'infinity-pedido';
const kInfinityOQueFoiFeitoMax = 500;

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

bool infinityConsentimentoDado() =>
    bind.mainGetOptionSync(key: kInfinityOpcaoSemNinguem) == 'Y';

Future<void> infinityGravarConsentimento(bool permitido) => bind.mainSetOption(
    key: kInfinityOpcaoSemNinguem, value: permitido ? 'Y' : 'N');

/// "Permitir que os técnicos de <empresa> acessem este computador sem alguém aqui".
String infinityTextoDoConsentimento() {
  final empresa = bind.mainGetOptionSync(key: kInfinityOpcaoEmpresa).trim();
  if (empresa.isEmpty) {
    return translate('infinity-sem-ninguem-permitir-generico');
  }
  return translate('infinity-sem-ninguem-permitir')
      .replaceAll('{empresa}', empresa);
}

bool _consentimentoPerguntado = false;

/// Chamado pelo relógio da janela principal: quando o computador entra numa empresa e o
/// consentimento nunca foi respondido, pergunta uma vez.
void infinityTalvezPerguntarConsentimento() {
  if (_consentimentoPerguntado) return;
  if (bind.isOutgoingOnly()) {
    _consentimentoPerguntado = true;
    return;
  }
  if (!infinityComputadorNaEmpresa()) return;
  if (bind.mainGetOptionSync(key: kInfinityOpcaoSemNinguem).isNotEmpty) {
    _consentimentoPerguntado = true;
    return;
  }
  _consentimentoPerguntado = true;
  gFFI.dialogManager.show((setState, close, context) {
    responder(bool permitido) async {
      await infinityGravarConsentimento(permitido);
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
            Text(infinityTextoDoConsentimento(),
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
  }, tag: 'infinity-consentimento');
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
    for (final s in lista) {
      if (s is Map &&
          s['rustdesk_id'] == peerId &&
          s['o_que_foi_feito_registrado'] != true &&
          s['id'] is String) {
        return s['id'] as String;
      }
    }
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
