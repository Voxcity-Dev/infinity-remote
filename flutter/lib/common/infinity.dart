// Infinity Remote: telas do Infinity que o upstream não tem
// (contrato: infinity-core docs/infinity-remote/contrato-api-cliente.md).
//
// - Chave da empresa (irk_): o admin a copia no assistente "Adicionar computador"
//   (Infinity Remote › Computadores) e cola aqui, em Configurações › Geral › Chave da empresa
//   ou no aviso da janela principal, enquanto o computador não está numa empresa. O serviço
//   reenvia o sysinfo com ela no próximo ciclo (src/hbbs_http/sync.rs). Trocar de empresa
//   só pelo caminho elevado: Configurações › Segurança desbloqueada (ou --infinity-chave
//   como admin); o serviço então apaga o segredo e pede um novo. Só a chave entra: o
//   servidor é sempre o do build.
//
// Nenhum valor de chave, segredo ou token vai para log ou volta para a tela.

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:get/get.dart';
import 'package:flutter_hbb/common.dart';
import 'package:flutter_hbb/models/platform_model.dart';

const kInfinityOpcaoChave = 'infinity-chave';
// Troca de empresa (caminho elevado); o serviço a aplica e não a guarda (src/infinity.rs).
const kInfinityOpcaoTrocaDeChave = 'infinity-chave-troca';
const kInfinityOpcaoSegredo = 'infinity-segredo';
// Local (só desta interface): o aviso da janela principal foi dispensado.
const kInfinityOpcaoLocalAvisoChave = 'infinity-aviso-chave-dispensado';

final _reChave = RegExp(r'^irk_[A-Za-z0-9_-]{43}$');

bool infinityChaveValida(String s) => _reChave.hasMatch(s.trim());

/// Há uma chave da empresa (no formato certo) gravada neste computador.
bool infinityTemChave() =>
    infinityChaveValida(bind.mainGetOptionSync(key: kInfinityOpcaoChave));

/// O computador já entrou numa empresa (recebeu o segredo do Infinity).
bool infinityComputadorNaEmpresa() =>
    bind.mainGetOptionSync(key: kInfinityOpcaoSegredo).isNotEmpty;

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
