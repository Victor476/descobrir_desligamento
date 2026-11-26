#!/usr/bin/env python3
"""Diagnóstico de Desligamento Aleatório para Windows.

Uso rápido:
  python main.py                  -> Analisa logs, hardware e Caixa-Preta (últimos 14 dias)
  python main.py --dias 30        -> Analisa os últimos 30 dias
  python main.py --monitor        -> Inicia a Caixa-Preta em tempo real (grava até a queda)
  python main.py --abrir          -> Analisa e abre o relatório HTML no navegador
"""

from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from diagnostico.analyzer import analyze_system
from diagnostico.blackbox import (
    DEFAULT_LOG_PATH,
    analyze_blackbox_log,
    run_blackbox_monitor,
)
from diagnostico.report import (
    print_terminal_report,
    save_html_report,
    save_json_report,
)
from diagnostico.windows_collectors import collect_all


def _configure_utf8_console() -> None:
    """Garante saída UTF-8 sem erros de acentuação no terminal do Windows."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    if hasattr(sys.stderr, "reconfigure"):
        try:
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    # Ativa suporte a cores ANSI no Windows 10/11
    if os.name == "nt":
        os.system("")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="descobrir_desligamento",
        description="Investiga por que o PC está desligando aleatoriamente no Windows.",
    )
    parser.add_argument(
        "--monitor",
        action="store_true",
        help="Ativa o modo Caixa-Preta (grava CPU, RAM, temperaturas e energia em tempo real até o PC desligar).",
    )
    parser.add_argument(
        "--intervalo",
        type=float,
        default=2.0,
        help="Intervalo em segundos entre amostras no modo --monitor (padrão: 2.0).",
    )
    parser.add_argument(
        "--dias",
        type=int,
        default=14,
        help="Quantidade de dias de histórico do Windows a analisar (padrão: 14).",
    )
    parser.add_argument(
        "--log-caixa-preta",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help=f"Caminho do arquivo da Caixa-Preta (padrão: {DEFAULT_LOG_PATH}).",
    )
    parser.add_argument(
        "--html",
        type=Path,
        default=Path("relatorios") / "diagnostico_desligamento.html",
        help="Caminho onde salvar o relatório HTML (padrão: relatorios/diagnostico_desligamento.html).",
    )
    parser.add_argument(
        "--sem-html",
        action="store_true",
        help="Não gera arquivo de relatório HTML.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        default=None,
        help="Caminho opcional para exportar os dados completos em JSON.",
    )
    parser.add_argument(
        "--abrir",
        action="store_true",
        help="Abre automaticamente o relatório HTML no navegador após finalizar.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    _configure_utf8_console()
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.monitor:
        run_blackbox_monitor(
            log_path=args.log_caixa_preta,
            interval_sec=max(0.5, args.intervalo),
        )
        return 0

    print(f"Coletando logs do Windows (últimos {args.dias} dias), dumps de BSOD e saúde do hardware...")
    collected = collect_all(days=max(1, args.dias))
    blackbox_summary = analyze_blackbox_log(args.log_caixa_preta)
    report = analyze_system(collected, blackbox_summary=blackbox_summary)

    print_terminal_report(report)

    if not args.sem_html:
        html_path = save_html_report(report, args.html)
        print(f"  Relatório HTML salvo em : {html_path.resolve()}")
        if args.abrir:
            webbrowser.open(html_path.resolve().as_uri())

    if args.json:
        json_path = save_json_report(report, args.json)
        print(f"  Relatório JSON salvo em : {json_path.resolve()}")

    print(
        "\n  DICA: Se o PC continuar desligando sem deixar Tela Azul, rode:\n"
        "        python main.py --monitor   (ou clique duas vezes em iniciar_caixa_preta.bat)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
