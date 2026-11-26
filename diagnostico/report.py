"""Formatação de saída no terminal e geração de relatório HTML e JSON."""

from __future__ import annotations

import html
import json
import os
import sys
from pathlib import Path
from typing import Any

from .analyzer import DiagnosisReport


def _supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class _Color:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def bold(self, text: str) -> str:
        return self.wrap("1", text)

    def red(self, text: str) -> str:
        return self.wrap("91", text)

    def yellow(self, text: str) -> str:
        return self.wrap("93", text)

    def green(self, text: str) -> str:
        return self.wrap("92", text)

    def cyan(self, text: str) -> str:
        return self.wrap("96", text)

    def dim(self, text: str) -> str:
        return self.wrap("2", text)


def print_terminal_report(report: DiagnosisReport) -> None:
    """Imprime um relatório limpo e direto no terminal."""
    c = _Color(_supports_color())
    line = "=" * 74
    sub = "-" * 74

    print("\n" + c.cyan(line))
    print(c.bold("  DIAGNÓSTICO DE DESLIGAMENTO ALEATÓRIO DO PC"))
    print(c.cyan(line))

    data = report.data
    sysinfo = data.system_info if data else {}
    if sysinfo:
        print(f"  Computador : {sysinfo.get('hostname', 'N/D')} | {sysinfo.get('os_caption', 'Windows')}")
        print(f"  CPU        : {sysinfo.get('cpu_name', 'N/D')}")
        print(f"  Placa-mãe  : {sysinfo.get('motherboard', 'N/D')} (BIOS {sysinfo.get('bios_version', 'N/D')})")
        print(f"  Memória    : {sysinfo.get('total_ram_gb', 'N/D')} GB")
    if data and data.license_info:
        lic = data.license_info
        lic_txt = f"{lic.get('name', 'Windows')} — {lic.get('license_status_text', lic.get('license_status'))}"
        if lic.get("is_evaluation") and (lic.get("license_status") in (0, 5) or lic.get("grace_period_minutes") == 0):
            lic_txt = c.red(lic_txt + " [EXPIRADA]")
        print(f"  Licença    : {lic_txt}")
    print(f"  Período    : Últimos {report.days_analyzed} dias | Gerado em {report.generated_at.strftime('%d/%m/%Y %H:%M:%S')}")
    if data:
        priv = c.green("Administrador") if data.is_admin else c.yellow("Usuário padrão (alguns sensores/dumps podem ficar ocultos)")
        print(f"  Privilégio : {priv}")

    # Avisos de coleta
    if data and data.warnings:
        print("\n" + c.yellow("  [AVISOS DA COLETA]"))
        for w in data.warnings:
            print(f"   - {w}")

    # Alertas imediatos de saúde
    if report.health_alerts:
        print("\n" + c.red("  [ALERTAS IMEDIATOS DE HARDWARE]"))
        for alert in report.health_alerts:
            print(f"   ! {alert}")

    # Resumo da Caixa-Preta se houver
    if report.blackbox_summary:
        bb = report.blackbox_summary
        print("\n" + c.bold("  [CAIXA-PRETA — MONITORAMENTO EM TEMPO REAL]"))
        if bb.get("interrupted_detected"):
            print("   " + c.red(f"QUEDA ABRUPTA CAPTURADA! Último registro: {bb.get('last_timestamp')}"))
            print(f"   Veredito : {c.bold(str(bb.get('verdict')))}")
            print(
                f"   Últimos ~30s -> CPU média: {bb.get('last_avg_cpu_pct')}% | RAM: {bb.get('last_avg_ram_pct')}% | "
                f"Temp CPU max: {bb.get('last_max_cpu_temp_c') or 'N/D'}°C | "
                f"Temp GPU max: {bb.get('last_max_gpu_temp_c') or 'N/D'}°C | "
                f"Potência GPU max: {bb.get('last_max_gpu_power_w') or 'N/D'}W | "
                f"Processo topo: {bb.get('last_top_process') or 'N/D'}"
            )
        else:
            print(f"   {bb.get('message')}")

    # Contagem de eventos
    print("\n" + c.bold(f"  [RESUMO DOS LOGS DO WINDOWS — {report.total_unexpected_shutdowns} DESLIGAMENTO(S) INESPERADO(S)]"))
    print("  " + sub)
    for label, count in report.event_counts.items():
        val_str = c.red(str(count)) if count > 0 and "Solicitados" not in label else str(count)
        print(f"   {label:<46} : {val_str}")

    # Sensores de temperatura atuais
    if data and data.temperatures:
        print("\n" + c.bold("  [TEMPERATURAS ATUAIS DETECTADAS]"))
        for t in data.temperatures[:8]:
            temp_val = t.get("temp_c")
            temp_fmt = f"{temp_val:.1f}°C" if isinstance(temp_val, (int, float)) else "N/D"
            if isinstance(temp_val, (int, float)) and temp_val >= 85:
                temp_fmt = c.red(temp_fmt)
            elif isinstance(temp_val, (int, float)) and temp_val >= 72:
                temp_fmt = c.yellow(temp_fmt)
            else:
                temp_fmt = c.green(temp_fmt)
            print(f"   - {t.get('sensor')} ({t.get('source')}): {temp_fmt}")

    # Hipóteses ranqueadas
    print("\n" + c.cyan(line))
    print(c.bold("  PROVÁVEIS CAUSAS (DA MAIS PROVÁVEL PARA A MENOS PROVÁVEL)"))
    print(c.cyan(line))
    for idx, hyp in enumerate(report.hypotheses, start=1):
        badge = f"[{hyp.confidence} — {hyp.score}%]"
        if hyp.confidence == "ALTA":
            badge_colored = c.red(badge)
        elif hyp.confidence == "MÉDIA":
            badge_colored = c.yellow(badge)
        else:
            badge_colored = c.green(badge)

        print(f"\n  {idx}. {c.bold(hyp.title)}  {badge_colored}")
        print("     Evidências:")
        for ev in hyp.evidences:
            print(f"       • {ev}")
        print("     O que fazer:")
        for rec in hyp.recommendations:
            print(f"       → {rec}")

    # Linha do tempo dos últimos incidentes
    if report.incidents:
        print("\n" + c.bold("  [LINHA DO TEMPO DOS ÚLTIMOS DESLIGAMENTOS INESPERADOS]"))
        print("  " + sub)
        for inc in report.incidents[:10]:
            ts = inc.timestamp.strftime("%d/%m/%Y %H:%M:%S")
            print(f"   • {c.bold(ts)} — {c.yellow(inc.kind)} (ID {inc.primary_event_id})")
            print(f"     {inc.summary}")
            if inc.related_events:
                rel_tags = ", ".join(
                    f"{r.provider}#{r.event_id}" for r in inc.related_events[:5]
                )
                print(c.dim(f"     Eventos próximos: {rel_tags}"))

    print("\n" + c.cyan(line))


def save_json_report(report: DiagnosisReport, output_path: Path) -> Path:
    """Exporta o diagnóstico completo em formato JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return output_path


def _e(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def save_html_report(report: DiagnosisReport, output_path: Path) -> Path:
    """Gera um relatório HTML moderno, autônomo e fácil de ler no navegador."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    data = report.data
    sysinfo = data.system_info if data else {}

    def _badge_class(conf: str) -> str:
        return {"ALTA": "badge-high", "MÉDIA": "badge-med", "BAIXA": "badge-low"}.get(conf, "badge-low")

    # Cartões de hipóteses
    hyp_cards = []
    for idx, h in enumerate(report.hypotheses, start=1):
        ev_items = "".join(f"<li>{_e(ev)}</li>" for ev in h.evidences)
        rec_items = "".join(f"<li>{_e(r)}</li>" for r in h.recommendations)
        hyp_cards.append(
            f"""
            <div class="card hyp-card">
              <div class="hyp-header">
                <h3>{idx}. {_e(h.title)}</h3>
                <span class="badge {_badge_class(h.confidence)}">{_e(h.confidence)} ({h.score}%)</span>
              </div>
              <div class="bar-track"><div class="bar-fill {_badge_class(h.confidence)}" style="width:{h.score}%"></div></div>
              <div class="two-col">
                <div>
                  <h4>Evidências Encontradas</h4>
                  <ul>{ev_items}</ul>
                </div>
                <div>
                  <h4>Ações Recomendadas</h4>
                  <ul>{rec_items}</ul>
                </div>
              </div>
            </div>
            """
        )

    # Tabela de incidentes
    if report.incidents:
        inc_rows = []
        for inc in report.incidents[:25]:
            rel = ", ".join(f"{r.provider} #{r.event_id}" for r in inc.related_events[:5]) or "Nenhum"
            inc_rows.append(
                f"""
                <tr>
                  <td>{_e(inc.timestamp.strftime('%d/%m/%Y %H:%M:%S'))}</td>
                  <td><strong>{_e(inc.kind)}</strong></td>
                  <td><code>{_e(f'0x{inc.bugcheck_code:08X}' if inc.bugcheck_code else '0x0')}</code></td>
                  <td>{_e(inc.summary)}</td>
                  <td class="muted">{_e(rel)}</td>
                </tr>
                """
            )
        incidents_html = f"""
        <table>
          <thead>
            <tr><th>Data/Hora</th><th>Classificação</th><th>BugCheck</th><th>Detalhes</th><th>Eventos Próximos</th></tr>
          </thead>
          <tbody>{''.join(inc_rows)}</tbody>
        </table>
        """
    else:
        incidents_html = "<p class='muted'>Nenhum desligamento inesperado foi registrado neste período.</p>"

    # Contadores
    count_cards = "".join(
        f"<div class='stat'><div class='stat-val'>{v}</div><div class='stat-lbl'>{_e(k)}</div></div>"
        for k, v in report.event_counts.items()
    )

    # Caixa-Preta
    bb_html = ""
    if report.blackbox_summary:
        bb = report.blackbox_summary
        if bb.get("interrupted_detected"):
            bb_html = f"""
            <div class="card alert-card">
              <h3>Caixa-Preta: Queda Abrupta Capturada!</h3>
              <p><strong>Veredito:</strong> {_e(bb.get('verdict'))}</p>
              <p>
                Último registro: <code>{_e(bb.get('last_timestamp'))}</code> |
                CPU média: <strong>{_e(bb.get('last_avg_cpu_pct'))}%</strong> |
                RAM média: <strong>{_e(bb.get('last_avg_ram_pct'))}%</strong> |
                Temp CPU máx: <strong>{_e(bb.get('last_max_cpu_temp_c') or 'N/D')}°C</strong> |
                Temp GPU máx: <strong>{_e(bb.get('last_max_gpu_temp_c') or 'N/D')}°C</strong> |
                GPU Potência máx: <strong>{_e(bb.get('last_max_gpu_power_w') or 'N/D')}W</strong> |
                Processo principal: <code>{_e(bb.get('last_top_process') or 'N/D')}</code>
              </p>
            </div>
            """
        else:
            bb_html = f"<div class='card'><h3>Caixa-Preta</h3><p class='muted'>{_e(bb.get('message'))}</p></div>"

    # Hardware (discos e temperaturas)
    temp_rows = ""
    if data and data.temperatures:
        temp_rows = "".join(
            f"<tr><td>{_e(t.get('sensor'))}</td><td>{_e(t.get('source'))}</td><td><strong>{_e(t.get('temp_c'))}°C</strong></td></tr>"
            for t in data.temperatures
        )
    else:
        temp_rows = "<tr><td colspan='3' class='muted'>Nenhum sensor de temperatura exposto (execute como Administrador ou abra o LibreHardwareMonitor).</td></tr>"

    disk_rows = ""
    if data and data.disks:
        disk_rows = "".join(
            f"<tr><td>{_e(d.get('model'))}</td><td>{_e(d.get('bus_type'))}</td><td>{_e(d.get('health_status'))}</td>"
            f"<td>{_e(d.get('temperature_c') if d.get('temperature_c') is not None else 'N/D')}°C</td>"
            f"<td>{_e(d.get('wear_pct') if d.get('wear_pct') is not None else 'N/D')}%</td></tr>"
            for d in data.disks
        )
    else:
        disk_rows = "<tr><td colspan='5' class='muted'>Nenhum disco listado.</td></tr>"

    alerts_block = ""
    if report.health_alerts:
        al_items = "".join(f"<li>{_e(a)}</li>" for a in report.health_alerts)
        alerts_block = f"<div class='card alert-card'><h3>Alertas Imediatos de Hardware</h3><ul>{al_items}</ul></div>"

    warnings_block = ""
    if data and data.warnings:
        w_items = "".join(f"<li>{_e(w)}</li>" for w in data.warnings)
        warnings_block = f"<div class='card warn-card'><h3>Avisos da Coleta</h3><ul>{w_items}</ul></div>"

    html_doc = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Diagnóstico de Desligamento do PC</title>
  <style>
    :root {{
      --bg: #0f172a; --panel: #1e293b; --border: #334155;
      --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
      --high: #ef4444; --med: #f59e0b; --low: #22c55e;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; padding: 28px 20px; font-family: "Segoe UI", system-ui, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.55;
    }}
    .container {{ max-width: 1120px; margin: 0 auto; }}
    header {{
      background: linear-gradient(135deg, #1e293b, #0f172a);
      border: 1px solid var(--border); border-radius: 14px; padding: 24px; margin-bottom: 20px;
    }}
    h1 {{ margin: 0 0 8px 0; font-size: 1.7rem; color: #f8fafc; }}
    h2 {{ margin: 28px 0 12px 0; font-size: 1.25rem; color: var(--accent); }}
    h3 {{ margin: 0 0 10px 0; font-size: 1.08rem; }}
    h4 {{ margin: 12px 0 6px 0; font-size: 0.92rem; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }}
    .meta {{ color: var(--muted); font-size: 0.92rem; display: flex; flex-wrap: wrap; gap: 16px; }}
    .card {{
      background: var(--panel); border: 1px solid var(--border);
      border-radius: 12px; padding: 18px 20px; margin-bottom: 16px;
    }}
    .alert-card {{ border-color: var(--high); background: rgba(239, 68, 68, 0.08); }}
    .warn-card {{ border-color: var(--med); background: rgba(245, 158, 11, 0.08); }}
    .stats-grid {{
      display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 12px; margin-bottom: 18px;
    }}
    .stat {{
      background: var(--panel); border: 1px solid var(--border); border-radius: 10px; padding: 14px;
    }}
    .stat-val {{ font-size: 1.6rem; font-weight: 700; color: #f8fafc; }}
    .stat-lbl {{ font-size: 0.84rem; color: var(--muted); margin-top: 4px; }}
    .hyp-header {{ display: flex; justify-content: space-between; align-items: center; gap: 12px; flex-wrap: wrap; }}
    .badge {{ padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: 700; color: #0f172a; }}
    .badge-high {{ background: var(--high); color: #fff; }}
    .badge-med {{ background: var(--med); color: #0f172a; }}
    .badge-low {{ background: var(--low); color: #0f172a; }}
    .bar-track {{ height: 7px; background: #0f172a; border-radius: 999px; overflow: hidden; margin: 10px 0 12px; }}
    .bar-fill {{ height: 100%; border-radius: 999px; }}
    .two-col {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 16px; }}
    ul {{ margin: 6px 0; padding-left: 20px; }}
    li {{ margin-bottom: 6px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; background: rgba(15, 23, 42, 0.45); }}
    .muted {{ color: var(--muted); }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 5px; font-size: 0.85em; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <h1>Diagnóstico de Desligamento Aleatório do PC</h1>
      <div class="meta">
        <span><strong>Máquina:</strong> {_e(sysinfo.get('hostname', 'N/D'))}</span>
        <span><strong>Sistema:</strong> {_e(sysinfo.get('os_caption', 'Windows'))}</span>
        <span><strong>CPU:</strong> {_e(sysinfo.get('cpu_name', 'N/D'))}</span>
        <span><strong>Placa-mãe:</strong> {_e(sysinfo.get('motherboard', 'N/D'))}</span>
        <span><strong>RAM:</strong> {_e(sysinfo.get('total_ram_gb', 'N/D'))} GB</span>
        <span><strong>Licença:</strong> {_e((data.license_info or {}).get('license_status_text', 'N/D') if data else 'N/D')}</span>
        <span><strong>Período:</strong> Últimos {report.days_analyzed} dias</span>
        <span><strong>Gerado em:</strong> {_e(report.generated_at.strftime('%d/%m/%Y %H:%M:%S'))}</span>
      </div>
    </header>

    {alerts_block}
    {bb_html}
    {warnings_block}

    <h2>Resumo dos Eventos do Windows</h2>
    <div class="stats-grid">{count_cards}</div>

    <h2>Causas Mais Prováveis</h2>
    {''.join(hyp_cards)}

    <h2>Linha do Tempo de Desligamentos Inesperados</h2>
    <div class="card">{incidents_html}</div>

    <h2>Saúde Atual do Hardware</h2>
    <div class="two-col">
      <div class="card">
        <h3>Sensores de Temperatura</h3>
        <table>
          <thead><tr><th>Sensor</th><th>Fonte</th><th>Temp.</th></tr></thead>
          <tbody>{temp_rows}</tbody>
        </table>
      </div>
      <div class="card">
        <h3>Discos / SSDs</h3>
        <table>
          <thead><tr><th>Modelo</th><th>Barramento</th><th>Saúde</th><th>Temp.</th><th>Desgaste</th></tr></thead>
          <tbody>{disk_rows}</tbody>
        </table>
      </div>
    </div>
  </div>
</body>
</html>
"""
    output_path.write_text(html_doc, encoding="utf-8")
    return output_path
