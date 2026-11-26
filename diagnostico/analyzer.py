"""Motor de análise e diagnóstico de desligamentos aleatórios no Windows.

Correlaciona eventos do sistema (Kernel-Power 41, EventLog 6008, WHEA-Logger,
BugCheck 1001, User32 1074, zonas térmicas, erros de disco/vídeo), dumps de BSOD,
saúde do hardware e registros da Caixa-Preta (quando disponíveis).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from .windows_collectors import CollectedData, KNOWN_BUGCHECKS, SystemEvent


@dataclass
class ShutdownIncident:
    """Representa um evento de desligamento inesperado com contexto correlacionado."""

    timestamp: datetime
    kind: str  # "Perda Súbita de Energia", "Tela Azul (BSOD)", "Desligamento Térmico", "Desligamento por Software"
    primary_event_id: int
    bugcheck_code: int = 0
    bugcheck_name: str = ""
    power_button_timestamp: int = 0
    thermal_state: int | None = None
    summary: str = ""
    related_events: list[SystemEvent] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "kind": self.kind,
            "primary_event_id": self.primary_event_id,
            "bugcheck_code": self.bugcheck_code,
            "bugcheck_hex": f"0x{self.bugcheck_code:08X}" if self.bugcheck_code else "0x0",
            "bugcheck_name": self.bugcheck_name,
            "power_button_timestamp": self.power_button_timestamp,
            "thermal_state": self.thermal_state,
            "summary": self.summary,
            "related_events": [e.to_dict() for e in self.related_events],
        }


@dataclass
class CauseHypothesis:
    """Hipótese diagnóstica ranqueada com evidências e ações recomendadas."""

    cause_id: str
    title: str
    confidence: str  # "ALTA", "MÉDIA", "BAIXA"
    score: int  # 0..100
    evidences: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "cause_id": self.cause_id,
            "title": self.title,
            "confidence": self.confidence,
            "score": self.score,
            "evidences": self.evidences,
            "recommendations": self.recommendations,
        }


@dataclass
class DiagnosisReport:
    """Resultado completo do diagnóstico."""

    generated_at: datetime
    days_analyzed: int
    total_unexpected_shutdowns: int
    incidents: list[ShutdownIncident]
    hypotheses: list[CauseHypothesis]
    event_counts: dict[str, int]
    health_alerts: list[str]
    blackbox_summary: dict[str, Any] | None = None
    data: CollectedData | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at.isoformat(),
            "days_analyzed": self.days_analyzed,
            "total_unexpected_shutdowns": self.total_unexpected_shutdowns,
            "event_counts": self.event_counts,
            "health_alerts": self.health_alerts,
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "incidents": [i.to_dict() for i in self.incidents],
            "blackbox_summary": self.blackbox_summary,
            "collected_data": self.data.to_dict() if self.data else None,
        }


def _safe_int(value: Any, default: int = 0) -> int:
    if value is None or value == "":
        return default
    try:
        s = str(value).strip()
        if s.lower().startswith("0x"):
            return int(s, 16)
        return int(s)
    except (ValueError, TypeError):
        return default


def _lookup_bugcheck(code: int) -> tuple[str, str]:
    if code == 0:
        return ("", "")
    if code in KNOWN_BUGCHECKS:
        return KNOWN_BUGCHECKS[code]
    return (f"BUGCHECK_0x{code:08X}", "Código de parada do Windows (BSOD). Pesquise o código exato ou analise o Minidump.")


def _confidence_from_score(score: int) -> str:
    if score >= 65:
        return "ALTA"
    if score >= 35:
        return "MÉDIA"
    return "BAIXA"


def _correlate_incidents(events: list[SystemEvent]) -> list[ShutdownIncident]:
    """Constrói a linha do tempo de desligamentos inesperados e correlaciona eventos próximos."""
    incidents: list[ShutdownIncident] = []
    # Eventos primários: Kernel-Power 41 (mais informativo) e EventLog 6008 (fallback)
    kp41_events = [
        e for e in events if e.event_id == 41 and "kernel-power" in e.provider.lower()
    ]
    e6008_events = [e for e in events if e.event_id == 6008]

    # Usamos Kernel-Power 41 como âncora principal
    used_timestamps: list[datetime] = []

    for ev in kp41_events:
        props = ev.properties or {}
        bugcheck = _safe_int(props.get("BugcheckCode", props.get("Param0", 0)))
        power_btn = _safe_int(props.get("PowerButtonTimestamp", props.get("Param6", 0)))
        thermal = props.get("ThermalState")
        thermal_val = _safe_int(thermal) if thermal not in (None, "") else None

        bc_name, bc_desc = _lookup_bugcheck(bugcheck)

        # Busca eventos relevantes em uma janela de 10 minutos antes até 2 minutos depois
        window_start = ev.timestamp - timedelta(minutes=10)
        window_end = ev.timestamp + timedelta(minutes=2)
        related = [
            other
            for other in events
            if other is not ev
            and window_start <= other.timestamp <= window_end
            and other.event_id in {18, 19, 20, 46, 47, 86, 87, 88, 89, 1001, 4101, 7, 11, 51, 129, 153, 6008, 1074}
        ]

        has_thermal = any(r.event_id in {86, 87, 88, 89} for r in related) or (
            thermal_val is not None and thermal_val > 0
        )
        has_whea = any(
            r.event_id in {18, 19, 20, 46, 47} and "whea" in r.provider.lower()
            for r in related
        )
        has_bugcheck_ev = any(r.event_id == 1001 for r in related)

        if bugcheck != 0 or has_bugcheck_ev:
            kind = "Tela Azul (BSOD)"
            summary = (
                f"Reinicialização após Tela Azul: {bc_name} (0x{bugcheck:08X}). {bc_desc}"
                if bugcheck != 0
                else "Reinicialização após erro crítico BugCheck (Event ID 1001)."
            )
        elif has_thermal:
            kind = "Desligamento Térmico (Superaquecimento)"
            summary = "O sistema registrou alerta térmico crítico (ACPI/Kernel-Power) próximo ao desligamento."
        elif has_whea:
            kind = "Erro Fatal de Hardware (WHEA)"
            summary = "Erro grave de hardware (CPU/RAM/PCIe) registrado pelo WHEA-Logger junto ao desligamento."
        elif power_btn > 0:
            kind = "Desligamento Forçado (Botão Power)"
            summary = "O botão físico de energia foi pressionado (pode indicar congelamento prévio do PC)."
        else:
            kind = "Perda Súbita de Energia (Kernel-Power 41 sem BSOD)"
            summary = (
                "Desligamento abrupto com BugcheckCode=0 (o Windows não conseguiu gravar Tela Azul). "
                "Típico de fonte (PSU), superaquecimento súbito, placa-mãe/VRM ou rede elétrica."
            )

        incidents.append(
            ShutdownIncident(
                timestamp=ev.timestamp,
                kind=kind,
                primary_event_id=41,
                bugcheck_code=bugcheck,
                bugcheck_name=bc_name,
                power_button_timestamp=power_btn,
                thermal_state=thermal_val,
                summary=summary,
                related_events=related,
            )
        )
        used_timestamps.append(ev.timestamp)

    # Inclui EventLog 6008 que não tenham um Kernel-Power 41 dentro de 3 minutos
    for ev in e6008_events:
        if any(abs((ev.timestamp - ts).total_seconds()) <= 180 for ts in used_timestamps):
            continue
        window_start = ev.timestamp - timedelta(minutes=10)
        window_end = ev.timestamp + timedelta(minutes=2)
        related = [
            other
            for other in events
            if other is not ev
            and window_start <= other.timestamp <= window_end
            and other.event_id in {18, 19, 20, 46, 47, 86, 87, 88, 89, 1001, 4101, 7, 11, 51, 129, 153}
        ]
        incidents.append(
            ShutdownIncident(
                timestamp=ev.timestamp,
                kind="Desligamento Inesperado (EventLog 6008)",
                primary_event_id=6008,
                summary=ev.message[:220] if ev.message else "O desligamento anterior do sistema foi inesperado.",
                related_events=related,
            )
        )

    # Inclui desligamentos forçados pelo WLMS (User32 1074 acionado por wlms.exe ou WLMS 101)
    wlms_shutdown_events = [
        e
        for e in events
        if (e.event_id == 1074 and "wlms.exe" in (e.message or "").lower())
        or (e.provider.lower() == "wlms" and e.event_id == 101)
    ]
    wlms_seen_ts: list[datetime] = []
    for ev in wlms_shutdown_events:
        if any(abs((ev.timestamp - ts).total_seconds()) <= 90 for ts in wlms_seen_ts):
            continue
        wlms_seen_ts.append(ev.timestamp)
        incidents.append(
            ShutdownIncident(
                timestamp=ev.timestamp,
                kind="Desligamento por Licença de Avaliação Expirada (WLMS)",
                primary_event_id=ev.event_id,
                summary=(
                    "O serviço wlms.exe (Windows Licensing Monitoring Service) desligou o computador "
                    "automaticamente porque o período de avaliação do Windows expirou (desliga a cada 1 hora)."
                ),
            )
        )

    incidents.sort(key=lambda i: i.timestamp, reverse=True)
    return incidents


def analyze_system(
    data: CollectedData,
    blackbox_summary: dict[str, Any] | None = None,
) -> DiagnosisReport:
    """Analisa todos os dados coletados e gera hipóteses ranqueadas de causa raiz."""
    events = data.events
    incidents = _correlate_incidents(events)

    # Contagens por categoria
    kp41_all = [e for e in events if e.event_id == 41 and "kernel-power" in e.provider.lower()]
    kp41_clean_powerloss = [
        inc for inc in incidents if inc.primary_event_id == 41 and inc.bugcheck_code == 0 and inc.power_button_timestamp == 0
    ]
    kp41_bsod = [inc for inc in incidents if inc.bugcheck_code != 0]
    e6008_all = [e for e in events if e.event_id == 6008]
    bugcheck_1001 = [
        e for e in events
        if e.event_id == 1001 and any(k in e.provider.lower() for k in ("bugcheck", "wer-systemerrorreporting"))
    ]
    whea_events = [
        e for e in events if e.event_id in {18, 19, 20, 46, 47} and "whea" in e.provider.lower()
    ]
    whea_fatal = [e for e in whea_events if e.event_id in {18, 20, 46}]
    thermal_events = [e for e in events if e.event_id in {86, 87, 88, 89}]
    throttle_events = [e for e in events if e.event_id == 37]
    gpu_tdr_events = [e for e in events if e.event_id == 4101]
    disk_error_events = [e for e in events if e.event_id in {7, 11, 51, 129, 153}]
    software_shutdowns = [e for e in events if e.event_id == 1074]
    wlms_events = [e for e in events if e.provider.lower() == "wlms"]
    wlms_1074_events = [
        e for e in software_shutdowns if "wlms.exe" in (e.message or "").lower()
    ]

    event_counts = {
        "Kernel-Power 41 (Desligamento Inesperado)": len(kp41_all),
        "EventLog 6008 (Desligamento Abrupto)": len(e6008_all),
        "WLMS (Licença Evaluation Expirada)": len(wlms_events) + len(wlms_1074_events),
        "BugCheck 1001 / BSOD": len(bugcheck_1001),
        "Minidumps (.dmp) encontrados": len(data.crash_dumps),
        "WHEA-Logger (Erros de Hardware)": len(whea_events),
        "Alertas Térmicos (ACPI 86-89)": len(thermal_events),
        "Driver de Vídeo Travou (Display 4101)": len(gpu_tdr_events),
        "Erros de Disco/SSD (7/11/51/129/153)": len(disk_error_events),
        "Desligamentos Solicitados (User32 1074)": len(software_shutdowns),
    }

    # Alertas imediatos de saúde atual do hardware
    health_alerts: list[str] = []
    max_temp_c = 0.0
    hot_sensors: list[str] = []
    for t in data.temperatures:
        val = t.get("temp_c")
        if isinstance(val, (int, float)):
            if val > max_temp_c:
                max_temp_c = float(val)
            if val >= 85.0:
                hot_sensors.append(f"{t.get('sensor', 'Sensor')}: {val:.1f}°C")
    if hot_sensors:
        health_alerts.append("Temperatura atual elevada detectada: " + ", ".join(hot_sensors))

    unhealthy_disks: list[str] = []
    for d in data.disks:
        hs = str(d.get("health_status") or "").lower()
        wear = d.get("wear_pct")
        temp = d.get("temperature_c")
        r_err = d.get("read_errors") or 0
        w_err = d.get("write_errors") or 0
        if hs and hs not in ("healthy", "ok"):
            unhealthy_disks.append(f"{d.get('model', 'Disco')} (status: {d.get('health_status')})")
        elif (isinstance(wear, (int, float)) and wear >= 90) or r_err > 0 or w_err > 0:
            unhealthy_disks.append(
                f"{d.get('model', 'Disco')} (desgaste={wear}%, erros leitura={r_err}, escrita={w_err})"
            )
        if isinstance(temp, (int, float)) and temp >= 70:
            health_alerts.append(f"SSD/Disco quente: {d.get('model', 'Disco')} em {temp}°C.")
    if unhealthy_disks:
        health_alerts.append("Disco com sinal de desgaste ou falha: " + "; ".join(unhealthy_disks))

    if data.battery:
        charge = data.battery.get("charge_pct")
        status = str(data.battery.get("status") or "").lower()
        if status and status not in ("ok", "healthy"):
            health_alerts.append(f"Status da bateria anormal: {data.battery.get('status')}")
        if isinstance(charge, int) and charge <= 10:
            health_alerts.append(f"Bateria muito baixa ({charge}%).")

    # --- Pontuação de Hipóteses ---
    hypotheses: list[CauseHypothesis] = []

    # 0. Licença Windows Evaluation Expirada (WLMS — desliga a cada 1 hora!)
    lic = data.license_info or {}
    os_caption = str((data.system_info or {}).get("os_caption") or "")
    is_eval_os = bool(lic.get("is_evaluation")) or ("evaluation" in os_caption.lower())
    lic_status = lic.get("license_status")
    grace_min = lic.get("grace_period_minutes")
    eval_expired = is_eval_os and (lic_status in (0, 5) or grace_min == 0)

    if eval_expired or wlms_events or wlms_1074_events:
        wlms_score = 0
        wlms_ev: list[str] = []
        if eval_expired:
            wlms_score += 55
            wlms_ev.append(
                f"Sistema rodando edição de avaliação expirada: {lic.get('name') or os_caption} "
                f"(Status={lic.get('license_status_text', lic_status)}, tempo restante={grace_min} min)."
            )
            health_alerts.insert(
                0,
                "LICENÇA DE AVALIAÇÃO DO WINDOWS EXPIRADA: O serviço WLMS desliga este PC automaticamente a cada 1 hora!",
            )
        if wlms_events:
            wlms_score += 35
            wlms_ev.append(
                f"{len(wlms_events)} evento(s) do serviço WLMS no Log Application confirmando expiração da licença e desligamento a cada hora."
            )
        if wlms_1074_events:
            wlms_score += 35
            wlms_ev.append(
                f"{len(wlms_1074_events)} evento(s) User32 1074 disparados diretamente por `wlms.exe` desligando o PC."
            )
        wlms_score = min(99, max(wlms_score, 85 if (wlms_events or wlms_1074_events) else 75))
        hypotheses.append(
            CauseHypothesis(
                cause_id="windows_eval_expired",
                title="Licença de Avaliação do Windows (Evaluation) Expirada — Desligamento Automático a Cada 1 Hora",
                confidence=_confidence_from_score(wlms_score),
                score=wlms_score,
                evidences=wlms_ev,
                recommendations=[
                    "NÃO é defeito de hardware (fonte, placa-mãe ou temperatura) — é um comportamento intencional das edições Evaluation da Microsoft após 90 dias.",
                    "Faça backup dos seus arquivos importantes antes de qualquer alteração.",
                    "Para resolver definitivamente, instale uma edição comercial licenciada do Windows (ex: Windows 11 Home ou Pro via Media Creation Tool oficial da Microsoft, ou uma licença comercial de Enterprise/LTSC), pois edições Evaluation não aceitam ativação direta com chaves varejo comuns.",
                    "Verifique também a data/hora do relógio do sistema, pois uma data adiantada no BIOS/Windows pode fazer o período de avaliação expirar prematuramente.",
                ],
            )
        )

    # 1. Fonte de Alimentação (PSU) / Rede Elétrica / Placa-mãe
    psu_score = 0
    psu_ev: list[str] = []
    if kp41_clean_powerloss:
        psu_score += min(65, 35 + len(kp41_clean_powerloss) * 10)
        psu_ev.append(
            f"{len(kp41_clean_powerloss)} evento(s) Kernel-Power 41 com BugcheckCode=0 (morte súbita sem Tela Azul)."
        )
    if kp41_clean_powerloss and not data.crash_dumps and not bugcheck_1001:
        psu_score += 15
        psu_ev.append("Nenhum arquivo de Minidump/BSOD gerado — típico de corte instantâneo de energia.")
    if kp41_clean_powerloss and not thermal_events and max_temp_c < 80:
        psu_score += 10
        psu_ev.append("Sem registros de superaquecimento no log do sistema.")
    if blackbox_summary and blackbox_summary.get("interrupted_detected"):
        bb_gpu_temp = blackbox_summary.get("last_max_gpu_temp_c") or 0
        bb_cpu_temp = blackbox_summary.get("last_max_cpu_temp_c") or 0
        bb_gpu_power = blackbox_summary.get("last_max_gpu_power_w") or 0
        if bb_gpu_temp < 82 and bb_cpu_temp < 85:
            psu_score += 15
            psu_ev.append(
                f"A Caixa-Preta mostrou temperaturas normais antes da queda (GPU max {bb_gpu_temp:.1f}°C, CPU max {bb_cpu_temp:.1f}°C)."
            )
            if bb_gpu_power >= 150:
                psu_ev.append(
                    f"Consumo da GPU estava alto ({bb_gpu_power:.0f}W) no momento da queda — forte indício de desarme de proteção (OCP/OPP) da fonte!"
                )
                psu_score += 10
    if psu_score > 0:
        psu_score = min(98, psu_score)
        hypotheses.append(
            CauseHypothesis(
                cause_id="power_psu",
                title="Fonte de Alimentação (PSU), Cabos ou Rede Elétrica",
                confidence=_confidence_from_score(psu_score),
                score=psu_score,
                evidences=psu_ev,
                recommendations=[
                    "Verifique cabos de energia (24 pinos da placa-mãe, EPS 8 pinos da CPU e PCIe da GPU) — desconecte e reconecte firmemente.",
                    "Teste ligar o PC direto na tomada (sem estabilizador — estabilizadores danificam fontes com PFC ativo; use apenas filtro de linha bom).",
                    "Se acontece ao abrir jogos ou sob carga pesada, a fonte pode estar sem potência suficiente ou com capacitores degradados (teste com outra fonte).",
                    "Se for notebook, teste sem a bateria ou verifique se o carregador/conector DC está com mau contato.",
                ],
            )
        )

    # 2. Superaquecimento (CPU / GPU / VRM)
    therm_score = 0
    therm_ev: list[str] = []
    if thermal_events:
        therm_score += min(75, 50 + len(thermal_events) * 10)
        therm_ev.append(f"{len(thermal_events)} evento(s) térmico(s) crítico(s) registrados pelo Windows (IDs 86-89).")
    if throttle_events:
        therm_score += min(20, len(throttle_events) * 5)
        therm_ev.append(f"{len(throttle_events)} evento(s) de redução de clock do processador (Event ID 37).")
    if max_temp_c >= 85:
        therm_score += 30
        therm_ev.append(f"Temperatura atual já está alta ({max_temp_c:.1f}°C).")
    elif max_temp_c >= 75:
        therm_score += 12
        therm_ev.append(f"Temperatura atual relativamente elevada ({max_temp_c:.1f}°C) mesmo durante o diagnóstico.")
    if blackbox_summary and blackbox_summary.get("interrupted_detected"):
        bb_gpu_temp = blackbox_summary.get("last_max_gpu_temp_c") or 0
        bb_cpu_temp = blackbox_summary.get("last_max_cpu_temp_c") or 0
        if bb_cpu_temp >= 90 or bb_gpu_temp >= 88:
            therm_score += 45
            therm_ev.append(
                f"Caixa-Preta registrou temperatura crítica nos segundos finais (CPU: {bb_cpu_temp:.1f}°C, GPU: {bb_gpu_temp:.1f}°C)!"
            )
    # Se há Kernel-Power 41 sem BSOD e sem sensores de CPU visíveis, superaquecimento ainda é suspeito moderado
    if kp41_clean_powerloss and therm_score == 0:
        therm_score = 30
        therm_ev.append(
            "Desligamentos súbitos sem BSOD também ocorrem quando a proteção térmica da placa-mãe (PROCHOT/THERMTRIP) corta a energia antes do Windows registrar o erro."
        )
    if therm_score > 0:
        therm_score = min(98, therm_score)
        hypotheses.append(
            CauseHypothesis(
                cause_id="overheating",
                title="Superaquecimento (CPU, GPU ou VRM da Placa-mãe)",
                confidence=_confidence_from_score(therm_score),
                score=therm_score,
                evidences=therm_ev,
                recommendations=[
                    "Rode o modo Caixa-Preta deste programa (`python main.py --monitor`) enquanto usa/joga para gravar as temperaturas exatas até o momento da queda.",
                    "Verifique se todas as ventoinhas (cooler da CPU, GPU e gabinete) estão girando livremente e limpe a poeira dos dissipadores.",
                    "Se a CPU passa de 90°C ou o PC tem mais de 2 anos sem manutenção, troque a pasta térmica do processador e verifique o encaixe do cooler/watercooler.",
                ],
            )
        )

    # 3. Erro de Hardware (WHEA - CPU, RAM, PCIe, Overclock/XMP)
    whea_score = 0
    whea_ev: list[str] = []
    if whea_fatal:
        whea_score += min(85, 60 + len(whea_fatal) * 10)
        whea_ev.append(
            f"{len(whea_fatal)} erro(s) FATAL(IS) do WHEA-Logger (IDs 18/20/46) — indica falha física ou instabilidade de CPU, RAM ou barramento PCIe."
        )
    elif whea_events:
        whea_score += min(55, 35 + len(whea_events) * 5)
        whea_ev.append(f"{len(whea_events)} aviso(s) de erro corrigido do WHEA-Logger (IDs 19/47).")
    if any(inc.bugcheck_code in (0x124, 0x101, 0x1A, 0x7F) for inc in incidents):
        whea_score += 25
        whea_ev.append("BugCheck típico de hardware/CPU/RAM detectado (ex: WHEA_UNCORRECTABLE_ERROR ou MEMORY_MANAGEMENT).")
    if whea_score > 0:
        whea_score = min(98, whea_score)
        hypotheses.append(
            CauseHypothesis(
                cause_id="hardware_whea",
                title="Instabilidade ou Defeito de Hardware (CPU, Memória RAM ou Placa-mãe)",
                confidence=_confidence_from_score(whea_score),
                score=whea_score,
                evidences=whea_ev,
                recommendations=[
                    "Desative temporariamente qualquer overclock, PBO/Curve Optimizer (AMD) ou perfil XMP/DOCP/EXPO na BIOS para testar estabilidade.",
                    "Teste a memória RAM usando o Diagnóstico de Memória do Windows (`mdsched.exe`) ou MemTest86, testando um pente de cada vez.",
                    "Atualize a BIOS da placa-mãe e os drivers do chipset (AMD/Intel) — erros WHEA 18 em Ryzen frequentemente são resolvidos com BIOS/chipset atualizados ou ajuste de voltagem.",
                ],
            )
        )

    # 4. Tela Azul (BSOD) / Drivers (especialmente GPU)
    bsod_score = 0
    bsod_ev: list[str] = []
    if kp41_bsod:
        bsod_score += min(70, 45 + len(kp41_bsod) * 10)
        codes = sorted({f"{i.bugcheck_name} (0x{i.bugcheck_code:08X})" for i in kp41_bsod})
        bsod_ev.append(f"Kernel-Power 41 com código de BSOD: {', '.join(codes)}.")
    if bugcheck_1001:
        bsod_score += min(30, 15 + len(bugcheck_1001) * 5)
        bsod_ev.append(f"{len(bugcheck_1001)} evento(s) BugCheck 1001 no Log do Sistema.")
    if data.crash_dumps:
        bsod_score += 20
        bsod_ev.append(
            f"{len(data.crash_dumps)} arquivo(s) de dump de BSOD encontrado(s) (mais recente: {data.crash_dumps[0].filename})."
        )
    if gpu_tdr_events:
        bsod_score += min(30, 15 + len(gpu_tdr_events) * 5)
        bsod_ev.append(f"{len(gpu_tdr_events)} travamento(s) do driver de vídeo (Display 4101).")
    if bsod_score > 0:
        bsod_score = min(98, bsod_score)
        hypotheses.append(
            CauseHypothesis(
                cause_id="bsod_drivers",
                title="Tela Azul (BSOD) / Conflito de Driver ou Windows Corrompido",
                confidence=_confidence_from_score(bsod_score),
                score=bsod_score,
                evidences=bsod_ev,
                recommendations=[
                    "Analise os arquivos `.dmp` em `C:\\Windows\\Minidump` usando WinDbg (da Microsoft Store) ou BlueScreenView para ver exatamente qual arquivo `.sys` causou o crash.",
                    "Se houver eventos Display 4101 ou BSOD de vídeo, faça instalação limpa do driver da GPU usando DDU (Display Driver Uninstaller).",
                    "Execute no Prompt como Administrador: `sfc /scannow` e `DISM /Online /Cleanup-Image /RestoreHealth` para reparar arquivos do Windows.",
                ],
            )
        )

    # 5. Falha de Disco / SSD / NVMe
    disk_score = 0
    disk_ev: list[str] = []
    if disk_error_events:
        disk_score += min(65, 25 + len(disk_error_events) * 8)
        disk_ev.append(
            f"{len(disk_error_events)} erro(s) de disco/armazenamento (IDs 7/11/51/129/153) nos últimos {data.days_analyzed} dias."
        )
    if unhealthy_disks:
        disk_score += 40
        disk_ev.append("SMART/Storage relatou alerta em: " + "; ".join(unhealthy_disks))
    if any(inc.bugcheck_code in (0xEF, 0xF4, 0x154, 0x133) for inc in incidents):
        disk_score += 20
        disk_ev.append("BugCheck associado a falha de armazenamento/SSD detectado.")
    if disk_score > 0:
        disk_score = min(95, disk_score)
        hypotheses.append(
            CauseHypothesis(
                cause_id="storage_disk",
                title="Falha no SSD / HD ou Controlador NVMe/SATA",
                confidence=_confidence_from_score(disk_score),
                score=disk_score,
                evidences=disk_ev,
                recommendations=[
                    "Faça backup imediato dos seus arquivos importantes!",
                    "Verifique o encaixe físico do SSD M.2 ou substitua o cabo SATA.",
                    "Verifique a saúde completa (SMART) com CrystalDiskInfo e atualize o firmware do SSD no utilitário do fabricante.",
                ],
            )
        )

    # 6. Desligamento Iniciado por Software / Windows Update / Tarefa Agendada
    if software_shutdowns and not incidents:
        sw_ev = [
            f"{len(software_shutdowns)} desligamento(s)/reinício(s) registrados como solicitados por software (User32 1074) e nenhum Kernel-Power 41."
        ]
        for ev in software_shutdowns[:3]:
            proc = ev.properties.get("param1") or ev.properties.get("Param0") or ""
            reason = ev.properties.get("param3") or ev.properties.get("Param2") or ""
            detail = f"{ev.timestamp.strftime('%d/%m %H:%M')}: {proc} {reason}".strip()
            sw_ev.append(detail)
        hypotheses.append(
            CauseHypothesis(
                cause_id="software_shutdown",
                title="Desligamento Acionado por Software / Windows Update / Agendamento",
                confidence="MÉDIA",
                score=55,
                evidences=sw_ev,
                recommendations=[
                    "Verifique os eventos User32 1074 na linha do tempo para identificar qual aplicativo ou serviço pediu o desligamento.",
                    "Cheque o Agendador de Tarefas do Windows e o horário ativo do Windows Update.",
                ],
            )
        )

    # Caso não haja nenhum incidente registrado no período
    if not hypotheses:
        log_read_failed = any("Log System" in w for w in data.warnings)
        if log_read_failed:
            hypotheses.append(
                CauseHypothesis(
                    cause_id="permission_error",
                    title="Sem Permissão para Ler os Logs do Windows",
                    confidence="BAIXA",
                    score=10,
                    evidences=[
                        "O programa não teve permissão para consultar o Visualizador de Eventos (Log System) neste ambiente.",
                        *[w for w in data.warnings if "Log System" in w or "WMI/CIM" in w],
                    ],
                    recommendations=[
                        "Clique com o botão direito em `executar_diagnostico.bat` e selecione 'Executar como administrador'.",
                        "Ou abra um PowerShell / Prompt de Comando como Administrador e execute `python main.py --dias 30`.",
                    ],
                )
            )
        else:
            hypotheses.append(
                CauseHypothesis(
                    cause_id="inconclusive",
                    title="Sem Evidências Suficientes no Histórico Recente",
                    confidence="BAIXA",
                    score=15,
                    evidences=[
                        f"Nenhum desligamento inesperado foi encontrado no Log do Windows nos últimos {data.days_analyzed} dias.",
                        "Se o PC desligou mesmo assim, o log pode ter sido limpo ou o período analisado precisa ser maior (use `--dias 60`).",
                    ],
                    recommendations=[
                        "Rode novamente aumentando o período: `python main.py --dias 60`.",
                        "Execute como Administrador para acessar todos os logs e sensores.",
                        "Ative a Caixa-Preta (`python main.py --monitor`) para capturar temperaturas, uso de CPU/GPU e energia antes da próxima queda!",
                    ],
                )
            )

    hypotheses.sort(key=lambda h: h.score, reverse=True)

    return DiagnosisReport(
        generated_at=datetime.now(),
        days_analyzed=data.days_analyzed,
        total_unexpected_shutdowns=len(incidents),
        incidents=incidents,
        hypotheses=hypotheses,
        event_counts=event_counts,
        health_alerts=health_alerts,
        blackbox_summary=blackbox_summary,
        data=data,
    )
