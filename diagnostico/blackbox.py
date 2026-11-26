"""Modo Caixa-Preta (Black Box) para capturar métricas em tempo real até a queda.

Grava telemetria contínua (CPU %, RAM %, temperatura CPU/GPU, consumo da GPU em Watts,
processo mais pesado) com flush + fsync imediato em disco. Se o PC desligar
abruptamente, a sessão fica marcada como interrompida e os últimos segundos
revelam exatamente o que estava acontecendo na hora da queda.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import signal
import time
from datetime import datetime
from pathlib import Path
from typing import Any

from .windows_collectors import _run_powershell_json, collect_nvidia_gpu_metrics


DEFAULT_LOG_PATH = Path("logs") / "caixa_preta.jsonl"


# --- Leitura ultraleve de CPU e RAM via Win32 API (ctypes) ---


class _FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", ctypes.c_uint32), ("dwHighDateTime", ctypes.c_uint32)]


class _MEMORYSTATUSEX(ctypes.Structure):
    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


def _filetime_to_int(ft: _FILETIME) -> int:
    return (ft.dwHighDateTime << 32) | ft.dwLowDateTime


class _WinCpuSampler:
    """Calcula uso percentual de CPU via GetSystemTimes com custo praticamente zero."""

    def __init__(self) -> None:
        self._prev: tuple[int, int, int] | None = None

    def _read_times(self) -> tuple[int, int, int] | None:
        if platform.system() != "Windows":
            return None
        idle, kernel, user = _FILETIME(), _FILETIME(), _FILETIME()
        ok = ctypes.windll.kernel32.GetSystemTimes(
            ctypes.byref(idle), ctypes.byref(kernel), ctypes.byref(user)
        )
        if not ok:
            return None
        return _filetime_to_int(idle), _filetime_to_int(kernel), _filetime_to_int(user)

    def sample_pct(self) -> float | None:
        cur = self._read_times()
        if cur is None:
            return None
        if self._prev is None:
            self._prev = cur
            return 0.0
        idle_d = cur[0] - self._prev[0]
        kernel_d = cur[1] - self._prev[1]
        user_d = cur[2] - self._prev[2]
        self._prev = cur
        total = kernel_d + user_d
        if total <= 0:
            return 0.0
        busy = total - idle_d
        return round(max(0.0, min(100.0, (busy / total) * 100.0)), 1)


def _read_memory_pct() -> tuple[float | None, float | None]:
    """Retorna (ram_pct, ram_used_gb) via GlobalMemoryStatusEx."""
    if platform.system() != "Windows":
        return None, None
    stat = _MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(_MEMORYSTATUSEX)
    if not ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
        return None, None
    used_gb = round((stat.ullTotalPhys - stat.ullAvailPhys) / (1024**3), 2)
    return float(stat.dwMemoryLoad), used_gb


def _read_cpu_temp_and_top_process() -> tuple[float | None, str | None]:
    """Lê temperatura de CPU/ACPI (se exposta) e o processo consumindo mais CPU."""
    ps_script = r"""
$temp = $null
foreach ($ns in @("root/LibreHardwareMonitor", "root/OpenHardwareMonitor")) {
    try {
        $s = Get-CimInstance -Namespace $ns -ClassName Sensor |
            Where-Object { $_.SensorType -eq "Temperature" -and $_.Name -match "Package|Core|Tctl|Tdie|CPU" } |
            Select-Object -First 1
        if ($s -and $s.Value -gt 0 -and $s.Value -lt 150) {
            $temp = [math]::Round([double]$s.Value, 1)
            break
        }
    } catch {}
}
if ($null -eq $temp) {
    try {
        $z = Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature | Select-Object -First 1
        if ($z -and $z.CurrentTemperature -gt 2000) {
            $temp = [math]::Round(($z.CurrentTemperature / 10.0) - 273.15, 1)
        }
    } catch {}
}
if ($null -eq $temp) {
    try {
        $tz = Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation | Select-Object -First 1
        if ($tz -and $tz.Temperature -gt 200) {
            $temp = [math]::Round($tz.Temperature - 273.15, 1)
        }
    } catch {}
}
$topProc = $null
try {
    $p = Get-Process | Sort-Object CPU -Descending | Select-Object -First 1
    if ($p) { $topProc = $p.ProcessName }
} catch {}
@{ cpu_temp_c = $temp; top_process = $topProc } | ConvertTo-Json -Compress
"""
    data, _ = _run_powershell_json(ps_script, timeout=8)
    if isinstance(data, dict):
        temp = data.get("cpu_temp_c")
        proc = data.get("top_process")
        return (float(temp) if isinstance(temp, (int, float)) else None), (str(proc) if proc else None)
    return None, None


def _write_record_durable(fh, record: dict[str, Any]) -> None:
    """Grava uma linha JSON e força sincronização imediata no disco (fsync)."""
    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
    fh.flush()
    try:
        os.fsync(fh.fileno())
    except OSError:
        pass


def run_blackbox_monitor(
    log_path: Path = DEFAULT_LOG_PATH,
    interval_sec: float = 2.0,
    max_duration_sec: float | None = None,
) -> None:
    """Executa o monitor Caixa-Preta continuamente até Ctrl+C (ou queda do PC)."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    cpu_sampler = _WinCpuSampler()
    cpu_sampler.sample_pct()  # warm-up

    stop_requested = False

    def _handle_signal(_signum, _frame):
        nonlocal stop_requested
        stop_requested = True

    signal.signal(signal.SIGINT, _handle_signal)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _handle_signal)

    print("=" * 72)
    print("  CAIXA-PRETA ATIVADA — Monitorando seu PC em tempo real")
    print("=" * 72)
    print(f"  Arquivo de gravação (fsync imediato): {log_path.resolve()}")
    print(f"  Intervalo: a cada {interval_sec:.1f}s | Sessão: {session_id}")
    print("  DICA: Deixe esta janela aberta enquanto usa/joga normalmente.")
    print("  Se o PC desligar sozinho, ligue novamente e rode o diagnóstico!")
    print("  Pressione Ctrl+C para encerrar com segurança.")
    print("-" * 72)

    start_mono = time.monotonic()
    tick = 0
    cached_cpu_temp: float | None = None
    cached_top_proc: str | None = None

    with log_path.open("a", encoding="utf-8") as fh:
        _write_record_durable(
            fh,
            {
                "type": "session_start",
                "session_id": session_id,
                "timestamp": datetime.now().isoformat(),
                "interval_sec": interval_sec,
            },
        )

        try:
            while not stop_requested:
                loop_start = time.monotonic()
                if max_duration_sec is not None and (loop_start - start_mono) >= max_duration_sec:
                    break

                cpu_pct = cpu_sampler.sample_pct()
                ram_pct, ram_used_gb = _read_memory_pct()
                gpus = collect_nvidia_gpu_metrics()
                gpu = gpus[0] if gpus else {}

                # Consulta temperatura de CPU e processo mais pesado a cada 3 ciclos para manter overhead mínimo
                if tick % 3 == 0:
                    cached_cpu_temp, cached_top_proc = _read_cpu_temp_and_top_process()

                sample = {
                    "type": "sample",
                    "session_id": session_id,
                    "timestamp": datetime.now().isoformat(),
                    "cpu_pct": cpu_pct,
                    "ram_pct": ram_pct,
                    "ram_used_gb": ram_used_gb,
                    "cpu_temp_c": cached_cpu_temp,
                    "gpu_name": gpu.get("name"),
                    "gpu_temp_c": gpu.get("temp_c"),
                    "gpu_util_pct": gpu.get("util_pct"),
                    "gpu_power_w": gpu.get("power_draw_w"),
                    "top_process": cached_top_proc,
                }
                _write_record_durable(fh, sample)

                # Saída ao vivo no terminal
                now_str = datetime.now().strftime("%H:%M:%S")
                cpu_t_str = f"{cached_cpu_temp:.1f}°C" if cached_cpu_temp is not None else "N/D"
                gpu_str = (
                    f"GPU {gpu.get('util_pct', 0):.0f}% {gpu.get('temp_c', 0):.0f}°C {gpu.get('power_draw_w', 0):.0f}W"
                    if gpu
                    else "GPU N/D"
                )
                print(
                    f"[{now_str}] CPU: {cpu_pct if cpu_pct is not None else 0:5.1f}% (Temp: {cpu_t_str:>6}) | "
                    f"RAM: {ram_pct if ram_pct is not None else 0:4.0f}% | {gpu_str} | Top: {cached_top_proc or '-'}"
                )

                tick += 1
                elapsed = time.monotonic() - loop_start
                sleep_for = max(0.2, interval_sec - elapsed)
                # Dorme em fatias curtas para responder rápido ao Ctrl+C
                end_sleep = time.monotonic() + sleep_for
                while not stop_requested and time.monotonic() < end_sleep:
                    time.sleep(min(0.2, end_sleep - time.monotonic()))
        finally:
            _write_record_durable(
                fh,
                {
                    "type": "session_end_clean",
                    "session_id": session_id,
                    "timestamp": datetime.now().isoformat(),
                    "samples_recorded": tick,
                },
            )
            print("\nCaixa-Preta encerrada normalmente (nenhuma queda abrupta nesta sessão).")


def analyze_blackbox_log(log_path: Path = DEFAULT_LOG_PATH) -> dict[str, Any] | None:
    """Analisa o arquivo da Caixa-Preta procurando sessões interrompidas por desligamento súbito."""
    if not log_path.exists():
        return None

    sessions: dict[str, dict[str, Any]] = {}
    session_order: list[str] = []

    try:
        with log_path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    # Linha truncada no meio da escrita = forte indício de queda abrupta!
                    continue
                sid = str(rec.get("session_id") or "default")
                if sid not in sessions:
                    sessions[sid] = {
                        "session_id": sid,
                        "started_at": rec.get("timestamp"),
                        "ended_cleanly": False,
                        "samples": [],
                    }
                    session_order.append(sid)

                rtype = rec.get("type")
                if rtype == "sample":
                    sessions[sid]["samples"].append(rec)
                elif rtype == "session_end_clean":
                    sessions[sid]["ended_cleanly"] = True
    except OSError:
        return None

    if not sessions:
        return None

    # Procura a sessão mais recente que NÃO terminou de forma limpa e teve amostras
    interrupted = [
        sessions[sid]
        for sid in reversed(session_order)
        if not sessions[sid]["ended_cleanly"] and len(sessions[sid]["samples"]) > 0
    ]

    if not interrupted:
        return {
            "log_path": str(log_path),
            "total_sessions": len(sessions),
            "interrupted_detected": False,
            "message": "Todas as sessões gravadas da Caixa-Preta foram encerradas normalmente.",
        }

    target = interrupted[0]
    tail = target["samples"][-15:]  # últimos ~30 segundos antes da morte do PC

    def _max_num(key: str) -> float | None:
        vals = [float(s[key]) for s in tail if isinstance(s.get(key), (int, float))]
        return round(max(vals), 1) if vals else None

    def _avg_num(key: str) -> float | None:
        vals = [float(s[key]) for s in tail if isinstance(s.get(key), (int, float))]
        return round(sum(vals) / len(vals), 1) if vals else None

    last_sample = tail[-1]
    max_cpu_t = _max_num("cpu_temp_c")
    max_gpu_t = _max_num("gpu_temp_c")
    max_gpu_w = _max_num("gpu_power_w")
    avg_cpu_pct = _avg_num("cpu_pct")
    avg_ram_pct = _avg_num("ram_pct")

    # Interpretação automática dos últimos segundos
    if (max_cpu_t and max_cpu_t >= 90) or (max_gpu_t and max_gpu_t >= 88):
        verdict = "SUPERAQUECIMENTO DETECTADO nos últimos segundos antes do desligamento!"
    elif max_gpu_w and max_gpu_w >= 150 and (avg_cpu_pct or 0) >= 40:
        verdict = "O PC desligou sob ALTA CARGA/CONSUMO com temperaturas normais — forte indício de Fonte (PSU) ou VRM!"
    elif (avg_cpu_pct or 0) < 20 and (max_gpu_w or 0) < 50:
        verdict = "O PC desligou quase OCIOSO (baixa carga e baixa temperatura) — típico de Fonte (PSU), tomada/energia, placa-mãe ou instabilidade de RAM/C-states."
    else:
        verdict = "Sessão interrompida abruptamente; verifique as últimas métricas gravadas abaixo."

    return {
        "log_path": str(log_path),
        "total_sessions": len(sessions),
        "interrupted_detected": True,
        "interrupted_sessions_count": len(interrupted),
        "session_id": target["session_id"],
        "last_timestamp": last_sample.get("timestamp"),
        "samples_in_session": len(target["samples"]),
        "last_avg_cpu_pct": avg_cpu_pct,
        "last_avg_ram_pct": avg_ram_pct,
        "last_max_cpu_temp_c": max_cpu_t,
        "last_max_gpu_temp_c": max_gpu_t,
        "last_max_gpu_power_w": max_gpu_w,
        "last_top_process": last_sample.get("top_process"),
        "verdict": verdict,
        "last_samples": tail[-5:],
    }
