"""Coletores de dados do Windows para investigar desligamentos inesperados.

Usa apenas a biblioteca padrão do Python + utilitários nativos do Windows
(PowerShell, CIM/WMI, nvidia-smi quando disponível), sem dependências externas.
"""

from __future__ import annotations

import ctypes
import json
import os
import platform
import shutil
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


# Grupos de consulta no Log "System" (separados para evitar limite de cláusulas XPath do Windows
# e evitar que eventos barulhentos de outros provedores, como BTHUSB/TPM ID 18, preencham o limite)
SYSTEM_CORE_EVENT_IDS = [
    41,    # Kernel-Power: desligamento inesperado / perda de energia
    6008,  # EventLog: desligamento anterior foi inesperado
    1074,  # User32: desligamento/reinício solicitado por software, usuário ou WLMS
    1076,  # User32: motivo informado para desligamento inesperado
    1001,  # BugCheck / WER: Tela Azul (BSOD)
    86,    # Kernel-Power: zona térmica ACPI excedeu limite
    87,    # Kernel-Power: desligamento térmico ACPI
    88,    # Kernel-Power: hibernação térmica ACPI
    89,    # Kernel-Power: estado térmico crítico
    4101,  # Display: driver de vídeo parou de responder (TDR)
    37,    # Kernel-Processor-Power: redução de velocidade (throttling/energia)
]

# Mantido por compatibilidade com referências externas
SYSTEM_EVENT_IDS = SYSTEM_CORE_EVENT_IDS + [18, 19, 20, 46, 47, 7, 11, 51, 129, 153]

# Status conhecidos de SoftwareLicensingProduct.LicenseStatus
LICENSE_STATUS_MAP: dict[int, str] = {
    0: "Não licenciado (Unlicensed)",
    1: "Licenciado (Licensed)",
    2: "Período de carência inicial (OOB Grace)",
    3: "Período de carência adicional (OOT Grace)",
    4: "Não genuíno (Non-Genuine Grace)",
    5: "Notificação / Expirado (Notification)",
    6: "Carência estendida (Extended Grace)",
}

# Mapeamento conhecido de códigos de BugCheck (BSOD) comuns
KNOWN_BUGCHECKS: dict[int, tuple[str, str]] = {
    0x0000000A: ("IRQL_NOT_LESS_OR_EQUAL", "Driver com bug ou memória RAM instável."),
    0x0000001A: ("MEMORY_MANAGEMENT", "Falha na memória RAM (execute MemTest86 / Diagnóstico de Memória)."),
    0x0000001E: ("KMODE_EXCEPTION_NOT_HANDLED", "Exceção de kernel causada por driver ou hardware."),
    0x0000003B: ("SYSTEM_SERVICE_EXCEPTION", "Erro em driver de vídeo, áudio ou sistema."),
    0x00000050: ("PAGE_FAULT_IN_NONPAGED_AREA", "Memória RAM com defeito, SSD com falha ou driver corrompido."),
    0x0000007E: ("SYSTEM_THREAD_EXCEPTION_NOT_HANDLED", "Driver incompatível ou corrompido."),
    0x0000007F: ("UNEXPECTED_KERNEL_MODE_TRAP", "Falha de hardware (CPU/RAM/overclock) ou driver."),
    0x0000009F: ("DRIVER_POWER_STATE_FAILURE", "Driver falhou ao entrar/sair de suspensão ou energia."),
    0x000000D1: ("DRIVER_IRQL_NOT_LESS_OR_EQUAL", "Driver (rede, vídeo ou armazenamento) acessou memória inválida."),
    0x000000EF: ("CRITICAL_PROCESS_DIED", "Processo crítico do Windows morreu (disco/SSD ou arquivos corrompidos)."),
    0x000000F4: ("CRITICAL_OBJECT_TERMINATION", "Falha de disco/SSD ou cabo SATA/NVMe desconectando."),
    0x00000101: ("CLOCK_WATCHDOG_TIMEOUT", "CPU travou (overclock instável, Vcore baixo, superaquecimento ou BIOS)."),
    0x00000116: ("VIDEO_TDR_FAILURE", "GPU/driver de vídeo travou e não recuperou (GPU, driver ou fonte)."),
    0x00000119: ("VIDEO_SCHEDULER_INTERNAL_ERROR", "Erro interno no driver da placa de vídeo ou VRAM defeituosa."),
    0x00000124: ("WHEA_UNCORRECTABLE_ERROR", "Erro grave de hardware (CPU, VRM, RAM, PCIe ou superaquecimento)."),
    0x00000133: ("DPC_WATCHDOG_VIOLATION", "Driver ou SSD/NVMe travou o sistema por tempo excessivo."),
    0x00000139: ("KERNEL_SECURITY_CHECK_FAILURE", "Corrupção de memória ou driver com bug."),
    0x00000154: ("UNEXPECTED_STORE_EXCEPTION", "Falha de leitura/escrita no SSD/HD ou memória RAM."),
}


@dataclass
class SystemEvent:
    """Representa um evento coletado do Visualizador de Eventos do Windows."""

    timestamp: datetime
    event_id: int
    provider: str
    level: str
    log_name: str
    message: str
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_id": self.event_id,
            "provider": self.provider,
            "level": self.level,
            "log_name": self.log_name,
            "message": self.message,
            "properties": self.properties,
        }


@dataclass
class CrashDumpInfo:
    """Informações sobre um arquivo de despejo de memória (BSOD .dmp)."""

    path: str
    filename: str
    modified_at: datetime
    size_bytes: int
    dump_type: str = "Minidump"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "filename": self.filename,
            "modified_at": self.modified_at.isoformat(),
            "size_bytes": self.size_bytes,
            "dump_type": self.dump_type,
        }


@dataclass
class CollectedData:
    """Pacote completo com todos os dados coletados do sistema."""

    collected_at: datetime
    days_analyzed: int
    is_admin: bool
    system_info: dict[str, Any] = field(default_factory=dict)
    events: list[SystemEvent] = field(default_factory=list)
    crash_dumps: list[CrashDumpInfo] = field(default_factory=list)
    temperatures: list[dict[str, Any]] = field(default_factory=list)
    gpu_info: list[dict[str, Any]] = field(default_factory=list)
    disks: list[dict[str, Any]] = field(default_factory=list)
    memory_modules: list[dict[str, Any]] = field(default_factory=list)
    battery: dict[str, Any] | None = None
    license_info: dict[str, Any] | None = None
    reliability_events: list[dict[str, Any]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "collected_at": self.collected_at.isoformat(),
            "days_analyzed": self.days_analyzed,
            "is_admin": self.is_admin,
            "system_info": self.system_info,
            "events": [e.to_dict() for e in self.events],
            "crash_dumps": [d.to_dict() for d in self.crash_dumps],
            "temperatures": self.temperatures,
            "gpu_info": self.gpu_info,
            "disks": self.disks,
            "memory_modules": self.memory_modules,
            "battery": self.battery,
            "license_info": self.license_info,
            "reliability_events": self.reliability_events,
            "warnings": self.warnings,
        }


def is_running_as_admin() -> bool:
    """Verifica se o script está rodando com privilégios de Administrador no Windows."""
    if platform.system() != "Windows":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_powershell_json(script: str, timeout: int = 30) -> tuple[Any, str | None]:
    """Executa um script PowerShell que retorna JSON e faz o parse seguro."""
    full_script = (
        "$OutputEncoding = [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)\n"
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        + script
    )
    try:
        proc = subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                full_script,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        return None, f"Tempo limite excedido ({timeout}s) ao consultar o Windows."
    except FileNotFoundError:
        return None, "PowerShell não encontrado neste sistema."
    except Exception as exc:
        return None, f"Erro ao executar PowerShell: {exc}"

    stdout = (proc.stdout or "").strip()
    if not stdout:
        stderr = (proc.stderr or "").strip()
        if proc.returncode != 0 and stderr:
            return None, stderr
        return None, None

    try:
        return json.loads(stdout), None
    except json.JSONDecodeError:
        # Tenta isolar o trecho JSON caso algum aviso tenha vazado no stdout
        start_obj = stdout.find("{")
        start_arr = stdout.find("[")
        starts = [i for i in (start_obj, start_arr) if i != -1]
        if starts:
            try:
                return json.loads(stdout[min(starts) :]), None
            except json.JSONDecodeError:
                pass
        return None, f"Não foi possível interpretar a saída do PowerShell: {stdout[:200]}"


def _parse_iso_datetime(value: str | None) -> datetime:
    """Converte string ISO retornada pelo PowerShell em datetime local naive."""
    if not value:
        return datetime.now()
    cleaned = value.strip()
    # Normaliza formato /Date(1234567890)/ do PowerShell 5.1 se ocorrer
    if cleaned.startswith("/Date(") and cleaned.endswith(")/"):
        ms_str = cleaned[6:-2].split("+")[0].split("-")[0]
        try:
            return datetime.fromtimestamp(int(ms_str) / 1000.0)
        except ValueError:
            return datetime.now()
    try:
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        dt = datetime.fromisoformat(cleaned)
        if dt.tzinfo is not None:
            dt = dt.astimezone().replace(tzinfo=None)
        return dt
    except ValueError:
        return datetime.now()


def collect_system_events(days: int = 14) -> tuple[list[SystemEvent], list[str]]:
    """Coleta eventos de desligamento, BSOD, hardware (WHEA), térmicos, disco e WLMS (licença)."""
    warnings: list[str] = []
    core_ids_csv = ",".join(str(i) for i in SYSTEM_CORE_EVENT_IDS)

    ps_script = f"""
$start = (Get-Date).AddDays(-{int(days)})
$resp = @{{ events = @(); errors = @() }}

function Add-EventsFromQuery($filterHash, $maxEvents, $label) {{
    try {{
        $raw = Get-WinEvent -FilterHashtable $filterHash -MaxEvents $maxEvents -ErrorAction Stop
        foreach ($ev in $raw) {{
            $props = @{{}}
            try {{
                $xml = [xml]$ev.ToXml()
                if ($xml.Event.EventData -and $xml.Event.EventData.Data) {{
                    $idx = 0
                    foreach ($d in $xml.Event.EventData.Data) {{
                        $key = if ($d.Name) {{ [string]$d.Name }} else {{ "Param$idx" }}
                        $props[$key] = [string]$d.'#text'
                        $idx++
                    }}
                }}
            }} catch {{}}
            $msg = if ($ev.Message) {{ $ev.Message }} else {{ "" }}
            if ($msg.Length -gt 800) {{ $msg = $msg.Substring(0, 800) + "..." }}
            $resp.events += [PSCustomObject]@{{
                timestamp = $ev.TimeCreated.ToString("o")
                event_id = [int]$ev.Id
                provider = [string]$ev.ProviderName
                level = [string]$ev.LevelDisplayName
                log_name = [string]$ev.LogName
                message = $msg
                properties = $props
            }}
        }}
    }} catch {{
        $m = $_.Exception.Message
        if ($m -notmatch "No events were found|Nenhum evento") {{
            $resp.errors += "$($label): $m"
        }}
    }}
}}

# 1) Eventos principais de desligamento, BSOD, térmico e vídeo no Log System
Add-EventsFromQuery @{{ LogName = 'System'; Id = @({core_ids_csv}); StartTime = $start }} 200 "Log System"

# 2) Erros de hardware WHEA-Logger (filtrado por provedor para não misturar com BTHUSB/TPM ID 18)
Add-EventsFromQuery @{{ LogName = 'System'; ProviderName = 'Microsoft-Windows-WHEA-Logger'; Id = @(18,19,20,46,47); StartTime = $start }} 100 "WHEA-Logger"

# 3) Erros de disco/armazenamento (consulta cada provedor existente para evitar erro quando algum não está instalado)
foreach ($prov in @('disk','stornvme','storport','ntfs')) {{
    try {{
        $null = Get-WinEvent -ListProvider $prov -ErrorAction Stop
        Add-EventsFromQuery @{{ LogName = 'System'; ProviderName = $prov; Id = @(7,11,51,129,153); StartTime = $start }} 50 "Disco ($prov)"
    }} catch {{}}
}}

# 4) Eventos do WLMS (Windows Licensing Monitoring Service) no Log Application (Windows Evaluation expirado!)
Add-EventsFromQuery @{{ LogName = 'Application'; ProviderName = 'WLMS'; StartTime = $start }} 50 "WLMS (Licenciamento)"

$resp | ConvertTo-Json -Depth 5 -Compress
"""
    data, err = _run_powershell_json(ps_script, timeout=45)
    if err:
        warnings.append(f"Erro ao ler Log System do Windows: {err}")
        return [], warnings

    if not isinstance(data, dict):
        return [], warnings

    for q_err in data.get("errors") or []:
        warnings.append(f"Erro ao ler {q_err}")

    raw_events = data.get("events") or []
    if isinstance(raw_events, dict):
        raw_events = [raw_events]

    events: list[SystemEvent] = []
    for item in raw_events:
        if not isinstance(item, dict):
            continue
        events.append(
            SystemEvent(
                timestamp=_parse_iso_datetime(item.get("timestamp")),
                event_id=int(item.get("event_id", 0)),
                provider=str(item.get("provider") or "Desconhecido"),
                level=str(item.get("level") or "Info"),
                log_name=str(item.get("log_name") or "System"),
                message=str(item.get("message") or "").strip(),
                properties=item.get("properties") if isinstance(item.get("properties"), dict) else {},
            )
        )

    events.sort(key=lambda e: e.timestamp, reverse=True)
    return events, warnings


def collect_crash_dumps(days: int = 30) -> tuple[list[CrashDumpInfo], list[str]]:
    """Procura arquivos de Minidump e MEMORY.DMP gerados por Telas Azuis (BSOD)."""
    dumps: list[CrashDumpInfo] = []
    warnings: list[str] = []
    cutoff = datetime.now() - timedelta(days=days)

    win_dir = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    minidump_dir = win_dir / "Minidump"

    try:
        if minidump_dir.exists():
            for entry in minidump_dir.glob("*.dmp"):
                try:
                    stat = entry.stat()
                    mod = datetime.fromtimestamp(stat.st_mtime)
                    if mod >= cutoff:
                        dumps.append(
                            CrashDumpInfo(
                                path=str(entry),
                                filename=entry.name,
                                modified_at=mod,
                                size_bytes=stat.st_size,
                                dump_type="Minidump",
                            )
                        )
                except OSError:
                    continue
    except PermissionError:
        warnings.append(
            "Sem permissão para listar C:\\Windows\\Minidump (execute como Administrador para verificar dumps de BSOD)."
        )

    memory_dmp = win_dir / "MEMORY.DMP"
    try:
        if memory_dmp.exists():
            stat = memory_dmp.stat()
            mod = datetime.fromtimestamp(stat.st_mtime)
            if mod >= cutoff:
                dumps.append(
                    CrashDumpInfo(
                        path=str(memory_dmp),
                        filename=memory_dmp.name,
                        modified_at=mod,
                        size_bytes=stat.st_size,
                        dump_type="Kernel/Full Dump",
                    )
                )
    except OSError:
        pass

    dumps.sort(key=lambda d: d.modified_at, reverse=True)
    return dumps, warnings


def collect_hardware_and_sensors() -> tuple[dict[str, Any], list[str]]:
    """Coleta informações de CPU, placa-mãe, BIOS, RAM, discos, bateria e sensores térmicos."""
    warnings: list[str] = []
    ps_script = r"""
$out = @{
    system_info = @{}
    temperatures = @()
    disks = @()
    memory_modules = @()
    battery = $null
    license_info = $null
    reliability_events = @()
    errors = @()
}

try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
    $cpu = Get-CimInstance Win32_Processor -ErrorAction Stop | Select-Object -First 1
    $mb = Get-CimInstance Win32_BaseBoard | Select-Object -First 1
    $bios = Get-CimInstance Win32_BIOS | Select-Object -First 1
    $gpus = @(Get-CimInstance Win32_VideoController | ForEach-Object {
        @{
            name = [string]$_.Name
            driver_version = [string]$_.DriverVersion
            status = [string]$_.Status
        }
    })
    $out.system_info = @{
        hostname = [string]$env:COMPUTERNAME
        os_caption = [string]$os.Caption
        os_version = [string]$os.Version
        last_boot = if ($os.LastBootUpTime) { $os.LastBootUpTime.ToString("o") } else { "" }
        manufacturer = [string]$cs.Manufacturer
        model = [string]$cs.Model
        total_ram_gb = if ($cs.TotalPhysicalMemory) { [math]::Round($cs.TotalPhysicalMemory / 1GB, 2) } else { 0 }
        cpu_name = [string]$cpu.Name
        cpu_cores = [int]$cpu.NumberOfCores
        cpu_threads = [int]$cpu.NumberOfLogicalProcessors
        cpu_load_pct = if ($null -ne $cpu.LoadPercentage) { [int]$cpu.LoadPercentage } else { $null }
        motherboard = "$($mb.Manufacturer) $($mb.Product)".Trim()
        bios_version = [string]$bios.SMBIOSBIOSVersion
        bios_date = if ($bios.ReleaseDate) { $bios.ReleaseDate.ToString("yyyy-MM-dd") } else { "" }
        video_controllers = $gpus
    }
} catch {
    $out.errors += "WMI/CIM indisponível: $($_.Exception.Message)"
}

# 1) Temperatura via ACPI Thermal Zone (frequentemente exige Admin)
try {
    $zones = Get-CimInstance -Namespace root/WMI -ClassName MSAcpi_ThermalZoneTemperature
    foreach ($z in $zones) {
        if ($z.CurrentTemperature -gt 2000) {
            $c = [math]::Round(($z.CurrentTemperature / 10.0) - 273.15, 1)
            $crit = if ($z.CriticalTripPoint -gt 2000) { [math]::Round(($z.CriticalTripPoint / 10.0) - 273.15, 1) } else { $null }
            $out.temperatures += @{
                source = "ACPI Thermal Zone"
                sensor = [string]$z.InstanceName
                temp_c = $c
                critical_c = $crit
            }
        }
    }
} catch {}

# 2) Temperatura via ThermalZoneInformation (nem sempre exige Admin)
try {
    $tzInfo = Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation
    foreach ($t in $tzInfo) {
        if ($t.Temperature -gt 200) {
            $c = [math]::Round($t.Temperature - 273.15, 1)
            $out.temperatures += @{
                source = "Windows Thermal Counter"
                sensor = [string]$t.Name
                temp_c = $c
                critical_c = $null
            }
        }
    }
} catch {}

# 3) LibreHardwareMonitor / OpenHardwareMonitor (se estiver rodando em segundo plano)
foreach ($ns in @("root/LibreHardwareMonitor", "root/OpenHardwareMonitor")) {
    try {
        $sensors = Get-CimInstance -Namespace $ns -ClassName Sensor | Where-Object { $_.SensorType -eq "Temperature" }
        foreach ($s in $sensors) {
            if ($null -ne $s.Value -and $s.Value -gt 0 -and $s.Value -lt 150) {
                $out.temperatures += @{
                    source = $ns.Split("/")[-1]
                    sensor = [string]$s.Name
                    temp_c = [math]::Round([double]$s.Value, 1)
                    critical_c = $null
                }
            }
        }
    } catch {}
}

# Discos e Saúde (Storage + SMART)
try {
    $pdisks = Get-PhysicalDisk
    foreach ($d in $pdisks) {
        $rel = $null
        try { $rel = $d | Get-StorageReliabilityCounter } catch {}
        $out.disks += @{
            model = [string]$d.FriendlyName
            media_type = [string]$d.MediaType
            bus_type = [string]$d.BusType
            health_status = [string]$d.HealthStatus
            operational_status = [string]$d.OperationalStatus
            size_gb = [math]::Round($d.Size / 1GB, 1)
            temperature_c = if ($rel -and $rel.Temperature) { [int]$rel.Temperature } else { $null }
            wear_pct = if ($rel -and $null -ne $rel.Wear) { [int]$rel.Wear } else { $null }
            read_errors = if ($rel -and $null -ne $rel.ReadErrorsUncorrected) { [int]$rel.ReadErrorsUncorrected } else { $null }
            write_errors = if ($rel -and $null -ne $rel.WriteErrorsUncorrected) { [int]$rel.WriteErrorsUncorrected } else { $null }
        }
    }
} catch {
    try {
        $wmiDisks = Get-CimInstance Win32_DiskDrive
        foreach ($d in $wmiDisks) {
            $out.disks += @{
                model = [string]$d.Model
                media_type = [string]$d.MediaType
                bus_type = [string]$d.InterfaceType
                health_status = [string]$d.Status
                operational_status = [string]$d.Status
                size_gb = if ($d.Size) { [math]::Round($d.Size / 1GB, 1) } else { 0 }
                temperature_c = $null
                wear_pct = $null
                read_errors = $null
                write_errors = $null
            }
        }
    } catch {}
}

# Módulos de RAM
try {
    $rams = Get-CimInstance Win32_PhysicalMemory
    foreach ($r in $rams) {
        $out.memory_modules += @{
            slot = [string]$r.DeviceLocator
            manufacturer = [string]$r.Manufacturer
            part_number = ([string]$r.PartNumber).Trim()
            capacity_gb = [math]::Round($r.Capacity / 1GB, 1)
            speed_mhz = if ($r.ConfiguredClockSpeed) { [int]$r.ConfiguredClockSpeed } else { [int]$r.Speed }
        }
    }
} catch {}

# Bateria (se for notebook)
try {
    $bat = Get-CimInstance Win32_Battery | Select-Object -First 1
    if ($bat) {
        $out.battery = @{
            name = [string]$bat.Name
            charge_pct = [int]$bat.EstimatedChargeRemaining
            status = [string]$bat.Status
            battery_status_code = [int]$bat.BatteryStatus
        }
    }
} catch {}

# Status da Licença do Windows (detecta edições Evaluation expiradas que desligam a cada 1 hora!)
try {
    $lic = Get-CimInstance SoftwareLicensingProduct -Filter "PartialProductKey is not null" |
        Where-Object { $_.Name -match "Windows" } |
        Select-Object -First 1
    if ($lic) {
        $out.license_info = @{
            name = [string]$lic.Name
            description = [string]$lic.Description
            license_status = [int]$lic.LicenseStatus
            grace_period_minutes = [int]$lic.GracePeriodRemaining
            is_evaluation = ([string]$lic.Name -match "Eval" -or [string]$lic.Description -match "EVAL")
        }
    }
} catch {}

# Monitor de Confiabilidade do Windows (últimos 14 dias - falhas do Windows)
try {
    $cutoff = (Get-Date).AddDays(-14)
    $recs = Get-CimInstance Win32_ReliabilityRecords |
        Where-Object { $_.TimeGenerated -ge $cutoff -and ($_.SourceName -match "Windows|BugCheck|Kernel|WER|Application Error") } |
        Sort-Object TimeGenerated -Descending |
        Select-Object -First 30
    foreach ($rec in $recs) {
        $msg = [string]$rec.Message
        if ($msg.Length -gt 300) { $msg = $msg.Substring(0, 300) + "..." }
        $out.reliability_events += @{
            timestamp = $rec.TimeGenerated.ToString("o")
            source = [string]$rec.SourceName
            product = [string]$rec.ProductName
            event_id = [int]$rec.EventIdentifier
            message = $msg
        }
    }
} catch {}

$out | ConvertTo-Json -Depth 5 -Compress
"""
    data, err = _run_powershell_json(ps_script, timeout=45)
    if err:
        warnings.append(f"Aviso ao consultar hardware/sensores: {err}")
        return {}, warnings
    if not isinstance(data, dict):
        return {}, warnings
    for hw_err in data.get("errors") or []:
        warnings.append(str(hw_err))
    return data, warnings


def collect_nvidia_gpu_metrics() -> list[dict[str, Any]]:
    """Coleta temperatura, consumo (W) e uso da GPU NVIDIA via nvidia-smi se disponível."""
    nvidia_smi = shutil.which("nvidia-smi")
    if not nvidia_smi:
        default_path = Path(r"C:\Windows\System32\nvidia-smi.exe")
        if default_path.exists():
            nvidia_smi = str(default_path)
    if not nvidia_smi:
        return []

    try:
        proc = subprocess.run(
            [
                nvidia_smi,
                "--query-gpu=name,temperature.gpu,utilization.gpu,power.draw,power.limit,memory.used,memory.total,fan.speed",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
    except Exception:
        return []

    gpus: list[dict[str, Any]] = []
    for line in proc.stdout.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 8:
            continue

        def _to_float(val: str) -> float | None:
            try:
                return float(val)
            except (ValueError, TypeError):
                return None

        gpus.append(
            {
                "name": parts[0],
                "temp_c": _to_float(parts[1]),
                "util_pct": _to_float(parts[2]),
                "power_draw_w": _to_float(parts[3]),
                "power_limit_w": _to_float(parts[4]),
                "vram_used_mb": _to_float(parts[5]),
                "vram_total_mb": _to_float(parts[6]),
                "fan_pct": _to_float(parts[7]),
            }
        )
    return gpus


def collect_all(days: int = 14) -> CollectedData:
    """Executa todas as coletas de diagnóstico no Windows."""
    admin = is_running_as_admin()
    result = CollectedData(
        collected_at=datetime.now(),
        days_analyzed=days,
        is_admin=admin,
    )

    if not admin:
        result.warnings.append(
            "Executado sem privilégios de Administrador: alguns sensores térmicos (ACPI) e arquivos de Minidump podem ficar ocultos."
        )

    events, ev_warnings = collect_system_events(days=days)
    result.events = events
    result.warnings.extend(ev_warnings)

    dumps, dump_warnings = collect_crash_dumps(days=max(days, 30))
    result.crash_dumps = dumps
    result.warnings.extend(dump_warnings)

    hw_data, hw_warnings = collect_hardware_and_sensors()
    result.warnings.extend(hw_warnings)

    result.system_info = hw_data.get("system_info") or {}
    result.temperatures = hw_data.get("temperatures") or []
    result.disks = hw_data.get("disks") or []
    result.memory_modules = hw_data.get("memory_modules") or []
    result.battery = hw_data.get("battery")
    result.license_info = hw_data.get("license_info")
    if isinstance(result.license_info, dict):
        code = result.license_info.get("license_status")
        if isinstance(code, int):
            result.license_info["license_status_text"] = LICENSE_STATUS_MAP.get(code, f"Código {code}")
    result.reliability_events = hw_data.get("reliability_events") or []

    gpu_metrics = collect_nvidia_gpu_metrics()
    result.gpu_info = gpu_metrics
    for gpu in gpu_metrics:
        if gpu.get("temp_c") is not None:
            result.temperatures.append(
                {
                    "source": "nvidia-smi",
                    "sensor": f"GPU ({gpu['name']})",
                    "temp_c": gpu["temp_c"],
                    "critical_c": 90.0,
                }
            )

    return result
