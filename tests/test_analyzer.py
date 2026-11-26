"""Testes unitários para o motor de diagnóstico, Caixa-Preta e gerador de relatórios."""

from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from diagnostico.analyzer import analyze_system
from diagnostico.blackbox import analyze_blackbox_log
from diagnostico.report import save_html_report, save_json_report
from diagnostico.windows_collectors import CollectedData, CrashDumpInfo, SystemEvent


def _make_base_data(**overrides) -> CollectedData:
    defaults = dict(
        collected_at=datetime(2026, 11, 25, 22, 0, 0),
        days_analyzed=14,
        is_admin=True,
        system_info={
            "hostname": "TEST-PC",
            "os_caption": "Windows 11 Pro",
            "cpu_name": "AMD Ryzen 7 5800X",
            "motherboard": "ASUS B550",
            "bios_version": "3404",
            "total_ram_gb": 32.0,
        },
        events=[],
        crash_dumps=[],
        temperatures=[],
        gpu_info=[],
        disks=[],
        memory_modules=[],
        battery=None,
        reliability_events=[],
        warnings=[],
    )
    defaults.update(overrides)
    return CollectedData(**defaults)


class TestShutdownAnalyzer(unittest.TestCase):
    def test_kernel_power_41_without_bugcheck_points_to_psu(self) -> None:
        now = datetime(2026, 11, 25, 21, 0, 0)
        events = [
            SystemEvent(
                timestamp=now,
                event_id=41,
                provider="Microsoft-Windows-Kernel-Power",
                level="Critical",
                log_name="System",
                message="O sistema foi reiniciado sem um desligamento correto primeiro.",
                properties={"BugcheckCode": "0", "PowerButtonTimestamp": "0"},
            ),
            SystemEvent(
                timestamp=now - timedelta(days=2),
                event_id=41,
                provider="Microsoft-Windows-Kernel-Power",
                level="Critical",
                log_name="System",
                message="O sistema foi reiniciado sem um desligamento correto primeiro.",
                properties={"BugcheckCode": "0", "PowerButtonTimestamp": "0"},
            ),
        ]
        report = analyze_system(_make_base_data(events=events))
        self.assertEqual(report.total_unexpected_shutdowns, 2)
        self.assertEqual(report.hypotheses[0].cause_id, "power_psu")
        self.assertEqual(report.hypotheses[0].confidence, "ALTA")

    def test_bsod_with_bugcheck_and_minidump_detected(self) -> None:
        now = datetime(2026, 11, 25, 20, 0, 0)
        events = [
            SystemEvent(
                timestamp=now,
                event_id=41,
                provider="Microsoft-Windows-Kernel-Power",
                level="Critical",
                log_name="System",
                message="Kernel-Power 41",
                properties={"BugcheckCode": str(0x116), "PowerButtonTimestamp": "0"},
            ),
            SystemEvent(
                timestamp=now - timedelta(seconds=10),
                event_id=4101,
                provider="Display",
                level="Warning",
                log_name="System",
                message="O driver de vídeo nvlddmkm parou de responder.",
            ),
        ]
        dumps = [
            CrashDumpInfo(
                path=r"C:\Windows\Minidump\112526-12345-01.dmp",
                filename="112526-12345-01.dmp",
                modified_at=now,
                size_bytes=512000,
            )
        ]
        report = analyze_system(_make_base_data(events=events, crash_dumps=dumps))
        self.assertEqual(report.incidents[0].kind, "Tela Azul (BSOD)")
        self.assertEqual(report.incidents[0].bugcheck_name, "VIDEO_TDR_FAILURE")
        self.assertEqual(report.hypotheses[0].cause_id, "bsod_drivers")
        self.assertEqual(report.hypotheses[0].confidence, "ALTA")

    def test_whea_fatal_hardware_error_prioritized(self) -> None:
        now = datetime(2026, 11, 25, 19, 0, 0)
        events = [
            SystemEvent(
                timestamp=now,
                event_id=41,
                provider="Microsoft-Windows-Kernel-Power",
                level="Critical",
                log_name="System",
                message="Kernel-Power 41",
                properties={"BugcheckCode": str(0x124)},
            ),
            SystemEvent(
                timestamp=now - timedelta(seconds=5),
                event_id=18,
                provider="Microsoft-Windows-WHEA-Logger",
                level="Error",
                log_name="System",
                message="Ocorreu um erro fatal de hardware. Componente: Núcleo do Processador.",
            ),
        ]
        report = analyze_system(_make_base_data(events=events))
        self.assertEqual(report.hypotheses[0].cause_id, "hardware_whea")
        self.assertGreaterEqual(report.hypotheses[0].score, 85)

    def test_thermal_shutdown_and_blackbox_overheating(self) -> None:
        now = datetime(2026, 11, 25, 18, 0, 0)
        events = [
            SystemEvent(
                timestamp=now,
                event_id=87,
                provider="Microsoft-Windows-Kernel-Power",
                level="Critical",
                log_name="System",
                message="Zona térmica ACPI excedeu o limite crítico.",
            )
        ]
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "caixa_preta.jsonl"
            records = [
                {"type": "session_start", "session_id": "s1", "timestamp": now.isoformat()},
                {
                    "type": "sample",
                    "session_id": "s1",
                    "timestamp": now.isoformat(),
                    "cpu_pct": 95.0,
                    "ram_pct": 70.0,
                    "cpu_temp_c": 96.5,
                    "gpu_temp_c": 89.0,
                    "gpu_power_w": 240.0,
                    "top_process": "Cyberpunk2077",
                },
            ]
            log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            bb_summary = analyze_blackbox_log(log_file)

        self.assertIsNotNone(bb_summary)
        assert bb_summary is not None
        self.assertTrue(bb_summary["interrupted_detected"])
        self.assertIn("SUPERAQUECIMENTO", bb_summary["verdict"])

        report = analyze_system(_make_base_data(events=events), blackbox_summary=bb_summary)
        self.assertEqual(report.hypotheses[0].cause_id, "overheating")
        self.assertEqual(report.hypotheses[0].confidence, "ALTA")

    def test_blackbox_clean_session_not_flagged_as_crash(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            log_file = Path(tmp) / "caixa_preta.jsonl"
            records = [
                {"type": "session_start", "session_id": "clean1", "timestamp": "2026-11-25T10:00:00"},
                {"type": "sample", "session_id": "clean1", "timestamp": "2026-11-25T10:00:02", "cpu_pct": 12.0},
                {"type": "session_end_clean", "session_id": "clean1", "timestamp": "2026-11-25T10:00:10"},
            ]
            log_file.write_text("\n".join(json.dumps(r) for r in records) + "\n", encoding="utf-8")
            bb = analyze_blackbox_log(log_file)
            self.assertIsNotNone(bb)
            assert bb is not None
            self.assertFalse(bb["interrupted_detected"])

    def test_windows_evaluation_expired_wlms_detected(self) -> None:
        now = datetime(2026, 11, 25, 22, 41, 15)
        events = [
            SystemEvent(
                timestamp=now,
                event_id=101,
                provider="WLMS",
                level="Error",
                log_name="Application",
                message="O período de licença desta instalação do Windows expirou. O sistema operacional está sendo desligado.",
            ),
            SystemEvent(
                timestamp=now,
                event_id=1074,
                provider="User32",
                level="Information",
                log_name="System",
                message="O processo C:\\WINDOWS\\system32\\wlms\\wlms.exe iniciou Desligar o sistema.",
            ),
        ]
        data = _make_base_data(
            events=events,
            license_info={
                "name": "Windows(R), EnterpriseSEval edition",
                "description": "TIMEBASED_EVAL channel",
                "license_status": 5,
                "license_status_text": "Notificação / Expirado (Notification)",
                "grace_period_minutes": 0,
                "is_evaluation": True,
            },
        )
        report = analyze_system(data)
        self.assertEqual(report.hypotheses[0].cause_id, "windows_eval_expired")
        self.assertEqual(report.hypotheses[0].confidence, "ALTA")
        self.assertGreaterEqual(report.hypotheses[0].score, 95)
        self.assertEqual(report.total_unexpected_shutdowns, 1)
        self.assertIn("WLMS", report.incidents[0].kind)

    def test_permission_warning_surfaces_permission_error_hypothesis(self) -> None:
        data = _make_base_data(
            warnings=["Erro ao ler Log System do Windows: Acesso negado."]
        )
        report = analyze_system(data)
        self.assertEqual(report.hypotheses[0].cause_id, "permission_error")

    def test_html_and_json_report_generation(self) -> None:
        report = analyze_system(_make_base_data())
        with tempfile.TemporaryDirectory() as tmp:
            html_out = save_html_report(report, Path(tmp) / "out.html")
            json_out = save_json_report(report, Path(tmp) / "out.json")
            self.assertTrue(html_out.exists())
            self.assertTrue(json_out.exists())
            html_text = html_out.read_text(encoding="utf-8")
            self.assertIn("Diagnóstico de Desligamento Aleatório do PC", html_text)
            parsed = json.loads(json_out.read_text(encoding="utf-8"))
            self.assertEqual(parsed["days_analyzed"], 14)


if __name__ == "__main__":
    unittest.main()
