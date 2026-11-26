# Diagnóstico de Desligamento Aleatório do PC (Windows)

Programa em Python (sem dependências externas — 100% biblioteca padrão + ferramentas nativas do Windows) feito para investigar **por que um computador está desligando ou reiniciando aleatoriamente**.

## O que o programa investiga

### 1. Análise Forense do Histórico do Windows (`python main.py`)
- **Logs de Eventos do Sistema (`Event Viewer`)**:
  - `Kernel-Power 41`: analisa `BugcheckCode`, `PowerButtonTimestamp` e `ThermalState` para distinguir **corte súbito de energia** (`BugcheckCode = 0`) de **Tela Azul (BSOD)** (`BugcheckCode != 0`).
  - `EventLog 6008`: registra desligamentos inesperados.
  - `WHEA-Logger (18, 19, 20, 46, 47)`: detecta erros de hardware em CPU, cache, memória RAM ou barramento PCIe.
  - `BugCheck 1001` e `C:\Windows\Minidump`: identifica Telas Azuis recentes e traduz códigos Stop conhecidos (`0x124`, `0x116`, `0x1A`, etc.).
  - `Kernel-Power 86–89` e `Event ID 37`: detecta alertas térmicos ACPI e throttling de processador.
  - `Display 4101`: detecta travamentos do driver de vídeo (TDR).
  - `disk / stornvme (7, 11, 51, 129, 153)`: detecta falhas de SSD/HD.
  - `User32 1074` e `WLMS (Application 100/101)`: identifica desligamentos iniciados por software, Windows Update ou **licença de avaliação do Windows (Evaluation) expirada**, que desliga o PC automaticamente a cada 1 hora via `wlms.exe`.
- **Saúde Atual do Hardware**:
  - Temperaturas via ACPI Thermal Zone, contadores do Windows, `nvidia-smi` (GPUs NVIDIA) e `LibreHardwareMonitor`/`OpenHardwareMonitor` (caso estejam abertos).
  - Saúde e desgaste (SMART) dos SSDs/HDs (`Get-PhysicalDisk` / `Get-StorageReliabilityCounter`).
  - Configuração de memória RAM, BIOS e bateria (em notebooks).
- **Motor de Diagnóstico Ranqueado + Relatório HTML**:
  - Cruza os eventos próximos a cada desligamento em uma linha do tempo, calcula as hipóteses mais prováveis (Fonte/PSU, Superaquecimento, Hardware/WHEA, BSOD/Drivers, Disco/SSD ou Software) e salva um relatório visual em `relatorios/diagnostico_desligamento.html`.

### 2. Modo Caixa-Preta em Tempo Real (`python main.py --monitor`)
Quando um PC desliga por **superaquecimento súbito** ou **desarme da fonte (PSU)**, o Windows frequentemente perde energia antes de gravar qualquer erro no log.

A **Caixa-Preta** grava a cada 2 segundos (com `flush` + `fsync` direto no disco em `logs/caixa_preta.jsonl`):
- Uso de CPU (%) e RAM (%)
- Temperatura de CPU (quando disponível)
- Temperatura, uso (%) e consumo em Watts da GPU NVIDIA
- Processo mais pesado em execução

Quando o PC desligar e você ligá-lo novamente, basta rodar `python main.py` (ou `executar_diagnostico.bat`): o programa detecta automaticamente a sessão interrompida e revela o que estava acontecendo nos últimos segundos antes da queda!

## Como usar

### Opção 1 — Duplo clique (mais fácil)
1. Para analisar o histórico agora: clique com o botão direito em `executar_diagnostico.bat` e escolha **Executar como administrador** (recomendado para ler todos os sensores térmicos e Minidumps).
2. Para capturar a próxima queda em tempo real: execute `iniciar_caixa_preta.bat` e deixe rodando enquanto usa ou joga no PC.

### Opção 2 — Terminal (PowerShell / CMD)
```powershell
# Diagnóstico padrão (últimos 14 dias) + relatório HTML
python main.py

# Analisar os últimos 60 dias e abrir o relatório HTML no navegador
python main.py --dias 60 --abrir

# Exportar também os dados completos em JSON
python main.py --dias 30 --json relatorios/diagnostico.json

# Iniciar a Caixa-Preta em tempo real (amostragem a cada 2 segundos)
python main.py --monitor --intervalo 2
```

> **Dica para leitura completa de temperatura da CPU no Windows:** placas-mãe de desktop frequentemente não expõem a temperatura real da CPU via ACPI nativo do Windows. Se quiser que a Caixa-Preta registre a temperatura exata de cada núcleo da CPU, deixe o **LibreHardwareMonitor** aberto minimizado em segundo plano — o programa lê os sensores dele automaticamente via WMI!
