# rtrace

Инструмент для первичного анализа ELF-файлов под Linux в изолированной VM.

---

## Русская версия

### Что это

`rtrace` нужен для простой задачи: взять подозрительный ELF-файл, запустить его не на хосте, а в отдельной Linux VM, и посмотреть, что нашлось по YARA в файле и в памяти процесса.

На выходе проект пишет JSON-артефакты и показывает находки через MITRE ATT&CK.

### Когда он полезен

`rtrace` подходит, если нужно:

- безопасно проверить подозрительный ELF
- быстро показать demo runtime-анализа
- посмотреть, что появляется только в памяти
- сохранить результат в читаемом виде
- остановить процесс после первого нового хита

Это не “антивирус на все случаи жизни” и не полноценная песочница. Это компактный стенд для первичного разбора.

### Что он делает

- запускает образец в Linux VM
- проверяет файл на диске (`FILE`)
- проверяет читаемую память процесса (`MEM`)
- по возможности связывает находки с регистрами (`REG`)
- сохраняет `meta.json`
- добавляет MITRE ATT&CK mapping
- умеет работать с `--stop-on-hit`

### Что нужно

Хост:

- Windows
- WSL2
- SSH-клиент

Внутри WSL:

- Ubuntu
- Rust
- QEMU

### Быстрый старт

#### 1. Подготовить VM

```powershell
.\scripts\sandbox\windows\prepare_vm.ps1
```

#### 2. Запустить VM с demo-образцом

```powershell
.\scripts\sandbox\windows\start_vm.ps1 -SampleBinary linux_rat_demo -DisplayBackend none
```

#### 3. Подключиться в гостевую систему

```powershell
ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1
```

Пароль по умолчанию:

```text
rtrace
```

#### 4. Запустить агент

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose
```

Если нужен режим остановки процесса:

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose --stop-on-hit
```

#### 5. Запустить sample

Во второй консоли:

```bash
/samples/linux_rat_demo
```

#### 6. Посмотреть результат

На хосте:

```powershell
Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object FullName
```

Последний артефакт:

```powershell
Get-Content (Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

WebUI:

```powershell
start .\webui\artifacts_viewer.html
```

### Что лежит в артефактах

В `artifacts/` появляются каталоги со снапшотами. Внутри каждого есть `meta.json`.

В нем обычно есть:

- `pid`, `ppid`
- путь к файлу и командная строка
- имя правила
- канал `FILE`, `MEM` или `REG`
- адрес и смещение
- совпавшие байты
- ATT&CK mapping

### Демонстрационные образцы

Основные встроенные sample:

- `linux_rat_demo` — Linux-ориентированный демонстрационный сценарий
- `runtime_noncrypto_multisig` — широкий набор non-crypto сигнатур
- `runtime_multisig` — несколько разных хитов за один запуск
- `runtime_mem_hit` — минимальный memory-only сценарий
- `runtime_eicar` — контрольный пример
- `clean_baseline` — “чистый” ELF без ожидаемых хитов

### Куда смотреть в репозитории

- `src/` — код на Rust
- `rules/` — YARA-правила
- `scripts/sandbox/windows/` — запуск и подготовка VM
- `scripts/sandbox/linux/` — helper-скрипты внутри гостя
- `webui/` — просмотр артефактов
- `tmp/bins/` — demo-бинарники
- `artifacts/` — результат анализа

### Ограничения

У проекта есть границы:

- это не production sandbox
- это не EDR
- он зависит от набора YARA-правил
- он не обещает полный обход anti-analysis техник

Нормальный способ воспринимать `rtrace` — как удобный стенд для первичного анализа и демонстрации.

---

## English Version

### What It Is

`rtrace` is a small tool for primary analysis of suspicious Linux ELF binaries.

The idea is simple: run a sample inside a separate Linux VM instead of on the host, scan the file and process memory with YARA, and save the results as JSON artifacts.

### When It Is Useful

Use `rtrace` when you want to:

- inspect a suspicious ELF more safely
- demonstrate runtime analysis
- catch strings that only appear in memory
- save findings in a readable form
- stop a process after the first new hit

It is not a full antivirus and not a full sandbox. It is a compact lab environment for primary analysis.

### What It Does

- runs a sample in a Linux VM
- scans the executable on disk (`FILE`)
- scans readable process memory (`MEM`)
- optionally correlates hits with CPU registers (`REG`)
- saves `meta.json`
- adds MITRE ATT&CK mapping
- supports `--stop-on-hit`

### Requirements

Host:

- Windows
- WSL2
- SSH client

Inside WSL:

- Ubuntu
- Rust
- QEMU

### Quick Start

#### 1. Prepare the VM

```powershell
.\scripts\sandbox\windows\prepare_vm.ps1
```

#### 2. Start the VM with a demo sample

```powershell
.\scripts\sandbox\windows\start_vm.ps1 -SampleBinary linux_rat_demo -DisplayBackend none
```

#### 3. Connect to the guest

```powershell
ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1
```

Default password:

```text
rtrace
```

#### 4. Run the agent

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose
```

If you want active stopping:

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose --stop-on-hit
```

#### 5. Run the sample

In a second shell:

```bash
/samples/linux_rat_demo
```

#### 6. Review the output

On the host:

```powershell
Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object FullName
```

Latest artifact:

```powershell
Get-Content (Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

WebUI:

```powershell
start .\webui\artifacts_viewer.html
```

### What You Get

The `artifacts/` directory contains snapshot folders with `meta.json`.

A typical artifact includes:

- `pid`, `ppid`
- executable path and command line
- matched rule
- detection channel: `FILE`, `MEM`, or `REG`
- address and offset
- matched bytes
- ATT&CK mapping

### Demo Samples

Main built-in samples:

- `linux_rat_demo`
- `runtime_noncrypto_multisig`
- `runtime_multisig`
- `runtime_mem_hit`
- `runtime_eicar`
- `clean_baseline`

### Repository Layout

- `src/` — Rust code
- `rules/` — YARA rules
- `scripts/sandbox/windows/` — VM preparation and startup
- `scripts/sandbox/linux/` — guest-side helpers
- `webui/` — artifact viewer
- `tmp/bins/` — demo binaries
- `artifacts/` — analysis output

### Limits

`rtrace` has clear limits:

- it is not a production sandbox
- it is not an EDR
- it depends on the YARA rule set
- it does not claim full anti-analysis coverage

The right way to treat it is as a practical lab tool for primary ELF runtime analysis.
