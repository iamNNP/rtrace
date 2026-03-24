# rtrace

## Русская версия

### Что это

`rtrace` - это инструмент для первичного анализа подозрительных ELF-файлов под Linux.
Он запускает образец в изолированной виртуальной машине, проверяет файл и память
процесса по YARA-правилам, а затем сохраняет результат в понятном виде.

Проект сделан как Blue Team решение: его задача не атаковать систему, а помочь
безопасно проверить подозрительный файл и быстрее понять, что именно он делает.

### Зачем нужен

Обычный статический анализ не всегда видит строки и данные, которые раскрываются
только во время работы программы. Запускать неизвестный ELF-файл прямо на хосте
тоже небезопасно. `rtrace` решает обе проблемы:

- запускает образец в Linux VM, а не на основной системе
- проверяет не только сам файл, но и память процесса
- сохраняет артефакты для последующего разбора
- показывает находки через MITRE ATT&CK
- может остановить процесс сразу после нового срабатывания

### Что умеет

- изолированно запускать подозрительные ELF-файлы в Linux VM
- сканировать исполняемый файл на диске (`FILE`)
- сканировать читаемую память процесса (`MEM`)
- по возможности проверять память по указателям из CPU-регистров (`REG`)
- записывать JSON-артефакты с описанием найденных совпадений
- сопоставлять находки с тактиками и техниками MITRE ATT&CK
- работать в режиме `--stop-on-hit`, если нужно сразу остановить процесс

### Что получится в итоге

После запуска пользователь получает:

- каталог `artifacts/` с файлами `meta.json`
- информацию о процессе: `pid`, `ppid`, путь к файлу, командную строку
- список найденных сигнатур
- канал обнаружения: `FILE`, `MEM` или `REG`
- адрес, смещение и совпавшие байты
- сопоставление с MITRE ATT&CK
- просмотр результатов в локальном WebUI

### Для кого проект

`rtrace` рассчитан на:

- исследователей вредоносного ПО
- Blue Team и SOC-аналитиков
- студентов и школьников, которые изучают анализ ELF-файлов
- тех, кому нужен воспроизводимый стенд для демонстрации runtime-анализа

### Что нужно для запуска

На практике удобнее всего использовать такой стенд:

- Windows
- WSL2
- Ubuntu внутри WSL
- установленный Rust в Ubuntu
- установленный QEMU в Ubuntu
- SSH-клиент на Windows

### Быстрый старт

#### 1. Подготовить виртуальную машину

```powershell
.\scripts\sandbox\windows\prepare_vm.ps1
```

#### 2. Запустить VM и подготовить образец

Рекомендуемый демонстрационный образец:

```powershell
.\scripts\sandbox\windows\start_vm.ps1 -SampleBinary linux_rat_demo -DisplayBackend none
```

Скрипт сам:

- соберет `rtrace-agent`
- положит образец в `samples/`
- запустит Linux VM
- смонтирует `/rules`, `/samples`, `/artifacts`
- откроет SSH на `127.0.0.1:2222`

#### 3. Подключиться к VM

```powershell
ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1
```

Пароль по умолчанию:

```text
rtrace
```

#### 4. Запустить агент внутри VM

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose
```

Если нужен режим активной остановки:

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose --stop-on-hit
```

#### 5. Запустить образец

Во второй консоли VM:

```bash
/samples/linux_rat_demo
```

#### 6. Посмотреть артефакты на хосте

```powershell
Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object FullName
```

Посмотреть последний артефакт:

```powershell
Get-Content (Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

#### 7. Открыть WebUI

```powershell
start .\webui\artifacts_viewer.html
```

После этого в браузере можно загрузить папку `artifacts/`.

### Какие образцы уже есть

В репозитории уже лежат демонстрационные ELF-файлы:

- `linux_rat_demo` - Linux-ориентированный пример с parent/child процессами
- `runtime_noncrypto_multisig` - широкий набор non-crypto сигнатур
- `runtime_multisig` - смешанный multi-signature пример
- `runtime_mem_hit` - минимальная проверка memory-only сценария
- `runtime_eicar` - контрольный тест

### Где что лежит

- `src/` - исходный код на Rust
- `rules/` - YARA-правила
- `scripts/sandbox/windows/` - подготовка и запуск VM
- `scripts/sandbox/linux/` - вспомогательные guest-side скрипты
- `webui/artifacts_viewer.html` - просмотр результатов в браузере
- `tmp/bins/` - демонстрационные бинарные файлы
- `artifacts/` - результаты анализа

### Что важно понимать

`rtrace` - это не промышленная песочница и не полноценная EDR-система.
Это исследовательский и учебный стенд для первичного runtime-анализа.

Проект хорошо подходит для:

- демонстрации анализа ELF-файлов
- проверки YARA-правил
- записи артефактов
- объяснения TTP через MITRE ATT&CK

Но он не обещает:

- полного обхода anti-analysis техник
- покрытия всех семейств Linux-вредоносного ПО
- замены полноценной malware sandbox-платформы

### Главная идея проекта

Если коротко, `rtrace` нужен для того, чтобы безопасно запустить подозрительный
ELF-файл в отдельной Linux VM, автоматически собрать сигнатурные и runtime-артефакты
и представить результат в удобном для анализа виде.

---

## English Version

### What It Is

`rtrace` is a tool for primary analysis of suspicious Linux ELF binaries.
It runs a sample inside an isolated virtual machine, scans the file and the
process memory with YARA rules, and then saves the results in a readable form.

This is a Blue Team project. Its goal is not to attack a system, but to help
an analyst safely inspect a suspicious file and quickly understand what it does.

### Why It Exists

Static analysis does not always see strings or data that only appear during
execution. Running an unknown ELF file directly on the host is also unsafe.
`rtrace` addresses both problems:

- it runs the sample inside a Linux VM instead of on the host
- it scans not only the file itself, but also the process memory
- it stores artifacts for later review
- it maps findings to MITRE ATT&CK
- it can stop the process on the first new hit

### What It Can Do

- run suspicious ELF files in an isolated Linux VM
- scan the executable file on disk (`FILE`)
- scan readable process memory (`MEM`)
- optionally inspect memory referenced by CPU registers (`REG`)
- save structured JSON artifacts
- map findings to MITRE ATT&CK tactics and techniques
- stop the process with `--stop-on-hit` if needed

### What You Get

After a run, the user gets:

- an `artifacts/` directory with `meta.json` files
- process information such as `pid`, `ppid`, executable path, and command line
- a list of detected signatures
- the detection channel: `FILE`, `MEM`, or `REG`
- address, offset, and matched bytes
- MITRE ATT&CK mapping
- a local WebUI for browsing results

### Who This Is For

`rtrace` is useful for:

- malware researchers
- Blue Team and SOC analysts
- students learning ELF analysis
- anyone who needs a reproducible runtime-analysis demo environment

### What You Need

The most practical setup is:

- Windows
- WSL2
- Ubuntu inside WSL
- Rust installed in Ubuntu
- QEMU installed in Ubuntu
- an SSH client on Windows

### Quick Start

#### 1. Prepare the virtual machine

```powershell
.\scripts\sandbox\windows\prepare_vm.ps1
```

#### 2. Start the VM and stage a sample

Recommended demo sample:

```powershell
.\scripts\sandbox\windows\start_vm.ps1 -SampleBinary linux_rat_demo -DisplayBackend none
```

This script will:

- build `rtrace-agent`
- place the sample into `samples/`
- start the Linux VM
- mount `/rules`, `/samples`, and `/artifacts`
- expose SSH on `127.0.0.1:2222`

#### 3. Connect to the VM

```powershell
ssh -o StrictHostKeyChecking=no -p 2222 ubuntu@127.0.0.1
```

Default password:

```text
rtrace
```

#### 4. Run the agent inside the VM

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose
```

If you want active stopping:

```bash
sudo /samples/rtrace-agent --rules-dir /rules --samples-dir /samples --artifacts-dir /artifacts --scan-interval-ms 300 --verbose --stop-on-hit
```

#### 5. Run the sample

In a second VM shell:

```bash
/samples/linux_rat_demo
```

#### 6. Review artifacts on the host

```powershell
Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object FullName
```

Show the latest artifact:

```powershell
Get-Content (Get-ChildItem .\artifacts -Recurse -Filter meta.json | Sort-Object LastWriteTime | Select-Object -Last 1).FullName
```

#### 7. Open the WebUI

```powershell
start .\webui\artifacts_viewer.html
```

Then load the `artifacts/` directory in the browser.

### Included Demo Samples

The repository already includes several demo ELF files:

- `linux_rat_demo` - a Linux-oriented parent/child process scenario
- `runtime_noncrypto_multisig` - broader non-crypto signature coverage
- `runtime_multisig` - a mixed multi-signature example
- `runtime_mem_hit` - a minimal memory-only scenario
- `runtime_eicar` - a simple control test

### Repository Layout

- `src/` - Rust source code
- `rules/` - YARA rules
- `scripts/sandbox/windows/` - VM preparation and startup
- `scripts/sandbox/linux/` - guest-side helper scripts
- `webui/artifacts_viewer.html` - browser-based artifact viewer
- `tmp/bins/` - demo binaries
- `artifacts/` - analysis output

### Important Notes

`rtrace` is not a full production sandbox and not a full EDR platform.
It is a research and educational environment for primary runtime analysis.

It is well suited for:

- demonstrating ELF analysis
- validating YARA rules
- recording artifacts
- explaining TTP through MITRE ATT&CK

It does not promise:

- full anti-analysis bypass coverage
- coverage of every Linux malware family
- replacement of a complete malware sandbox platform

### Main Idea

In short, `rtrace` exists to safely run a suspicious ELF file inside a separate
Linux VM, automatically collect signature and runtime artifacts, and present the
results in a form that is easy to review.
#   r t r a c e  
 