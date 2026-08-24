# Тулчейн

> Перевод [../TOOLCHAIN.md](../docs/TOOLCHAIN.md); при расхождениях приоритет у английского оригинала.

Пути относительно корня набора. Начните с [AGENT.ru.md](../AGENT.ru.md). Входные QVM кладите в `work/`.

## Требования

- Rust (`cargo`)
- `tools/win32-qvm/` (`q3lcc`, `q3cpp`, `q3rcc`, `q3asm`) — Windows-бинарники из этого набора
- Python 3 (`tools/dump.py`)
- один или несколько старых `.qvm` мода

Добавьте `tools/win32-qvm` в `PATH` либо вызывайте exe по полному пути. PowerShell алиасит `cpp` на `Copy-ItemProperty`; q3lcc всегда запускайте через `cmd.exe` (см. `scripts/build_qvm.ps1`).

## 0. Сборка QVM мода из C-исходников (опционально)

Если есть исходники мода вместо старого `.qvm` (например, baseq3a), повторяйте
собственный сборочный скрипт мода, подменив только тулзы набора. Ванильный
game-модуль, флаги как в его `compile.bat`:

```bat
rem каждый .c (cwd = каталог исходников):
q3lcc.exe -DQ3_VM -DQAGAME -S -Wf-g g_main.c
rem затем ассемблирование:
q3asm.exe -vq3 -m -v -o qagame -f qagame.q3asm
```

Подводные камни тулчейна набора, проверены на поставляемых бинарниках:

- Пара `q3lcc`/`q3cpp` из набора **не** понимает `-I`, и quoted-`#include`
  тоже не ищется относительно включающего файла — только от CWD процесса.
  Компилируйте с CWD внутри каталога исходников, затем переносите готовые
  `.asm` в свой выходной каталог.
- У `q3asm` из набора нет флага `-r` (это опция форка); используйте `-vq3 -m`.
- `q3asm -f` требует полное имя listfile (`game.q3asm`; суффикс не
  дописывается автоматически).
- Держите `.q3asm`-listfile плоским (голые имена) рядом с `.asm`-выводами;
  внешние `.asm` (например, `g_syscalls.asm`) копируйте туда же.

## 1. Сборка проб

Каталог и флаги: [TOOLS.ru.md](TOOLS.ru.md).

```powershell
cd toolchain\qvm
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs `
  --bin probe_align --bin probe_names --bin probe_disasm --bin probe_findfn `
  --bin probe_findconst --bin probe_strat --bin probe_check --bin probe_seqdiff `
  --bin probe_uidiff --bin probe_cgamediff
```

Вывод: `toolchain/qvm/target/release/`.

## 2. Identity emit (untyped по умолчанию)

```powershell
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
```

Это запускает `probe_sigs` (если нужен), `probe_emit --no-typed`, затем `probe_dump_all`.

Вручную:

```powershell
cd toolchain\qvm
.\target\release\probe_emit.exe `
  ..\..\work\qagame.qvm `
  ..\..\work\qagame\qagame.c `
  ..\..\work\qagame\syscalls.asm `
  --no-typed --sigs ..\..\work\qagame\qagame.sigs --names ..\..\work\qagame.names
```

Typed emit использует `src/types.rs` — опциональный оверлей data-space под конкретный мод, поставляемый как **пустой шаблон**. Заполните его по собственной реконструкции (гайдлайн в шапке файла) до передачи `--typed`.

Постоянные C-фиксы кладите в `probe_emit`, а не в сгенерированный `.c`. Патчи, специфичные для образцов: [COMPAT.ru.md](COMPAT.ru.md) — не считайте, что они применимы.

## 3. C → QVM (round-trip)

```powershell
.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame
```

Linux: `./scripts/build_qvm.sh work/qagame qagame` — нужны lcc-based `q3lcc` / `q3asm` в `PATH`.

Вручную:

```powershell
$tmp = Join-Path $env:USERPROFILE 'AppData\Local\Temp'
$tools = Resolve-Path tools\win32-qvm
cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& set PATH=$tools;%PATH%& cd /d work\qagame& q3lcc.exe -DQ3_VM -S qagame.c & q3asm.exe -vq3 -m -o qagame syscalls.asm qagame.asm"
```

Приёмка: `probe_check` на пересобранном QVM; `probe_seqdiff orig.qvm rebuilt.qvm` (qagame). Для UI/cgame есть `probe_uidiff` / `probe_cgamediff`.

## Примечания

- В этом дереве поставляется hex-aware `q3asm` (большие blob'ы / литералы `0x…`).
- Quake3e может пипхолить байткод при загрузке: живой PC ≠ индексу `probe_disasm`. Смещения data остаются на месте.
- Оболочки Cursor/агентов часто направляют `TMP`/`TEMP` в крошечный каталог — `build_qvm.ps1` их сбрасывает.
