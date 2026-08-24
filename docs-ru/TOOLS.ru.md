# Инструменты RESQ

> Перевод [../TOOLS.md](../docs/TOOLS.md); при расхождениях приоритет у английского оригинала.

Относительно корня набора. После сборки: `toolchain/qvm/target/release/*.exe`. Обёртки: `scripts/emit_qvm.ps1`, `scripts/build_qvm.ps1`. Постоянные распоряжения: [AGENT.ru.md](../AGENT.ru.md).

## Сборка

```powershell
cd toolchain\qvm

# One tool
cargo build --release --bin probe_emit

# Core set
cargo build --release --bin probe_emit --bin probe_uidiff --bin probe_seqdiff `
  --bin probe_disasm --bin probe_findfn --bin probe_findconst --bin probe_check `
  --bin probe_strat --bin probe_align --bin probe_sigs --bin probe_callers

# Every probe_* in src/bin (slow)
Get-ChildItem src\bin\probe_*.rs | ForEach-Object {
  cargo build --release --bin $_.BaseName
}
```

Компилятор QVM для хоста (не Rust) лежит отдельно:

| файл | роль |
|------|------|
| `tools/win32-qvm/q3lcc.exe` | C → asm (`-DQ3_VM -S`) |
| `tools/win32-qvm/q3cpp.exe` / `q3rcc.exe` | препроцессор / бэкенд lcc |
| `tools/win32-qvm/q3asm.exe` | asm → `.qvm` (сборка **hex-aware**) |
| `tools/win32-qvm/7za.exe` | 7-Zip CLI — распаковка pk3 мода (zip); вне конвейера тулчейна |

Скрипты-обёртки: `scripts/emit_qvm.ps1`, `scripts/build_qvm.ps1` (см. `TOOLCHAIN.ru.md`).

---

## Конвейер (минимум)

### `probe_emit`: декомпиляция → собираемый C

```text
probe_emit <in.qvm> <out.c> <out-syscalls.asm> [--sigs file] [--names file]
           [--only a,b,c] [--lst stem] [--typed] [--no-typed]
```

```powershell
New-Item -ItemType Directory -Force -Path ..\..\work\ui | Out-Null
.\target\release\probe_emit.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui.c `
  ..\..\work\ui\syscalls.asm `
  --no-typed
```

Передавайте дополнительные пути `.sigs` / `.names`, когда они уже сгенерированы (см. ниже). Эмитит C89, готовый к q3lcc, `syscalls.asm`, встраивает образ данных (`qvm_mem_words`). UI может получить compat-переписывание Driver Info (`Q_strncpyz`).

Необязательные флаги: `--only a,b,c` эмитит подмножество функций плюс их замыкание по вызовам; `--wrapper` добавляет заглушку `vmMain`, ссылающуюся на каждую эмитнутую функцию, чтобы entry-root-обрезка q3asm не выбросила частичное множество (применять с `--only`); `--lst stem` пишет список файлов `.lst` для q3asm (`syscalls.asm` + `<stem>.asm`) для частичных сборок.

### `q3lcc` + `q3asm`: C → QVM

```powershell
# Prefer scripts/build_qvm.ps1 — it resets TMP and calls q3lcc via cmd.exe
$tmp = Join-Path $env:USERPROFILE 'AppData\Local\Temp'
$env:Path = "$(Resolve-Path ..\..\tools\win32-qvm);$env:Path"
cd ..\..\work\ui
cmd.exe /c "set TMP=$tmp& set TEMP=$tmp& q3lcc.exe -DQ3_VM -S ui.c & q3asm.exe -vq3 -m -o ui_test syscalls.asm ui.asm"
```

Или: `..\..\scripts\build_qvm.ps1 -SrcDir ..\..\work\ui -Stem ui`.

---

## Диагностика байткода

| инструмент | вызов | назначение |
|------|------------|---------|
| `probe_disasm` | `probe_disasm <qvm> [fn] [lo] [hi]` | дизассемблировать `fn[fn]` или явный диапазон insn |
| `probe_findfn` | `probe_findfn <qvm> <insn\|entry>` | какая функция владеет insn |
| `probe_findconst` | `probe_findconst <qvm> <value>` | все `CONST value` + следующий опкод |
| `probe_findcall` | `probe_findcall <qvm> <target>` | CALL'ы в fn или trap (отрицательный) |
| `probe_findstore` | `probe_findstore <qvm> <addr>` | STORE по абсолютному адресу данных |
| `probe_strat` | `probe_strat <qvm> <off> [off…]` | строка по смещению data/lit |
| `probe_data` | `probe_data <qvm> <start_byte> [count]` | дамп слов данных вокруг смещения (`f=` + `vec4`, если похоже на цвет) |
| `probe_addr2idx` | `probe_addr2idx <qvm> <byte_addr>` | адрес байта кода → индекс insn |
| `probe_check` | `probe_check <qvm>` | статические проверки вроде `VM_CheckInstructions` |
| `probe_calls` | `probe_calls <qvm> <fn_index>` | CALL'ы внутри одной функции |
| `probe_callers` | `probe_callers <qvm> [--named] [--min N] [--only N,M,…]` | вызывающие + строки/trap'и |
| `probe_inventory` | `probe_inventory <qvm>` | trap'ы и строки по функциям |
| `probe_indircall` | `probe_indircall <qvm>` | косвенный CALL / формы таблиц |

Примеры:

```powershell
.\target\release\probe_disasm.exe ..\..\work\ui.qvm 0 30504 30570
.\target\release\probe_findfn.exe ..\..\work\ui.qvm 30504
.\target\release\probe_findconst.exe ..\..\work\ui.qvm 19048
.\target\release\probe_strat.exe ..\..\work\ui.qvm 19048 19480
.\target\release\probe_check.exe ..\..\work\ui\ui_test.qvm
```

Живой Quake3e может пипхол-переписывать байткод: PC из отладчика ≠ индексам `probe_disasm`. Смещения data остаются на месте.

---

## Имена и сигнатуры

Эти файлы генерируются под тот QVM, который вы смотрите. Кладите их в `work/<module>/` и передавайте `probe_emit`. Без них функции становятся `fn_<entry>`, а арность берётся из байткода. С ними в C появляются реальные имена и более точные прототипы.

Формат:

```text
# .names
fn[0] vmMain
fn[7] G_InitGame

# .sigs
fn[0] vmMain frame=28 args=3 ret=int
    arg0=ptr arg1=ptr arg2=ptr
```

`fn[N]` — это индекс функции в CFG (порядок `probe_findfn` / `build_functions`). `probe_emit` выбирает путь по суффиксу (`.names` / `.sigs`); `--names` / `--sigs` — просто маркеры.

### `.sigs` из QVM

```powershell
New-Item -ItemType Directory -Force -Path ..\..\work\ui | Out-Null
.\target\release\probe_sigs.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui.sigs
```

Опционально: передайте существующий `.names`, чтобы строки сигнатур несли эти имена. `probe_sigs` выводит frame, арность и `void|int|float` из ENTER / ARG / LEAVE.

### `.names` из `.map` того же QVM

Если у вас уже есть q3asm `.map` этого бинарника:

```powershell
cargo build --release --bin probe_names
.\target\release\probe_names.exe ..\..\work\ui.qvm ui.map
# writes ui.names in the current directory
```

`--all` печатает и безымянные функции. Инструмент всегда пишет `{stem}.names`.

### `.names` выравниванием по известной сборке

Когда у старого QVM нет карты, снимите его отпечаток против родственного QVM, у которого она есть (id Tech3 `game.qvm` + `game.map` или любая пересборка, поставлявшаяся с картой):

```powershell
cargo build --release --bin probe_align
.\target\release\probe_align.exe `
  path\to\known\game.qvm `
  path\to\known\game.map `
  ..\..\work\qagame.qvm
# writes qagame.names in the current directory
```

Проходы: точный (опкод+операнд), только по опкодам, строковая/trap-сигнатура, затем trigram Jaccard (мера Жаккара по триграммам). Скопируйте `.names` рядом с модулем.

Ручные имена, которые выравнивание пропустило, кладутся в локальный `overrides.txt` (`fn[N] Name`, комментарии с `#`). Передавайте его с `--overrides`; эти строки главнее:

```powershell
.\target\release\probe_align.exe `
  path\to\known\game.qvm path\to\known\game.map `
  ..\..\work\qagame.qvm `
  --overrides ..\..\work\qagame\overrides.txt
```

### `.map` из `.names`

```powershell
.\target\release\probe_origmap.exe `
  ..\..\work\qagame.qvm `
  ..\..\work\qagame\qagame.names `
  qagame.map
```

### Прочее

| инструмент | вызов | назначение |
|------|------------|---------|
| `probe_typer` | `probe_typer <qvm> [types.txt] [--names file]` | кластеризация обращений к памяти (типы / регионы) |

---

## Диффы оригинал vs пересборка (эмулятор)

Прогоните один и тот же сценарий `vmMain` на обоих QVM и сравните trap-логи.

| инструмент | модуль | типичный вызов |
|------|--------|--------------|
| `probe_uidiff` | ui | `probe_uidiff <orig.ui.qvm> <rebld.ui.qvm>` |
| `probe_seqdiff` | qagame | `probe_seqdiff <orig> <rebld>` |
| `probe_cgamediff` | cgame | `probe_cgamediff <orig> <rebld>` |
| `probe_diff` | одна fn | `probe_diff <orig> <rebld> <fn> [args…]` |
| `probe_verify` | одна fn | эмуляция + печать trap'ов со строками |
| `probe_emu` | одна fn | `probe_emu <qvm> [fn_index] [args…]` |

```powershell
$env:QVM_UI_CROSSHAIR_MODEL = '1'   # optional
.\target\release\probe_uidiff.exe `
  ..\..\work\ui.qvm `
  ..\..\work\ui\ui_test.qvm
```

На сэмпловом UI ожидайте несколько известных несовпадений аргументов `trap_S_StartLocalSound`. Ошибки эмулятора означают, что что-то сломалось.

Переменные окружения:

| переменная | эффект |
|----------|--------|
| `QVM_UI_CROSSHAIR_MODEL=1` | более полное покрытие прицела в Game Options |
| `QVM_SEQ_VERBOSE=1` | подробный trap-дамп при несовпадении |
| `QVM_TRACE_CALLS` / `QVM_TRACE_STEP` | трассировка ENTER/LEAVE/CALL на пересборке |
| `QVM_ARGV0=<cmd>` | `Argv(0)` для проб консольных команд |
| `QVM_MODEL_MATH=1` | sin/cos/sqrt в харнессе |

---

## Узкие пробы

Под конкретный баг. В ежедневную сборку не включать:

`probe_cgcmd`, `probe_cgframe`, `probe_cgdecal`, `probe_ginit`, `probe_pm`, `probe_sqrt`, `probe_state`, `probe_stepdiff`, `probe_persist`, `probe_shift` / `probe_shift2`, `probe_datacmp`, `probe_whocalls`, `probe_decompile`, `probe_structure`, `probe_switch*`, `vmdbg_diff`.

Остальное в `src/bin` (`probe_any`, `probe_blocks`, `probe_cfg`, `probe_checklit`, `probe_chk2`, `probe_chkstr`, `probe_cmdtable`, `probe_findlit`, `probe_fn`, `probe_insns`, `probe_load`, `probe_rebld`, `probe_stubs`, `probe_table`, `probe_trace`, `probe_ucmp`, `probe_vf`) — экспериментальный черновик: каталога нет, стабильность не обещана. Запуск без аргументов обычно печатает `usage`.

`probe_dump_all` — часть ежедневного identity-конвейера (структурированный дамп). Нужен большой стек потока; большие qagame считаются минутами.

Запуск без аргументов обычно печатает `usage`.

---

## Повседневный набор

```powershell
cargo build --release --bin probe_emit --bin probe_check `
  --bin probe_disasm --bin probe_findfn --bin probe_findconst `
  --bin probe_strat --bin probe_uidiff --bin probe_seqdiff --bin probe_cgamediff
```

Затем emit → `scripts/build_qvm.ps1`. Упаковывайте pk3 только по запросу пользователя.

---

## dump.py (строковый / identity оракул)

```powershell
python tools\dump.py --qvm work\qagame.qvm hdr
python tools\dump.py --qvm work\qagame.qvm find "Clan Arena"
python tools\dump.py --qvm work\qagame.qvm str 21349
python tools\dump.py --qvm work\ui.qvm color 5148
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c insn 107760
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar cg_damageKick
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
```

`--qvm` обязателен. `--c` / `--struct` / `--names` необязательны и по умолчанию указывают на соседей QVM (`stem.c`, `stem/stem.c`, …). `hdr` / `str` / `find` / `table` / `ptrs` / `color` требуют только QVM. `insn` / `fn` / `calls` / `slot` / `xref` / `addcmd` требуют identity `.c`. Для `cvar` / `cvars` нужен QVM ради таблицы и identity `.c` ради количеств загрузок.

**Цветовые указатели:** `str` — для C-строк. CONST вида `menutext.color` / `SetColor` — это `vec4*`. `color N` печатает RGBA по N−4 / N / N+4 (CONST часто в середине вектора; без выравнивания на 16 байт). `table` печатает `f=` на нестроковых dword.

**Загрузки cvar:** `xref` следует только за **строкой имени**. Геймплей обычно держит CONST `vmCvar+8` (BSS), так что используемый cvar может выглядеть неиспользуемым. Используйте `cvar NAME` / `cvars` (полный `[vm,vm+271]`, погоня за указателем таблицы, taint по опкодам; пропуск Register/Update по диапазону insn). Рецепт и промах по `amf_debug`: [CVAR_XREF.ru.md](CVAR_XREF.ru.md).
