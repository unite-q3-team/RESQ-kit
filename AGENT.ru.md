# AGENT — ныряйте в любой Quake 3 QVM. Анализируйте, декомпилируйте, пересобирайте.

> Перевод [AGENT.md](AGENT.md); при расхождениях приоритет у английского оригинала.

Вы используете **RESQ**: Restore Everything from Stale QVM.

Этот набор — **универсальный реккомпилятор и оракул для Q3 VM**. Это не порт на скелет.

| задача | планка | этот набор |
|-----|-----|----------|
| **Реккомпиляция / анализ** | `.qvm` → C89 → q3lcc → играбельный `.qvm` (`seqdiff` 0 против исходного модуля) | **да** |
| **Порт на готовые исходники** | переписать тела в другое дерево исходников | **нет** — не изобретайте скелет и не включайте незаполненный `types.rs` |

Пользователь даёт один или несколько файлов `.qvm`. Декомпилируйте их, именуйте функции и объясняйте байткод. Не выдумывайте имена полей структур. Не «чините» эмиттер во время чтения дампа.

Документация в этом наборе — на английском. Если пользователь пишет на другом языке, всё равно держите файлы набора на английском, пока он не попросит иного.

---

## Структура

```
resq-kit/
  AGENT.md                 this file
  README.md                human handoff
  GLOSSARY.md              terms (blob, CONST −4, overlay lie, …)
  docs/                    TOOLS / TOOLCHAIN / ARCHITECTURE / COMPAT / WORKFLOW
  toolchain/qvm/           Rust crate (`src/`, Cargo.toml, Cargo.lock only)
  tools/win32-qvm/         q3lcc / q3cpp / q3rcc / q3asm (Windows)
  tools/dump.py            string / hdr / table / ptrs / identity oracle
  scripts/                 emit_qvm.ps1, build_qvm.ps1
  work/                    put input QVMs and emit output here
```

Не копируйте `qvm/target`, движки, pk3 или identity-дампы конкретного мода в новую сессию, если пользователь их не приложил.

---

## Требования

- Rust (`cargo`)
- Python 3
- Windows для комплектных `q3lcc` / `q3asm` (или ваш собственный lcc/q3asm)
- `vm/qagame.qvm`, `cgame.qvm`, `ui.qvm` мода (в моде их может не быть)

---

## Жёсткие правила

1. **Не передавайте `--typed`, пока пользователь не попросил typed emit, а `src/types.rs` не заполнен под этот модуль.** Эмит по умолчанию generic (`loc_0`, blob). Поставляемый `types.rs` — пустой шаблон; типизированный C из незаполненного или чужого ключа — ложь.
2. **Не правьте `types.rs` «под модуль»**, если пользователь явно не запросил оверлей-ключ, подкреплённый доказательствами. Первый проход — всегда generic identity C.
3. **Не выдумывайте `pers.*`, пады или имена слотов** из hex-смещений. Именуйте поле только тогда, когда байткод + строки это доказывают.
4. **Заголовки оверлея лгут.** `fn[N] SomeStockName` в `.names` / structured-дампе может оказаться коллизией имён. Identity-дамп `int RealName(` плюс первый `L<insn>:` — это байткод. Побеждает identity.
5. **Комментарии CONST часто ±4.** Комментарий `qvm_mem + 45487` может указывать на 4 байта внутри C-строки или за 4 байта до неё. `dump.py str` печатает walk-back / at / +4. Предпочитайте полную C-строку, начинающуюся после NUL. **Указатели цвета / `vec4` — та же ловушка:** lcc не выравнивает float4 на 16 байт, поэтому `qvm_mem + N` часто оказывается альфой предыдущего вектора. Используйте `dump.py color N` (окна при N−4 / N / N+4). Не привязывайте адрес к границе 16 байт.
6. **Identity `.c` — не игровые исходники.** Не компилируйте его как `g_main.c`. Не вставляйте `loc_0`, `qvm_mem` или `va(p0…p59)` в дерево порта.
7. **Постоянные баги эмита чинятся в `probe_emit`, а не в сгенерированном `.c`.** См. `docs-ru/COMPAT.ru.md` (Driver Info `Q_strncpyz`, ClientSpawn `FL_NO_BOTS`). Эти патчи специфичны для образцов; не считайте, что они применимы к другому моду.
8. **q3lcc — это C89.** Никаких `int x;` после инструкций; никаких `for (int i`. Вложенный `{ int x; }` допустим.
9. **В PowerShell псевдоним `cpp` → `Copy-ItemProperty`.** Запускайте q3lcc через `cmd.exe`. Задайте `TMP`/`TEMP` равными `%USERPROFILE%\AppData\Local\Temp` (Cursor часто направляет их в крошечный каталог).
10. Не делайте `git commit` и не пакуйте играбельный pk3, если пользователь не просит.

---

## Конвейер (один модуль)

При необходимости заменяйте `qagame` на `cgame` / `ui`. Пути ниже предполагают, что вы сделали `cd` в `resq-kit/`.

### 0. Сборка проб (один раз)

```powershell
cd toolchain\qvm
cargo build --release --bin probe_emit --bin probe_dump_all --bin probe_sigs `
  --bin probe_align --bin probe_names --bin probe_disasm --bin probe_findfn `
  --bin probe_findconst --bin probe_strat --bin probe_findcall --bin probe_findstore `
  --bin probe_check --bin probe_seqdiff --bin probe_uidiff --bin probe_cgamediff `
  --bin probe_callers --bin probe_inventory --bin probe_data --bin probe_table
```

Бинарники: `toolchain/qvm/target/release/probe_*.exe`.

### 1. Положите QVM в `work/`

```
work/qagame.qvm
```

Или передайте скриптам любой путь.

### 2. Сигнатуры (необязательно, но полезно)

```powershell
.\toolchain\qvm\target\release\probe_sigs.exe work\qagame.qvm work\qagame.sigs
```

### 3. Имена (необязательно)

- Если есть подходящий `.map`: `probe_names.exe work\qagame.qvm qagame.map`
- Иначе выравнивайте против `game.qvm` + `game.map` из **id Tech3 / baseq3** того же класса модуля (game/cgame/ui):

```powershell
.\toolchain\qvm\target\release\probe_align.exe `
  path\to\baseq3\game.qvm path\to\baseq3\game.map `
  work\qagame.qvm
```

Пишет `qagame.names` в текущем каталоге. Ручные имена: `fn[N] HumanName` в `overrides.txt`, передайте `--overrides`.

**Выравнивание — лишь подсказка.** Многие функции останутся `fn_<entry>` или столкнутся с stock-именами. Это нормально.

### 4. Identity-эмит (собираемый C, оракул)

```powershell
.\scripts\emit_qvm.ps1 -Qvm work\qagame.qvm -OutDir work\qagame
```

Или вручную:

```powershell
.\toolchain\qvm\target\release\probe_emit.exe `
  work\qagame.qvm work\qagame\qagame.c work\qagame\syscalls.asm `
  --no-typed --sigs work\qagame.sigs --names work\qagame.names
```

`--no-typed` — значение по умолчанию (флаг всё ещё принимается). `.sigs` / `.names` необязательны (определяются по суффиксу, если вы передаёте пути).

### 5. Structured-дамп (читайте, не компилируйте)

```powershell
.\toolchain\qvm\target\release\probe_dump_all.exe `
  work\qagame.qvm work\qagame\qagame.struct.c work\qagame.names
```

Использует стек потока 512 МиБ. На больших qagame уходят минуты. `--raw` сохраняет написание `loc_N`.

### 6. Пересборка (только если нужен играбельный round-trip)

```cmd
cmd.exe /c "set TMP=%USERPROFILE%\AppData\Local\Temp& set TEMP=%USERPROFILE%\AppData\Local\Temp& set PATH=resq-kit\tools\win32-qvm;%PATH%& cd /d resq-kit\work\qagame& q3lcc.exe -DQ3_VM -S qagame.c & q3asm.exe -vq3 -m -o qagame syscalls.asm qagame.asm"
```

Или `.\scripts\build_qvm.ps1 -SrcDir work\qagame -Stem qagame`.

Приёмка: `probe_check` на пересобранном QVM; `probe_seqdiff orig.qvm rebuilt.qvm` (qagame), `probe_cgamediff` / `probe_uidiff` для остальных модулей. Некоторые UI-образцы держат известный mismatch Driver Info в `trap_S_StartLocalSound` — другой мод должен давать seqdiff 0, если вы не нашли похожего выхода за границы strcpy.

---

## Как читать дамп (оракул)

Предпочитайте `tools/dump.py` grep'у по `.c`-файлам на 80 тыс. строк.

```powershell
python tools\dump.py --qvm work\qagame.qvm hdr
python tools\dump.py --qvm work\qagame.qvm find "Clan Arena"
python tools\dump.py --qvm work\qagame.qvm str 21349
python tools\dump.py --qvm work\qagame.qvm table 19624 -c 8
python tools\dump.py --qvm work\qagame.qvm ptrs 21349
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c --struct work\qagame\qagame.struct.c --names work\qagame.names insn 107760
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c xref SomeString
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar amf_debug
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c calls G_InitGame
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c slot 668
```

| команда | нужен QVM | нужен identity `.c` |
|-----|-----------|---------------------|
| `hdr` `str` `find` `table` `ptrs` | да | нет |
| `insn` `fn` `calls` `slot` `xref` `addcmd` | да | да |
| `cvar` `cvars` | да | identity для grep по `+8`/`obj`; taint опкодов / табличные строки — из самого QVM |

Пробы байткода (без файла дампа):

```powershell
.\toolchain\qvm\target\release\probe_disasm.exe work\qagame.qvm 0 100 200
.\toolchain\qvm\target\release\probe_findfn.exe work\qagame.qvm 107760
.\toolchain\qvm\target\release\probe_findconst.exe work\qagame.qvm 45487
.\toolchain\qvm\target\release\probe_strat.exe work\qagame.qvm 45487
```

---

## Что такое identity C

- Один файл на VM. Функции — **goto** + метки `L<insn>:`. `insn` — счётчик команд VM, а не байтовое смещение в файле.
- Локальные переменные живут в `unsigned char loc_0[frame]`.
- Все глобальные переменные — один **blob** `qvm_mem` / `qvm_mem_words`. Настоящие глобальные C **сдвинули бы BSS** и сломали указатели на трапы.
- `qvm_mem + (CONST − 4)`, потому что слово 0 — NULL-стражник; VM-адрес 4 — это `qvm_mem[0]`.
- **data** = инициализированные данные (в файле). **lit** = C-строки (в файле, после data). **BSS** = нули на этапе выполнения, в `.qvm` их **нет**. Строки видит только data+lit в `dump.py`.
- Трапы — отрицательные CONST (`trap_SendServerCommand`, …).

Structured-дамп (`*.struct.c`) добавляет `if`/`while` и имена оверлея. По-прежнему нельзя компилировать как игру.

---

## Рекомендуемый первый отчёт пользователю

Для каждого модуля (`qagame` / `cgame` / `ui`, которые существуют):

1. Заголовок: число инструкций, размеры data/lit/bss (`dump.py hdr`).
2. Прошли ли emit + q3lcc.
3. Число функций (`.names` / CFG). Сколько выровнялось в стоковые имена, сколько осталось `fn_*`.
4. Характерные строки (имя мода, дополнительные gametype'ы, дополнительные команды) из `dump.py find`.
5. Таблицы команд (`addcmd` в cgame; qagame часто представляет собой dispatch, а не `trap_AddCommand`).
6. Открытые вопросы — безымянная BSS, коллизии оверлея — **перечислены как остаточные, а не выдуманные**. Остаточные cvar'ы: `cvar` / `cvars` (identity `[vm,vm+271]` + taint указателя таблицы), а не пустой `xref NAME`. Ноль загрузок после этого всё равно означает: не вешайте поведение на эту ручку.

Не начинайте порт на baseq3a, пока пользователь не попросил. Этот набор — decompile + explain.
