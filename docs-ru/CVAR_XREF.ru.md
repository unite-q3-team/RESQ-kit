# Cvar BSS xref (`dump.py cvar`)

> Перевод [../CVAR_XREF.md](../docs/CVAR_XREF.md); при расхождениях приоритет у английского оригинала.

Геймплейные CONST — это **`vmCvar+8`** (float `.value`, часто проверяется как `int != 0`) или **`+12`** (`.integer`). `dump.py xref NAME` идёт только по **C-строке**. Пустой xref ≠ не используется.

```powershell
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvar amf_debug
python tools\dump.py --qvm work\qagame.qvm --c work\qagame\qagame.c cvars
```

`cvar` / `cvars` (алиас `cvarxref`) обходят таблицу cvar, затем:

1. Identity CONST где угодно в **`[vmCvar, vmCvar+271]`** (классифицируются read / write / address-only). Компактные `+8` / `+12` и ioq3 `+260` / `+264` по-прежнему перечисляются первыми.
2. Opcode taint по `.qvm` (CONST / LOAD / ADD / LOCAL → LOAD1/2/4), включая **table-pointer chase**: `LOAD *(table+row*stride)`, затем `LOAD *(p+8)` — identity никогда не печатает `qvm_mem+<этот BSS>` для таких случаев.
3. Уход указателя: `&vmCvar` как аргумент вызова; **источник** `BLOCK_COPY` внутри 272-байтового объекта (dest-only чтением не считается).

Пропускайте именно **диапазоны инструкций Register/Update** (обход таблицы `loc += stride` плюс `trap_Cvar_Register|Update`), а не имена оверлея вроде `RegisterCvars`. Чтение после цикла в той же функции всё равно считается. Default-copy в ROM Update — не геймплейное чтение.

Name-dword таблицы могут быть `find_off` или `find_off+0x100`; `ptrs` ищет оба варианта. Автодетект stride: **16–32** (стоковый cgame/ui обычно 16; образец qagame 101×28 @ VM 4). `vmCvar_t` занимает 272 байта: **`+280` — это `+8` следующего cvar**, а не этот `.integer`. `cvars` оставляет колонку `+8`; `obj` — прочие identity-попадания `[vm,vm+271]`; `tbl` — упущенное table-pointer / taint identity.

Если ничего не осталось: `no CONST, no table-pointer LOAD, no [vm,vm+271] hit outside Register/Update ranges`. Пустой `xref NAME` — всё ещё не «не используется».

Ниже — кейс разобранный кейс qagame. Термины набора: [GLOSSARY.ru.md](../GLOSSARY.ru.md).

## Симптом (почему `xref` солгал)

`amf_debug` был каталогизирован как **leftover** (зарегистрирован, «нет чтения»): `dump.py xref amf_debug` пуст, а `grep amf_debug` по `qagame.c` пуст, кроме упакованного data blob.

В игре он используется. При `amf_debug 1` наблюдатели видят неподвижные плазменные (иногда ракетные) сферы в точке, куда бот прыгает/идёт.

Байткод **действительно** читает этот cvar. Строковый xref этого не показал.

## Почему строковый xref молчит

Геймплей почти никогда не ставит CONST на **строку имени**. Он ставит CONST на **BSS-адрес `vmCvar_t`**.

| Что мы грепали | Что VM реально берёт через CONST |
|-----------------|----------------------------|
| `"amf_debug"` / `qvm_mem + 13923` (или `@14179`) | `qvm_mem + 54716` (`vmCvar+8`) |
| `trap_Cvar_VariableIntegerValue("amf_debug")` | не используется |

`dump.py xref` идёт только по **строковым** смещениям (`qvm_mem + N` для C-строки и ±4). Он никогда не проходит по таблице cvar до BSS-ячейки.

`grep amf_debug` по identity C тоже ничего не даёт: lit упакован как hex-dwords `qvm_mem_words[]`, а не как C-литералы `"amf_debug"`:

```
eWeapon\0amf_debug\0g_blinkImp
```

в `qagame.c` рядом с data blob (`(void*)0x645f666du` …).

`G_RegisterCvars` / `G_UpdateCvars` обходят таблицу по указателю (`loc_24 += 28`) и зовут `trap_Cvar_Update`. Это **не** геймплейное чтение. ROM-строки (`flags & 64`) копируют дефолт обратно в строку `vmCvar`; это тоже не чтение `.value` для AI.

## Раскладка таблицы (что обходит `cvar`)

Таблица образец qagame: **101 строка**, stride **28**, счётчик по адресу **`qvm_mem+2828`**, первый `vmCvar*` по **VM-адресу 4**. Другие моды: stride 16 / 20 / 24 / 28 / 32 (автодетект).

Раскладка строки (совпадает с id-шным `cvarTable_t`):

| смещение | поле |
|-----|--------|
| +0 | `vmCvar_t *` (BSS) |
| +4 | указатель на имя |
| +8 | указатель на дефолт |
| +12 | флаги |
| +16 | снимок modificationCount |
| +20 | trackChange |
| +24 | teamShader |

**Name/default dword могут быть на `0x100` выше смещений `dump.py find`.**  
Пример: строка на `@13923` против табличного dword `14179` (`13923+256`). Текущий `find amf_debug` на этом QVM выдаёт `@14179` (dword уже совпадает). Тот же сдвиг у `g_buildWPs` (`14743` против `14999`). Это **в добавление** к правилу комментария CONST −4 из глоссария.

Ручной рецепт (теперь внутри `cvar`):

1. `find NAME` → смещение строки.
2. Ищите в таблице `name == find_off` или `find_off + 0x100`. Считайте `vmCvar`.
3. Identity: `*(int*)(qvm_mem + <vmCvar+8>)` / `*(float*)(qvm_mem + <vmCvar+4>)`.

Этот QVM проверяет **`+8`** как int (`!= 0` работает для `"0"`/`"1"`, потому что все биты `0.0f` нулевые). ioq3 `vmCvar_t` держит `string[256]` на +0 (`.value` на +260); `cvar` показывает обе раскладки.

## Кейс: `amf_debug` (был leftover, чтение есть)

| | |
|--|--|
| строка таблицы | 58 |
| флаги | 3 (`ARCHIVE\|USERINFO`) |
| дефолт | `"0"` |
| `vmCvar` | `54708` (`0xd5b4`) |
| чтение | `qvm_mem+54716` (`+8`) |
| identity | `fn_16459` / `L16459` (строка чтения `L16460`) |

`fn_16459(origin, weapon, lifetime_ms)`:

- gate: `*(int*)(qvm_mem+54716) != 0`, иначе return 0
- `G_Spawn`, `classname` `"Mark"` (`qvm_mem+18249`)
- `s.eType = 3` (`ET_MISSILE`), `s.weapon =` аргумент (`8` plasma / `5` rocket)
- `r.svFlags = 128` (`SVF_USE_CURRENT_ORIGIN`, не `SVF_BROADCAST`), damage/splash 0
- `s.pos.trType = 0` (`TR_STATIONARY`), origin = arg0, Z += 1
- `nextthink = level.time + lifetime`, `think = G_FreeEntity`

Вызывающие передают цель прыжка бота (QVM `bs+9368`; порт: клиентская таблица) или origin вейпоинта. cgame рисует плазменный болт, поэтому это выглядит как "plasminki in the air", к которым бот идёт.

Identity `fn_16459` **не** зовёт `trap_LinkEntity`. Оригинал 0.52 всё равно показывает сферы в игре. Порт линкует их, чтобы ioq3-снапшоты их включали.

Порт вешает Marks на: сэмплы вейпоинтов (plasma 5000); посадку DelayedJump в `fn_34692` (plasma 500); продолжение прыжка в `fn_91157` (plasma 500); коммит RJ (rocket 4000). Полный mover `fn_34855` не портирован.

Ungated-клон `fn_16612` **не имеет вызывающих**.

`g_debugprint` (`vm+8` = `54444`) — **другой** cvar: текстовые дампы `G_LogPrintf_2`, а не Marks.

## Потерянные cvar: повторная проверка (identity + table-pointer + opcode taint)

У них есть **строка в таблице** и BSS-ячейка `vmCvar`. После identity `[vm, vm+271]`, LOAD по указателю на таблицу и QVM taint **вне диапазонов инструкций Register/Update** (2026-08-20): **по-прежнему ноль геймплейных чтений**. Точная строка `cvar`:

`no CONST, no table-pointer LOAD, no [vm,vm+271] hit outside Register/Update ranges`

`amf_debug` по-прежнему попадает на `+8` в `qvm_mem+54716` (`fn_16459` / `L16460`) — новый chase не отрегрессировал.

`trap_Cvar_Variable*` эти имена никогда не принимает. Они остаются **потерянными**. Ре-аудит — через `cvar`, не `xref`.

cgame.qvm / ui.qvm: **нет C-строки** ни для одной из этих девяти — сообщите так и остановитесь.

| имя | row | `vmCvar` | флаги |
|------|-----|----------|-------|
| `g_buildWPs` | 0 | 47092 | LATCH (32) |
| `g_waypoints` | 65 | 52804 | ROM (64) |
| `bot_speedup` | 72 | 50628 | ROM |
| `bot_hideLGPG` | 70 | 51444 | ROM |
| `bot_enemyacc` | 71 | 51172 | ARCHIVE\|LATCH |
| `bot_newrj` | 83 | 48996 | 0 |
| `bot_maxjump` | 81 | 55252 | 0 |
| `bot_maxdown` | 82 | 54980 | 0 |
| `bot_tfl` | 87 | 47908 | 0 |

Пока на тех 272 байтах нет LOAD (этот статический чек или runtime watchpoint), **не вешайте на них поведение**. Текст changelog про `bot_speedup` / hide LG / new RJ — намерение, а не разводка 0.52.

Только в readme, **строки нет в data+lit qagame/cgame/ui**: `g_rj_new`, `g_lightningDamage`. Всё ещё потеряны.

Потерянные ROM-ручки (`bot_hideLGPG`, `g_waypoints`, `bot_speedup`) заморожены на дефолтах через `G_UpdateCvars` (`flags&64`). Hide-LG/PG в байткоде безусловен (совпадает с ROM-дефолтом 1), это не чтение `bot_hideLGPG`.

В `dump.py` нет (one-off / vmdbg): runtime LOAD watchpoints, происхождение аргументов `trap_BotLibVarSet`, FS `*.wps`. Не обобщайте float-иммедиаты (0.9 / 1.03 / 1.04).

## Также нулевые абсолютные `+8` в qagame (не помечены lost)

Строки таблицы без `qvm_mem + (vm+8)` в коде qagame. Часть из них — engine/UI/`trap_Cvar_Variable*` на **клиенте** либо ROM-баннеры: `gamename`, `gamedate`, `about`, `g_motd`, `g_log`, `g_banIPs`, `ogc_*`, `g_rankings`, `g_drawBBox`, … Не помечайте их lost, не проверив cgame/ui тем же способом. `g_drawBBox` — клиентский оверлей unlagged.

## Чем это не является

- Имена полей из `struct.c` оверлея (они лгут; побеждает identity `L<insn>`).
- Выдумывание имён BSS для `gentity` / `bot_state`.
- `dump.py slot` (это **смещение поля** gclient/gentity, а не cvar).
