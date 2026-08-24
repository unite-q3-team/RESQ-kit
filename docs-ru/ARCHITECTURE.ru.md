# Архитектура

> Перевод [../ARCHITECTURE.md](../docs/ARCHITECTURE.md); при расхождениях приоритет у английского оригинала.

```
┌─────────────────┐     probe_emit      ┌──────────────────┐
│  stale .qvm     │ ──────────────────► │  module.c        │
│  (code+data+bss)│   (+names,+sigs)    │  syscalls.asm    │
└─────────────────┘                     └────────┬─────────┘
                                                 │ q3lcc -DQ3_VM -S
                                                 ▼
                                        ┌──────────────────┐
                                        │  module.asm      │
                                        └────────┬─────────┘
                                                 │ q3asm -vq3
                                                 ▼
                                        ┌──────────────────┐
                                        │  module.qvm      │
                                        │  → zzzz-*-fixed  │
                                        └──────────────────┘
```

## Крейт `toolchain/qvm`

| часть | назначение |
|-------|-----|
| `loader` / `opcodes` / `disasm` / `cfg` | разбор QVM, восстановление функций |
| `decompile` + `structure` | стек → SSA → C |
| `probe_emit` | C, готовый к q3lcc, + blob `qvm_mem_words` |
| `emu` + `probe_common` | интерпретация VM, моделирование trap |
| `probe_uidiff` / `probe_seqdiff` / `probe_cgamediff` | сравнение trap-логов orig против rebuilt |
| `probe_disasm` / `findconst` / `findfn` | точечные проверки |

## Адреса данных

`qvm_mem_words` линкуется по data-смещению **4** (нулевая страница на 0).

Emit пишет ссылки на строки как `qvm_mem + (orig_addr - 4)`, чтобы слинкованный адрес совпадал с исходным абсолютным смещением.

«Голые» записи вида `*(int*)(260028) = …` сохраняют исходное число. Blob должен покрывать этот диапазон.

## Коллизии CONST

«Голый» `CONST n` может оказаться смещением строки или точкой входа функции. Emit выбирает:

- данные → `qvm_mem + …`
- функция → `(int)fn_N` (релоцирует q3asm)

Эвристики, важные на реальных модах:

- address-taken / глобальные записи fnptr
- записи полей-колбэков (`ent->think` и родня)
- отложенные `param_forward` × `bare_call_cells` (действия диалогов подтверждения)

Ошибка выбора → битый CALL → краш меню, зависание, `unknown type 0`.

## Движок

Живые прогоны шли на Quake3e. Держитесь близко к upstream. Патчите в emit compat баги входного VM, проявляющиеся на современном GL (Driver Info), и retry `FL_NO_BOTS` в ClientSpawn. Клиентский `glconfig` лучше не трогать.
