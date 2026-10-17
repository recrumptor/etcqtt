#!/usr/bin/env python3
"""Патч ядра для целей без 64-битных атомиков (mips32: mipsel_24kc и т.п.).

На mips32 в std нет AtomicU64/AtomicI64. Скрипт заменяет их импорты на `portable_atomic`
(тот же API; без нативной поддержки используется реализация на блокировке).
Запускать из каталога rust-client; после него нужно добавить зависимость:
    cargo add portable-atomic@1
Скрипт идемпотентен: повторный запуск ничего не меняет.
"""
import pathlib
import re
import sys

NAMES = ("AtomicU64", "AtomicI64")
QUALIFIED = re.compile(r"\b(?:std|core)::sync::atomic::(AtomicU64|AtomicI64)\b")
GROUP = re.compile(r"(\batomic::)\{([^{}]*)\}")
IDENT = {n: re.compile(r"\b%s\b" % n) for n in NAMES}


def process(path: pathlib.Path) -> bool:
    src = path.read_text(encoding="utf-8")
    if not any(n in src for n in NAMES):
        return False
    need_import = set()

    def fix_group(m):
        items = [x.strip() for x in m.group(2).split(",") if x.strip()]
        keep = [x for x in items if x not in NAMES]
        if len(keep) == len(items):
            return m.group(0)
        need_import.update(x for x in items if x in NAMES)
        return "%s{%s}" % (m.group(1), ", ".join(keep))

    out = QUALIFIED.sub(lambda m: "portable_atomic::" + m.group(1), src)
    out = GROUP.sub(fix_group, out)
    if need_import:
        out = out.rstrip("\n") + "\n\n// csqtt-openwrt: 64-bit atomics for mips32\nuse portable_atomic::{%s};\n" % ", ".join(sorted(need_import))
    if out == src:
        return False
    path.write_text(out, encoding="utf-8")
    return True


def main() -> int:
    root = pathlib.Path(".")
    changed = []
    for f in sorted(root.rglob("*.rs")):
        if {"vendor", "target"} & set(f.parts):
            continue
        if process(f):
            changed.append(str(f))
    # проверка: не осталось импортов 64-битных атомиков из std
    left = []
    for f in root.rglob("*.rs"):
        if {"vendor", "target"} & set(f.parts):
            continue
        t = f.read_text(encoding="utf-8")
        for m in GROUP.finditer(t):
            if any(x.strip() in NAMES for x in m.group(2).split(",")):
                left.append(str(f))
    print("изменены файлы (%d): %s" % (len(changed), ", ".join(changed) or "—"))
    if left:
        print("ОШИБКА: остались импорты std 64-битных атомиков: " + ", ".join(sorted(set(left))))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
