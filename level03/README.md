# Level 03 — reversing a XOR decryption check

## Overview
No memory corruption here — this is a pure reversing puzzle. The program reads
an integer, derives a key from it, XOR-decrypts an embedded string, and spawns
a shell if the result equals `"Congratulations!"`. We recover the key by
analysis and feed the matching input.

## Analysis
```sh
strings level03      # "Congratulations!", "/bin/sh"
```
Decompiled flow:
```c
if ( strcmp((const char *)v4, "Congratulations!") == 0 )
    return system("/bin/sh");

__isoc99_scanf("%d", &savedregs);
test(savedregs, 322424845);
```
- `test()` computes `322424845 - <your number>` and checks the result falls in
  a valid range, then calls `decrypt()` with it.
- `decrypt()` uses that value as a **XOR key** over the encrypted buffer
  `"Q}|u`sfg~sf{}|a3"`.
- If decryption yields `"Congratulations!"`, we win.

## Recovering the key
Brute the small key space against the known plaintext:
```sh
python -c '
enc = "Q}|u`sfg~sf{}|a3"
for k in range(16, 20):
    print k, "".join(chr(ord(c) ^ k) for c in enc)
'
```
Key **18** produces `Congratulations!`.

## Computing the input
`test()` needs `322424845 - input == 18`, so:
```
input = 322424845 - 18 = 322424827
```

## Exploitation
```sh
(echo "322424827"; cat) | ./level03
cat /home/users/level04/.pass
```

## Flag
```
kgv3tkEb9h2mLkRsPkXRfc2mHbjMxQzvb2FrgKkf
```
