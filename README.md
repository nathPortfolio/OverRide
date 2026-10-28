# Override

> Binary exploitation wargame.
> A [42](https://42.fr) security project focused on exploiting ELF binaries on an i386 system.

---

## 📖 About

**Override** is a hands-on introduction to binary exploitation. The project ships as a
bootable ISO containing a chain of increasingly difficult levels. Each level runs under a
dedicated user (`level00` → `level09`) and guards a `.pass` file readable only by the
*next* user.

The goal of each challenge is to exploit a vulnerability in a provided binary — using the
privileges of the current level — in order to read the next level's `.pass`, then log in
as that user and repeat. The chain ends at the `end` user.

The exercises cover classic memory-corruption and logic flaws: buffer overflows, format
string bugs, stack/return-address control, shellcode injection, and reverse engineering of
ELF executables.

> ⚠️ **Educational use only.** These binaries are intentionally vulnerable and live on an
> isolated training VM. The techniques here are for learning memory safety and secure
> coding — not for use against systems you don't own.

---

## 🧭 How it works

1. Boot the project ISO in a 64-bit virtual machine.
2. Connect over SSH (port `4242`), starting with `level00:level00`:
   ```sh
   ssh level00@<VM_IP> -p 4242
   ```
3. Exploit the current level's binary to read `/home/level0X/.pass`.
4. `su` to the next user with the recovered password.
5. Repeat until the `end` user.

> Becoming `root` is **not** part of the project and is considered cheating. Likewise,
> brute-forcing the SSH passwords is forbidden and pointless — every solution must be
> justified by its actual exploit.

---

## 📂 Repository structure

Each level has its own directory. **No binaries are committed** — only the material needed
to explain and reproduce the exploit.

```
.
├── level00/
│   ├── flag          # recovered .pass (or empty, with a justification)
│   ├── source        # readable reconstruction of the exploited binary
│   └── Ressources/   # anything needed to prove the solve (scripts, notes, ...)
├── level01/
│   └── ...
├── ...
└── level09/          # bonus
```

- **`flag`** — the password recovered for the next level. May be empty if a justification
  is provided instead.
- **`source`** — a developer-readable form of the exploited binary (language not imposed).
- **`Ressources/`** — exploit scripts, payloads, disassembly notes, and anything else used
  to demonstrate the solve. Everything in here must be fully explainable.

---

## 🗂️ Levels

| Level   | Status      | Vulnerability / Technique *(to confirm)* |
|---------|-------------|------------------------------------------|
| level00 | ✅ Mandatory | _reverse engineering / hardcoded check_  |
| level01 | ✅ Mandatory | _…_                                      |
| level02 | ✅ Mandatory | _…_                                      |
| level03 | ✅ Mandatory | _…_                                      |
| level04 | ✅ Mandatory | _…_                                      |
| level05 | ✅ Mandatory | _…_                                      |
| level06 | ✅ Mandatory | _…_                                      |
| level07 | ✅ Mandatory | _…_                                      |
| level08 | ✅ Mandatory | _…_                                      |
| level09 | ⭐ Bonus     | _…_                                      |

> Fill in the technique column with a one-line summary per level (e.g. "stack buffer
> overflow + ret overwrite", "format string → GOT overwrite", "env-var shellcode").
> The bonus is only evaluated if the mandatory part is complete and flawless.

---

## 🛠️ Typical toolkit

- `gdb` (often with `peda`/`gef`) — debugging and runtime inspection
- `objdump` / `readelf` — static analysis of the ELF binaries
- `ltrace` / `strace` — library and syscall tracing
- `python` — payload crafting
- `/proc` inspection — locating stack/addresses at runtime

---

## 📜 Notes

- All solutions must be reproducible and defensible during evaluation.
- Any ISO-specific file must be downloaded at defense time, never committed to the repo.
- External tooling should come with its own reproducible environment (VM, Docker, Vagrant).

---
