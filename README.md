# pwnshop

Pwnshop is a templated challenge generation engine, built on jinja, to generate source code for challenges, compile it, verify it, and all that fun stuff.
We use pwnshop to generate most of pwn.college's challenges!

This repository has the core of pwnshop, along with one example challenge.

## Challenge Generation

Let's generate some things!


```sh
# `babyshell_level1` in testing mode
python -m pwnshop --challenge BabyShellBasicShellcode --src

# `babyshell_level1` in teaching mode
python -m pwnshop --challenge BabyShellBasicShellcode --walkthrough --src

# make sure `babyshell_level1` compiles and the reference solution works
python -m pwnshop --challenge BabyShellBasicShellcode --walkthrough --verify

# generate the `babyshell_level1` binary
python -m pwnshop --challenge BabyShellBasicShellcode --walkthrough --bin > babyshell_level1

```
