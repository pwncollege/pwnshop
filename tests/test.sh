#!/bin/bash -xe

cd "$(dirname "${BASH_SOURCE[0]}")"/..

echo "pwncollege{TESTING}" | sudo tee /flag
cd example_module
EXM=$PWD
pwnshop list | grep ShellExample
pwnshop render ShellExample
pwnshop build ShellExample > /tmp/shell_example
file /tmp/shell_example | grep ELF
strings <(pwnshop build ShellOptimized) | grep -- "-O3"
pwnshop verify ShellExample

( pwnshop verify -m example_module || true ) | tee /tmp/out
cat /tmp/out | grep "SUCCEEDED: ShellExample"
cat /tmp/out | grep "SUCCEEDED: ShellOptimized"
cat /tmp/out | grep "FAILED: ShellBadVerifier"
cat /tmp/out | grep "SUCCEEDED: Shell1604"

( pwnshop verify || true ) | tee /tmp/out
cat /tmp/out | grep "SUCCEEDED: ShellExample"
cat /tmp/out | grep "SUCCEEDED: ShellOptimized"
cat /tmp/out | grep "FAILED: ShellBadVerifier"
cat /tmp/out | grep "SUCCEEDED: Shell1604"

pwnshop apply ../example_deploy/pwnshop.yml
SOURCES=( ../example_deploy/*/*/*.c )
BINS=( ../example_deploy/*/*/shell )
FILES=( ../example_deploy/*/*/* )
[ "${#SOURCES[@]}" -eq 1 ] || exit 1
[ "${#BINS[@]}" -eq 5 ] || exit 1
[ "${#FILES[@]}" -eq 6 ] || exit 1

cd /
pwnshop -C $EXM render ShellExample
