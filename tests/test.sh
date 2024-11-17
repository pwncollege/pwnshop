#!/bin/bash -xe

cd "$(dirname "${BASH_SOURCE[0]}")"/..

cd example_module
EXM=$PWD
pwnshop list | grep ShellExample
pwnshop render ShellExample
pwnshop build ShellExample > /tmp/shell_example
file /tmp/shell_example | grep ELF
strings <(pwnshop build ShellOptimized) | grep -- "-O3"
pwnshop verify ShellExample

( pwnshop verify || true ) | tee /tmp/out
cat /tmp/out | grep "SUCCEEDED: ShellExample"
cat /tmp/out | grep "SUCCEEDED: ShellOptimized"
cat /tmp/out | grep "FAILED: ShellBadVerifier"
cat /tmp/out | grep "SUCCEEDED: Shell1604"
cat /tmp/out | grep "SUCCEEDED: Shell1604InVitu"

pwnshop apply ../example_deploy/pwnshop.yml
SOURCES=( ../example_deploy/*/*/*.c )
BINS=( ../example_deploy/*/*/shell )
FILES=( ../example_deploy/*/*/* )
LIBS=( ../example_deploy/*/*/lib/* )
[ "${#SOURCES[@]}" -eq 1 ] || exit 1
[ "${#BINS[@]}" -eq 6 ] || exit 1
[ "${#FILES[@]}" -eq 8 ] || exit 1
[ "${#LIBS[@]}" -eq 3 ] || exit 1

rm -rf ../example_deploy/*/*/*
pwnshop apply ../example_deploy/pwnshop.yml --mp --quiet
SOURCES=( ../example_deploy/*/*/*.c )
BINS=( ../example_deploy/*/*/shell )
FILES=( ../example_deploy/*/*/* )
LIBS=( ../example_deploy/*/*/lib/* )
[ "${#SOURCES[@]}" -eq 1 ] || exit 1
[ "${#BINS[@]}" -eq 6 ] || exit 1
[ "${#FILES[@]}" -eq 8 ] || exit 1
[ "${#LIBS[@]}" -eq 3 ] || exit 1

cd /
pwnshop -C $EXM render ShellExample

echo SUCCESS
