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
cat /tmp/out | grep "SUCCEEDED: PythonPass"

cd /
pwnshop -C $EXM render ShellExample

echo SUCCESS
