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

pwnshop verify-module example_module > /tmp/out
grep "ATTEMPTED: 3" /tmp/out
grep "FAILED: 1" /tmp/out
grep "SUCCEEDED: 2" /tmp/out

pwnshop verify-all > /tmp/out
grep "ATTEMPTED: 3" /tmp/out
grep "FAILED: 1" /tmp/out
grep "SUCCEEDED: 2" /tmp/out

cd /
pwnshop -C $EXM render ShellExample
