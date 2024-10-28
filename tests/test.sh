#!/bin/bash -xe

cd "$(dirname "${BASH_SOURCE[0]}")"/..

echo "pwncollege{TESTING}" | sudo tee /flag
cd example_module
pwnshop list | grep ShellExample
pwnshop render ShellExample
pwnshop build ShellExample > /tmp/shell_example
file /tmp/shell_example | grep ELF
pwnshop verify ShellExample
pwnshop verify-module example_module
cd ../../
pwnshop -C pwnshop/example_module render ShellExample
