#!/bin/bash -xe

cd "$(dirname "${BASH_SOURCE[0]}")"/..

rm -rf example_deploy/*/*/*
pwnshop -C example_module apply example_deploy/pwnshop.yml
SOURCES=( example_deploy/{*,*/*}/*.c )
BINS=( example_deploy/{*,*/*}/shell )
LIBS=( example_deploy/{*,*/*}/lib/* )
[ "${#SOURCES[@]}" -eq 1 ] || exit 1
[ "${#BINS[@]}" -eq 6 ] || exit 1
[ "${#FILES[@]}" -eq 14 ] || exit 1
[ "${#LIBS[@]}" -eq 3 ] || exit 1

rm -rf example_deploy/*/*/*
pwnshop -C example_module apply example_deploy/pwnshop.yml --mp --quiet
SOURCES=( example_deploy/{*,*/*}/*.c )
BINS=( example_deploy/{*,*/*}/shell )
LIBS=( example_deploy/{*,*/*}/lib/* )
[ "${#SOURCES[@]}" -eq 1 ] || exit 1
[ "${#BINS[@]}" -eq 6 ] || exit 1
[ "${#LIBS[@]}" -eq 3 ] || exit 1

echo SUCCESS
