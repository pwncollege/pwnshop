#!/usr/bin/env python3

import sys
import os
import argparse
import contextlib
import traceback
import multiprocessing as mp

import pwn
import pwnshop

def dothing(args):
    level, version, instance, module, num, give_source, verify = args
    seed = "_".join([module, level, str(version), str(instance)])

    walkthrough = version == 0
    Challenge = pwnshop.ALL_CHALLENGES[f"{module}Level{level}"]
    challenge = Challenge(seed=seed, walkthrough=walkthrough)

    print(f"Generating: {seed=} {walkthrough=}", flush=True)

    pname = f"level-{level}"
    name = f"level{level}"
    if num > 1:
        name += f".{version}"
        pname += f"-{version}"
    path = f"./challenges/{module}/{pname}/_{instance}"

    os.makedirs(path, exist_ok=True)

    source = challenge.generate_source()

    if give_source:
        with open(f"{path}/{module}_{name}.c", "w") as f:
            f.write(source)

    binary, libs = challenge.build_binary(source=source)

    binary_path = f"{path}/{module.lower()}_{name}"
    if isinstance(challenge, pwnshop.KernelChallenge):
        binary_path = f"{binary_path}.ko"

    with open(binary_path, "wb") as f:
        f.write(binary)
    os.chmod(binary_path, 0o755)

    if verify:
        challenge.verify(binary=binary)


def main():
    parser = argparse.ArgumentParser(description="pwnshop challenge emitter")
    parser.add_argument(
        "-m",
        "--module",
        required=True,
    )
    parser.add_argument(
        "-l",
        "--levels",
        default=None,
    )
    parser.add_argument(
        "-n",
        "--num",
        type=int,
        default=1,
    )
    parser.add_argument(
        "-i",
        "--instances",
        type=int,
        default=256,
    )
    parser.add_argument(
        "-s",
        "--source",
        action="store_true",
    )
    parser.add_argument(
        "-v",
        "--verify",
        action="store_true",
    )
    parser.add_argument(
        "-vvv",
        "--verbose",
        action="store_true",
    )

    args = parser.parse_args()

    module = args.module.lower()

    if args.levels:
        levels = args.levels.split(",")
    else:
        prefix = f"{args.module}Level"
        levels = [level[len(prefix):] for level in pwnshop.ALL_CHALLENGES if level.startswith(prefix)]

    if args.verbose:
        pwn.context.log_level = "DEBUG"

    jobs = []
    for level in levels:
        for version in range(args.num):
            for i in range(args.instances):
                jobs.append((level, version, i, args.module, args.num, args.source, args.verify))


    with mp.Pool(1) as pool:
        pool.map(dothing, jobs)

if __name__ == "__main__":
    main()
