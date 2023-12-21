import functools
import argparse
import pwnshop
import inspect
import random
import glob
import sys
import pwn #pylint:disable=import-error
import os

def challenge_class(challenge):
    if ":" not in challenge:
        assert challenge in pwnshop.ALL_CHALLENGES, "Unknown challenge specified!"
        return pwnshop.ALL_CHALLENGES[challenge]
    else:
        module, level_src = challenge.split(":")
        level = int(level_src)

        assert module in pwnshop.MODULE_LEVELS, "Uknown module specified!"
        assert 0 < level <= len(pwnshop.MODULE_LEVELS[module]), "Invalid level specified."
        return pwnshop.MODULE_LEVELS[module][level-1]

def with_challenge(f):
    @functools.wraps(f)
    def f_with_challenge(args):
        challenge = challenge_class(challenge=args.challenge)(seed=args.seed, walkthrough=args.walkthrough)
        return f(args, challenge)
    return f_with_challenge

@with_challenge
def handle_render(args, challenge):
    src = challenge.generate_source()
    if not args.lineno:
        args.out.write(src+"\n")
    else:
        for i, line in enumerate(src.splitlines()):
            args.out.write(f"{i + 1}\t{line}\n")
    if os.path.isfile(args.out.name):
        os.chmod(args.out.name, 0o644)

@with_challenge
def handle_build(args, challenge):
    binary, libs = challenge.build_binary()
    args.out.buffer.write(binary)
    if os.path.isfile(args.out.name):
        os.chmod(args.out.name, 0o755)

    if args.lpath and libs:
        os.makedirs(args.lpath, exist_ok=True)
        for lib_name, lib_bytes in libs:
            lib_path = args.lpath + f'/{lib_name}'
            with open(lib_path, 'wb+') as f:
                f.write(lib_bytes)
            os.chmod(lib_path, 0o755)

def verify_challenge(challenge, debug=False, flag=None, strace=False):
    if debug:
        pwn.context.log_level = "DEBUG"

    if flag:
        with open("/flag", "wb") as f:
            f.write(flag.encode())

    if "strace" in inspect.getfullargspec(challenge.verify)[0]:
        challenge.verify(strace=strace)
    else:
        challenge.verify()

@with_challenge
def handle_verify(args, challenge):
    return verify_challenge(challenge, debug=args.debug, flag=args.flag, strace=args.strace)

def handle_verify_module(args):
    for n,c in enumerate(c(seed=args.seed, walthrough=args.walkthrough) for c in pwnshop.MODULE_LEVELS[args.module]):
        print(f"Verifying {args.module} level {n+1}.")
        verify_challenge(c, debug=args.debug, flag=args.flag, strace=args.strace)

def main():
    parser = argparse.ArgumentParser(description="pwnshop challenge emitter", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-I",
        "--import",
        required=False,
        help="a path glob to import additional challenges from (either /path/to/module.py or /path/to/package/ or /some/glob/*, but avoid shell-expansion for the latter!)",
    )
    commands = parser.add_subparsers(help="the action for pwnshop to perform", required=True, dest="ACTION")
    command_render = commands.add_parser("render", help="render the source code of a challenge")
    command_build = commands.add_parser("build", help="build the binary code of a challenge")
    command_verify = commands.add_parser("verify", help="verify the functionality of a challenge")
    command_verify_module = commands.add_parser("verify-module", help="verify the functionality of all challenges in a module")

    command_render.add_argument(
        "-l",
        "--lineno",
        action="store_true",
        help="render line numbers",
    )

    command_build.add_argument(
        "--lpath",
        help="Location to store needed library files",
    )

    for c in [ command_verify, command_verify_module ]:
        c.add_argument(
            "-t",
            "--strace",
            action="store_true",
            help="print out strace information during verification",
        )

        c.add_argument(
            "-f",
            "--flag",
            help="change the flag to be verified against",
        )


    # where to write
    for c in [ command_render, command_build ]:
        c.add_argument(
            "-O",
            "--out",
            type=argparse.FileType('w'),
            default='-',
            help="change the output destination"
        )

    # common arguments
    for subparser in commands.choices.values():
        subparser.add_argument(
            "-s",
            "--seed",
            required=False,
            default=random.randrange(0, 999999),
            help="the seed from which to generate the challenge (default: random)",
        )

        subparser.add_argument(
            "-d",
            "--debug",
            action="store_true",
            help="print out debugging information",
        )

        subparser.add_argument(
            "-w",
            "--walkthrough",
            action="store_true",
            help="enable challenge walkthrough mode",
        )

    # common to all single-challenge commands
    for subparser in [ command_render, command_build, command_verify ]:
        subparser.add_argument("challenge", help="the challenge, as ChallengeClassName or ModuleName:level_number")

    command_verify_module.add_argument("module", help="the module to verify")

    parser.epilog = f"""Commands usage:\n\t{command_render.format_usage()}\t{command_build.format_usage()}\t{command_verify.format_usage()}"""

    args = parser.parse_args()
    pwn.context.log_level = "ERROR"

    if getattr(args, "import", None):
        imports = glob.glob(getattr(args, "import"))
        for i in imports:
            sys.path.append(os.path.realpath(os.path.dirname(i)))
            try:
                module_name = os.path.basename(i).split(".py")[0]
                __import__(module_name)
            finally:
                sys.path.pop()

    globals()["handle_" + args.ACTION.replace('-', '_')](args)

if __name__ == "__main__":
    main()
