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

def with_challenges(f):
    @functools.wraps(f)
    def f_with_challenge(args):
        challenges = [
            challenge_class(challenge=c)(seed=args.seed, walkthrough=args.walkthrough)
            for c in args.challenges
        ]
        return f(args, challenges)
    return f_with_challenge

@with_challenges
def handle_render(args, challenges):
    for challenge in challenges:
        src = challenge.generate_source()
        if not args.lineno:
            args.out.write(src+"\n")
        else:
            for i, line in enumerate(src.splitlines()):
                args.out.write(f"{i + 1}\t{line}\n")
        if os.path.isfile(args.out.name):
            os.chmod(args.out.name, 0o644)

def handle_list(args): #pylint:disable=unused-argument
    for module,challenges in pwnshop.MODULE_LEVELS.items():
        for n,challenge in enumerate(challenges, start=1):
            print(f"{module}:{n} --- {challenge.__name__}")

@with_challenges
def handle_build(args, challenges):
    for challenge in challenges:
        binary, libs, pdb = challenge.build_binary()
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
        if pdb:
            with open(f"{args.out.name.replace('.exe', '.pdb')}", 'wb') as f:
                f.write(pdb)

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

@with_challenges
def handle_verify(args, challenges):
    for challenge in challenges:
        print(f"Verifying {type(challenge).__name__}.")
        verify_challenge(challenge, debug=args.debug, flag=args.flag, strace=args.strace)

def handle_verify_module(args):
    for n,c in enumerate(c(seed=args.seed, walkthrough=args.walkthrough) for c in pwnshop.MODULE_LEVELS[args.module]):
        print(f"Verifying {args.module} level {n+1}: {type(c).__name__}.")
        verify_challenge(c, debug=args.debug, flag=args.flag, strace=args.strace)

def main():
    parser = argparse.ArgumentParser(description="pwnshop challenge emitter", formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "-C",
        "--challenge-location",
        required=False,
        help="a path glob to import challenges from (either /path/to/module.py or /path/to/package/ or /some/glob/*, but avoid shell-expansion for the latter!). Defaults to cwd.",
        default=os.getcwd()
    )
    commands = parser.add_subparsers(help="the action for pwnshop to perform", required=True, dest="ACTION")
    command_render = commands.add_parser("list", help="list known challenges")
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
        subparser.add_argument("challenges", help="the challenges, as multiple ChallengeClassName or ModuleName:level_number", nargs="+")

    command_verify_module.add_argument("module", help="the module to verify")

    parser.epilog = f"""Commands usage:\n\t{command_render.format_usage()}\t{command_build.format_usage()}\t{command_verify.format_usage()}"""

    args = parser.parse_args()
    pwn.context.log_level = "ERROR"

    import_dir = args.challenge_location
    if not os.path.isdir(import_dir):
        print(f"Error, {import_dir=} does not exist")
        return -1
    imports = glob.glob(import_dir)
    for i in imports:
        i = i.rstrip("/")
        sys.path.append(os.path.realpath(os.path.dirname(i)))
        try:
            module_name = os.path.basename(i).split(".py")[0]
            __import__(module_name)
        finally:
            sys.path.pop()

    globals()["handle_" + args.ACTION.replace('-', '_')](args)

if __name__ == "__main__":
    main()
