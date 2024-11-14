import traceback
import functools
import argparse
import logging
import pwnshop
import pwnlib.context
import pwnlib.log
import signal
import random
import shutil
import yaml
import glob
import sys
import os

pwnlib.log.install_default_handler()

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
        challenges = [ ]
        for m in (args.module or [ ]) if "module" in args else [ ]:
            challenges += [
                c(seed=args.seed, walkthrough=args.walkthrough)
                for c in pwnshop.MODULE_LEVELS[m]
            ]

        if args.challenges:
            challenges += [
                challenge_class(challenge=c)(seed=args.seed, walkthrough=args.walkthrough)
                for c in args.challenges
            ]

        if not challenges:
            challenges += [
                c(seed=args.seed, walkthrough=args.walkthrough)
                for c in pwnshop.ALL_CHALLENGES.values()
            ]

        if getattr(args, "build_image", None):
            for c in challenges:
                c.BUILD_IMAGE = args.build_image

        if getattr(args, "verify_image", None):
            for c in challenges:
                c.VERIFY_IMAGE = args.verify_image

        return f(args, challenges)
    return f_with_challenge

@with_challenges
def handle_render(args, challenges):
    for challenge in challenges:
        src = challenge.render()
        if not args.line_numbers:
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
        binary, libs, pdb = challenge.build()
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

def raise_timeout(signum, stack):
    raise TimeoutError("ACTION TIMED OUT")

def verify_challenge(challenge, debug=False, flag=None, strace=False):
    if debug:
        pwnlib.context.context.log_level = "DEBUG"

    if flag:
        with open("/flag", "wb") as f:
            f.write(flag.encode())

    try:
        os.chdir(challenge.work_dir)
        return challenge.verify(strace=strace)
    except TypeError as e:
        if "strace" not in str(e):
            raise
    return challenge.verify()

def verify_many(args, challenges):
    failures = [ ]
    for challenge in challenges:
        name = challenge.__name__ if type(challenge) is type else type(challenge).__name__

        print(f"VERIFYING: {name}")

        try:
            if type(challenge) is type:
                challenge = challenge(seed=args.seed, walkthrough=args.walkthrough)

            if args.timeout:
                signal.signal(signal.SIGALRM, raise_timeout)
                signal.alarm(args.timeout)

            verify_challenge(challenge, debug=args.debug, flag=args.flag, strace=args.strace)
            signal.alarm(0)
            print(f"SUCCEEDED: {name}")
        except NotImplementedError:
            failures.append(challenge)
            print(f"MISSING: {name}")
        except Exception: #pylint:disable=broad-exception-caught
            print(traceback.format_exc())
            failures.append(challenge)
            print(f"FAILED: {name}")

    return not failures

@with_challenges
def handle_verify(args, challenges):
    return verify_many(args, challenges)

def handle_apply(args):
    if args.debug:
        pwnlib.context.context.log_level = "DEBUG"

    yaml_dir = os.path.abspath(os.path.dirname(args.yaml))
    y = yaml.safe_load(open(args.yaml))
    name_prefix = y.get("binary_name_prefix", None)

    for c in y['challenges']:
        seed = c.get('seed', y.get('seed', args.seed))
        variants = args.variants or c.get('variants', y.get('variants', 1))
        walkthrough = c.get('walkthrough', y.get('walkthrough', args.walkthrough))
        keep_source = c.get('keep_source', y.get('keep_source', False))
        binary_name = c.get('binary_name', y.get('binary_name', name_prefix + "-" + c['id'] if name_prefix else c['id']))
        build_image = c.get('build_image', y.get('build_image', None))
        verify_image = c.get('verify_image', y.get('verify_image', None))

        if args.challenges and c['id'] not in args.challenges and not any(cc.startswith(c['id']+":") for cc in args.challenges):
            continue

        for v in range(variants):
            if args.challenges and c['id'] not in args.challenges and f"{c['id']}:{v}" not in args.challenges:
                continue

            print(f"Applying {c['id']} variant {v}.")

            challenge = pwnshop.ALL_CHALLENGES[c['challenge']](
                walkthrough=walkthrough,
                seed=seed + v,
                basename=binary_name,
            )

            out_dir = f"{yaml_dir}/{c['id']}/_{v}"
            if os.path.exists(out_dir):
                shutil.copytree(out_dir, challenge.work_dir, dirs_exist_ok=True)
            else:
                os.makedirs(out_dir)

            os.chdir(challenge.work_dir)

            if build_image:
                challenge.BUILD_IMAGE = build_image
            if verify_image:
                challenge.VERIFY_IMAGE = verify_image

            if args.no_render and not args.no_build:
                print("... using existing source")
                challenge.source = open(challenge.src_path).read()
            else:
                print("... rendering")
                challenge.render()

            if args.no_build:
                print("... using existing binary")
                challenge.binary = open(challenge.bin_path, "rb").read()
            else:
                print("... building")
                challenge.build()

            if not args.no_verify:
                print("... verifying")
                challenge.flaky_verify()
                print("... verification passed")

            print(f"... copying files to {out_dir}")
            if keep_source:
                shutil.copy2(challenge.src_path, os.path.join(out_dir, os.path.basename(challenge.src_path)))
            shutil.copy2(challenge.bin_path, os.path.join(out_dir, os.path.basename(challenge.bin_path)))
            if os.path.exists(challenge.lib_path):
                shutil.copytree(challenge.lib_path, os.path.join(out_dir, os.path.basename(challenge.lib_path)), dirs_exist_ok=True)

            #if pdb:
            #   with open(f"{args.out.name.replace('.exe', '.pdb')}", 'wb') as f:
            #       f.write(pdb)

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
    command_apply = commands.add_parser("apply", help="parse a yaml and generate the defined challenges")

    command_render.add_argument(
        "--line-numbers",
        action="store_true",
        help="render line numbers",
    )

    command_build.add_argument(
        "--lpath",
        help="Location to store needed library files",
    )

    command_build.add_argument(
        "--build-image",
        help="Docker image to use for building",
    )

    command_apply.add_argument(
        "--no-verify",
        action="store_true",
        help="Do not verify the built binaries.",
    )
    command_apply.add_argument(
        "--no-build",
        action="store_true",
        help="Do not build the binaries (only verify).",
    )
    command_apply.add_argument(
        "--no-render",
        action="store_true",
        help="Do not re-render the code (will be ignored if no code is available).",
    )
    command_apply.add_argument(
        "--variants",
        type=int,
        help="Override the number of variants specified in the yaml (useful for testing).",
    )
    command_apply.add_argument(
        "yaml",
        help="Path to the yaml.",
    )

    command_verify.add_argument(
        "--strace",
        action="store_true",
        help="print out strace information during verification",
    )

    command_verify.add_argument(
        "-f",
        "--flag",
        help="change the flag to be verified against",
        default="pwn.college{TESTFLAG.ehCUlFggVqD8JsUQin.0V.TESTFLAG}"
    )

    command_verify.add_argument(
        "--timeout",
        type=int,
        help="set a per-challenge timeout (in seconds) for verification",
    )

    command_verify.add_argument(
        "-m",
        "--module",
        help="Verify all the challenges in a module. Can be specified multiple times.",
        action="append"
    )

    command_verify.add_argument(
        "--build-image",
        help="Docker image to use for building",
    )

    command_verify.add_argument(
        "--verify-image",
        help="Docker image to use for verification",
    )


    # where to write
    for c in [ command_render, command_build ]:
        c.add_argument(
            "-o",
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
    for subparser in [ command_render, command_build, command_verify, command_apply ]:
        subparser.add_argument("challenges", help="the challenges, as multiple ChallengeClassName or ModuleName:level_number. Default: all challenges.", nargs="*")

    parser.epilog = f"""Commands usage:\n\t{command_render.format_usage()}\t{command_build.format_usage()}\t{command_verify.format_usage()}"""

    args = parser.parse_args()
    pwnlib.context.context.log_level = "ERROR"

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

    r = globals()["handle_" + args.ACTION.replace('-', '_')](args)
    if r in (None, True):
        return 0
    elif type(r) is int:
        return r
    else:
        return 1

if __name__ == "__main__":
    sys.exit(main())
