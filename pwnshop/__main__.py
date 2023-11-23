import argparse
import pwnshop
import random
import yaml
import sys
import pwn
import os

def challenge_class(challenge=None, module=None, level=None):
    if challenge:
        assert challenge in pwnshop.ALL_CHALLENGES, "Unknown challenge specified!"
        return pwnshop.ALL_CHALLENGES[challenge]
    elif level and module:
        assert module in pwnshop.MODULE_LEVELS, "Uknown module specified!"
        assert 0 < level <= len(pwnshop.MODULE_LEVELS[module]), "Invalid level specified."
        return pwnshop.MODULE_LEVELS[module][level-1]
    else:
        raise AssertionError("Improper challenge specification (need challenge or module&level).")

def make_challenge(challenge=None, module=None, level=None, **kwargs):
    return challenge_class(challenge=challenge, module=module, level=level)(**kwargs)

def main():
    parser = argparse.ArgumentParser(description="pwnshop challenge emitter")
    parser.add_argument(
        "-I",
        "--import",
        required=False,
        nargs="*",
        action="extend",
        help="a path to import additional challenges from (either /path/to/module.py or /path/to/package/)",
    )
    parser.add_argument(
        "-c",
        "--challenge",
        required=False,
        help="the challenge to generate",
    )
    parser.add_argument(
        "-m",
        "--module",
        required=False,
        help="the module to use",
    )
    parser.add_argument(
        "-L",
        "--level",
        required=False,
        type=int,
        help="the level (of the given module) to generate",
    )
    parser.add_argument(
        "-s",
        "--seed",
        required=False,
        default=random.randrange(0, 999999),
        help="the seed from which to generate the challenge",
    )
    parser.add_argument(
        "-d",
        "--debug",
        action="store_true",
        help="print out debugging information",
    )
    parser.add_argument(
        "-t",
        "--strace",
        action="store_true",
        help="print out strace information",
    )
    parser.add_argument(
        "-l",
        "--lineno",
        action="store_true",
        help="print out line numbers",
    )
    parser.add_argument(
        "-f",
        "--flag",
        help="change the flag to be verified against",
    )

    # where to write
    parser.add_argument(
        "-O",
        "--out",
        type=argparse.FileType('w'),
        default='-',
        help="change the output destination"
    )
    parser.add_argument(
        "-D",
        "--dojo",
        help="the dojo to insert the yml spec into"
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--src", action="store_true", help="Dump the challenge source"
    )
    group.add_argument(
        "--bin", action="store_true", help="Dump the challenge binary"
    )
    group.add_argument(
        "--verify", action="store_true", help="Verify that the challenge works"
    )
    group.add_argument(
        "--yml", action="store_true", help="Dump the challenge yaml"
    )
    group.add_argument(
        "--dojo-insert", action="store_true", help="Insert challenge yaml into dojo spec."
    )

    parser.add_argument(
        "-w",
        "--walkthrough",
        action="store_true",
        help="enable challenge walkthrough mode",
    )

    parser.add_argument(
        "--lpath",
        help="Location to store needed library files",
    )

    args = parser.parse_args()

    if getattr(args, "import", None):
        imports = getattr(args, "import")
        for i in imports:
            sys.path.append(os.path.realpath(os.path.dirname(i)))
            try:
                module_name = os.path.basename(i).split(".py")[0]
                __import__(module_name)
            finally:
                sys.path.pop()

    if args.debug:
        pwn.context.log_level = "DEBUG"

    if args.flag:
        with open("/flag", "wb") as f:
            f.write(args.flag.encode())

    if (args.yml or args.dojo_insert) and args.module and not args.level:
        assert args.module in pwnshop.MODULE_LEVELS, "Uknown module specified!"
        module = getattr(pwnshop.challenges, args.module)
        num_test = module.NUM_TESTING
        metadata = [ ]
        for i,C in enumerate(pwnshop.MODULE_LEVELS[args.module], start=1):
            if hasattr(module, "CHOOSE_LEVELS") and i not in module.CHOOSE_LEVELS:
                continue

            cm = C(seed=args.seed, walkthrough=1).metadata()
            cm["name"] = f"level{i}" if num_test == 0 else f"level{i}.0"
            cm["category"] = args.module
            del cm["class_name"]
            metadata.append(cm)

            for j in range(num_test):
                cm = C(seed=args.seed, walkthrough=0).metadata()
                cm["name"] = f"level{i}.{j+1}"
                cm["category"] = args.module
                del cm["class_name"]
                metadata.append(cm)

        if args.yml:
            args.out.write(yaml.dump(metadata))
        else:
            # using ruamel to preserve structure, comments, etc
            from ruamel.yaml import YAML
            y = YAML()
            y.indent(offset=2, sequence=4, mapping=2)
            y.preserve_quotes = True
            y.width = 4096

            # thanks to https://stackoverflow.com/questions/8640959/how-can-i-control-what-scalar-form-pyyaml-uses-for-my-data
            #def str_presenter(dumper, data):
            #   if len(data.splitlines()) > 1:  # check for multiline string
            #       return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
            #   return dumper.represent_scalar('tag:yaml.org,2002:str', data)
            #yaml.add_representer(str, str_presenter)

            dojo = y.load(open(args.dojo, "r").read())
            try:
                dojo_module = next(m for m in dojo["modules"] if m["id"] == module.DOJO_MODULE)
            except StopIteration:
                print("Can't find module with specified challenge category in dojo spec.")
                sys.exit(1)
            dojo_module["challenges"] = metadata
            y.dump(dojo, open(args.dojo, "w"))
    elif args.challenge or (args.module and args.level):
        challenge = make_challenge(
            challenge=args.challenge, module=args.module, level=args.level, seed=args.seed, walkthrough=args.walkthrough
        )

        if args.src:
            src = challenge.generate_source()
            if not args.lineno:
                args.out.write(src+"\n")
            else:
                for i, line in enumerate(src.splitlines()):
                    args.out.write(f"{i + 1}\t{line}\n")
            if os.path.isfile(args.out.name):
                os.chmod(args.out.name, 0o644)

        if args.bin:
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


        if args.verify:
            # TODO: this was an optimization which may be critical for verifying against 1000s of program runs
            # binary = challenge.build_binary()
            # challenge.verify(binary=binary, strace=args.strace)
            challenge.verify()

        if args.yml:
            args.out.write(yaml.dump(challenge.metadata()))

    elif args.src or args.bin or args.verify:
        print("Improper challenge specification (need challenge or module&level).")
        sys.exit(1)
    elif args.yml:
        print("Improper challenge specification (need challenge or module&level or module).")
        sys.exit(1)
    else:
        print("Unexpected configuration.")
        sys.exit(1)



if __name__ == "__main__":
    main()
