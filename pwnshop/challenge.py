import sys
import os
import re
import string
import random
import signal
import inspect
import logging
import subprocess
import tempfile
import textwrap
import contextlib
import traceback

import docker
import pyastyle
import pwn
from jinja2 import Environment, PackageLoader, ChoiceLoader, contextfilter

from .register import register_challenge

pwn.context.arch = "x86_64"
pwn.context.encoding = "latin"

_LOG = logging.getLogger(__name__)

def hex_str_repr(s):
    hex_s = s.encode("latin").hex()
    return "".join("\\x" + hex_s[i : i + 2] for i in range(0, len(hex_s), 2))


def layout_text(text):
    lines = textwrap.wrap(textwrap.dedent(text), width=120)
    if lines:
        lines[-1] += "\\n"
    else:
        lines = [""]
    return "\n".join(f'puts("{line}");' for line in lines)


@contextfilter
def layout_text_walkthrough(context, text):
    if not context.get("walkthrough"):
        return "\n"
    return layout_text(text)


class Challenge:
    COMPILER = "gcc"
    PIE = None
    RELRO = "full"
    MASM_FLAG = "-masm=intel"
    OPTIMIZATION_FLAG = "-O0"
    CANARY = None
    FRAME_POINTER = None
    STATIC = False
    EXEC_STACK = False
    STRIP = False
    DEBUG_SYMBOLS = False
    LINK_LIBRARIES = []

    vbuf_in_main = True
    vbuf_in_constructor = False
    print_greeting = True
    constant_goodbye = True
    win_message = "You win! Here is your flag:"
    static_win_function_variables = True

    build_image = None

    context = {
        "min": min,
        "max": max,
        "hex": hex,
        "hex_str_repr": hex_str_repr,
        "layout_text": layout_text,
        "layout_text_walkthrough": layout_text,
    }

    def __init__(self, *, seed, work_dir=None, basename=None, src_extension=".c", bin_extension=None, walkthrough=False):
        self.seed = seed
        self.random = random.Random(seed)
        self.walkthrough = walkthrough

        self.source = None
        self.binary = None
        self.libraries = None
        self.set_paths(work_dir=work_dir, basename=basename, src_extension=src_extension or "", bin_extension=bin_extension or "")

    def set_paths(self, work_dir=None, basename=None, src_extension="", bin_extension=""):
        self.work_dir = tempfile.mkdtemp(prefix='pwnshop-') if work_dir is None else work_dir
        os.makedirs(self.work_dir, exist_ok=True)
        basename = basename or self.__class__.__name__.lower()

        self.bin_path = f"{self.work_dir}/{basename}{bin_extension}"
        self.src_path = f"{self.work_dir}/{basename}{src_extension}"
        self.lib_path = f"{self.work_dir}/lib"

    def __init_subclass__(cls, register=True):
        cls_module = inspect.getmodule(cls)
        if register and getattr(cls_module, "PWNSHOP_AUTOREGISTER", True):
            register_challenge(cls)

    @property
    def TEMPLATE_PATH(self):
        raise NotImplementedError()

    @property
    def local_context(self):
        return {
            e: getattr(self, e)
            for e in dir(self)
            if not e.startswith("_") and e == e.upper()
        }

    @property
    def flag(self):
        with open("/flag", "rb") as f:
            return f.read()

    def random_word(self, length, vocabulary=string.ascii_lowercase):
        return "".join(self.random.choice(vocabulary) for _ in range(length))

    def render(self):
        env = Environment(loader=ChoiceLoader([
            PackageLoader(__name__, ""),
            PackageLoader(__name__, "templates"),
            PackageLoader(inspect.getmodule(self).__name__, ""),
            PackageLoader(inspect.getmodule(self).__name__, ".."),
        ]), trim_blocks=True)
        env.filters["layout_text"] = layout_text
        env.filters["layout_text_walkthrough"] = layout_text_walkthrough
        template = env.get_template(self.TEMPLATE_PATH)
        result = template.render(
            challenge=self,
            walkthrough=self.walkthrough,
            **self.context,
            **self.local_context,
        )
        result = pyastyle.format(result, "--style=allman")
        result = re.sub("\n{2,}", "\n\n", result)

        self.source = result
        with open(self.src_path, "w") as o:
            o.write(self.source)

        return result

    def build_compiler_cmd(self):
        cmd = [self.COMPILER]

        if self.RELRO == "full":
            cmd.append("-Wl,-z,relro,-z,now")
        elif self.RELRO  == "partial":
            cmd.append("-Wl,-z,relro,-z,lazy")
        elif self.RELRO == "none":
            cmd.append("-Wl,-z,norelro")

        if self.PIE is True:
            cmd.append("-pie")
        elif self.PIE is False:
            cmd.append("-no-pie")

        if self.CANARY is True:
            cmd.append("-fstack-protector")
        elif self.CANARY is False:
            cmd.append("-fno-stack-protector")

        if self.FRAME_POINTER is True:
            cmd.append("-fno-omit-frame-pointer")
        elif self.FRAME_POINTER is False:
            cmd.append("-fomit-frame-pointer")

        if self.STATIC and self.PIE:
            cmd.append("-static-pie")
        elif self.STATIC:
            cmd.append("-static")

        if self.EXEC_STACK:
            cmd.append("-z")
            cmd.append("execstack")

        if self.DEBUG_SYMBOLS:
            cmd.append("-g")

        if self.STRIP:
            cmd.append("-s")

        if self.MASM_FLAG:
            cmd.append(self.MASM_FLAG)
        if self.OPTIMIZATION_FLAG:
            cmd.append(self.OPTIMIZATION_FLAG)

        cmd.append("-w")

        cmd.append("-x")
        cmd.append("c")

        cmd.append("-")

        for lib in self.LINK_LIBRARIES:
            cmd.append("-l" + lib)

        return cmd

    def build(self):
        if not self.source:
            self.render()

        cmd = self.build_compiler_cmd()

        if self.build_image is None:
            cmd.append("-o")
            cmd.append(self.bin_path)
            subprocess.check_output(cmd, input=self.source.encode())
            with open(self.bin_path, 'rb') as f:
                self.binary = f.read()
                self.libraries = None
        else:
            self.binary, self.libraries = self._containerized_build(cmd)

            # the interpreter is set to */challenge*/lib/ld-blah
            if os.path.exists("/challenge"):
                os.unlink("/challenge")
            os.symlink(self.work_dir, "/challenge")

        os.chmod(self.bin_path, 0o4755)

        return self.binary, self.libraries, None

    @contextlib.contextmanager
    def verify(self, cmd_args=None, argv=None, **kwargs):
        raise NotImplementedError()

    @contextlib.contextmanager
    def run_challenge(
        self,
        *,
        cmd_args=None,
        argv=None,
        flag_symlink=None,
        close_stdin=False,
        strace=False,
        **kwargs,
    ):
        environment_ctx = None
        if flag_symlink:
            os.symlink("/flag", f"{flag_symlink}")

        with open("/flag", "rb") as f:
            assert f.read() == self.flag

        if argv is None:
            argv = [self.bin_path]
            if cmd_args:
                argv += cmd_args
            if strace:
                argv = ["strace"] + argv
                kwargs["stderr"] = 2
        else:
            assert not strace

        if not self.binary:
            self.build()

        with pwn.process(
            argv, **kwargs
        ) as process:
            if close_stdin:
                process.stdin.close()
            try:
                yield process
            finally:
                if environment_ctx:
                    environment_ctx.__exit__(*sys.exc_info())

    def run_sh(self, command, **kwargs):
        return pwn.process(command, shell=True, **kwargs)

    def metadata(self):
        """
        Returns a dictionary to be yaml'ed for the dojo.
        """
        return {
            "class_name": self.__class__.__name__,
            "description": inspect.cleandoc(self.__doc__) if self.__doc__ else ""
        }

    def _containerized_build(self, cmd):
        """
        Spins up a docker container to build target, returns binary and linked libraries
        """
        cmd.append("-o")
        cmd.append(self.bin_path)
        cmd.append(self.src_path)

        if not self.source:
            self.render()

        os.makedirs(f"{self.lib_path}", exist_ok=True)

        client = docker.from_env()
        img, tag = self.build_image.split(':')
        client.images.pull(img, tag=tag)

        #TODO: container life is context manager
        container = client.containers.run(
            img + ':' + tag,
            'sleep 300',
            auto_remove=True,
            detach=True,
            volumes = {self.work_dir : {'bind': self.work_dir, 'mode': 'rw'}}
        )
        ret, out = container.exec_run('/bin/bash -c "apt update && apt install -y gcc patchelf && mkdir -p /tmp/pwnshop"')
        assert ret == 0

        ret, out = container.exec_run(cmd)
        #container.exec_run(f'chmod 0777 ' + bin_path)
        #container.exec_run(f'chown {os.getuid()}:{os.getgid()} ' + bin_path)
        assert ret == 0, out

        ret, out = container.exec_run("ldd " + self.bin_path)
        assert ret == 0
        lib_paths = filter(lambda x: '/' in x, out.decode().split())

        libs = []
        for p in lib_paths:
            lib_name = os.path.basename(p)
            container.exec_run(f'cp {p} {self.lib_path}/{lib_name}')

            container.exec_run(f'chmod 0766 {self.lib_path}/{lib_name}')
            container.exec_run(f'chown {os.getuid()}:{os.getgid()} {self.lib_path}/{lib_name}')

            with open(f'{self.lib_path}/{lib_name}', 'rb') as f:
                libs.append((lib_name, f.read()))
            if "ld-linux" in lib_name:
                ret, out = container.exec_run(
                    f'patchelf --set-interpreter /challenge/lib/{lib_name} ' + self.bin_path,
                    workdir=self.work_dir
                )
            else:
                container.exec_run(
                    f'patchelf --replace-needed {lib_name} /challenge/lib/{lib_name} ' + self.bin_path,
                    workdir=self.work_dir
                )

        with open(f"{self.bin_path}", 'rb') as f:
            binary = f.read()

        return binary, libs

class WindowsChallenge(Challenge, register=False):
    COMPILER = "cl"
    CANARY = None
    FRAME_POINTER = True
    PDB = True
    CFG = True
    DYNAMIC_BASE = True
    ASLR_HIGH_ENTROPY = True
    MAKE_DLL = False

    def build_compiler_cmd(self):
        cmd = [self.COMPILER]

        if self.CANARY is True:
            cmd.append("/GS")
        else:
            cmd.append("/GS-")

        if self.FRAME_POINTER is False:
            cmd.append("/0y")

        if self.PDB:
            cmd.append("/Zi")

        if self.CFG:
            cmd.append("/guard:cf")
        else:
            cmd.append("/guard:cf-")

        if self.MAKE_DLL:
            cmd.append("/LD")

        return cmd
        # Linker options

        #pylint:disable=unreachable
        cmd.append('/LINK')
        if self.DYNAMIC_BASE is True:
            cmd.append('/DYNAMICBASE')
        else:
            cmd.append('/DYNAMICBASE:NO')

        if self.ASLR_HIGH_ENTROPY is True:
            cmd.append('/HIGHENTROPYVA')

        for lib in self.LINK_LIBRARIES:
            cmd.append(lib)

        return cmd

    def build(self, source=None):
        if not source:
            source = self.render()

        cmd = self.build_compiler_cmd()

        if self.build_image is None:
            with tempfile.TemporaryDirectory(prefix='pwnshop-') as workdir:
                src_path = f"{workdir}/{self.__class__.__name__.lower()}.c"

                if self.MAKE_DLL:
                    bin_path = f"{workdir}/{self.__class__.__name__.lower()}.dll"
                else:
                    bin_path = f"{workdir}/{self.__class__.__name__.lower()}.exe"
                pdb_path = f"{workdir}/{self.__class__.__name__.lower()}.pdb"
                with open(src_path, 'w') as f:
                    f.write(source)

                cmd.append(src_path)
                subprocess.check_output(cmd, cwd=workdir)
                with open(bin_path, 'rb') as f:
                    binary = f.read()

                if self.PDB:
                    with open(pdb_path, 'rb') as f:
                        pdb = f.read()
                else:
                    pdb = None
                return binary, None, pdb

        else:
            raise NotImplementedError("Containerized Windows build not supported")

class KernelChallenge(Challenge, register=False):
    def __init__(self, bin_extension=".ko", **kwargs):
        super().__init__(bin_extension=bin_extension, **kwargs)

    def build(self):
        with tempfile.TemporaryDirectory() as workdir:
            with open(f"{workdir}/Makefile", "w") as f:
                f.write(
                    textwrap.dedent(
                        f"""
                        obj-m += challenge.o

                        all:
                        \tmake -C /opt/linux/linux-5.4 M={workdir} modules
                        clean:
                        \tmake -C /opt/linux/linux-5.4 M={workdir} clean
                        """
                    )
                )

            cmd = ["make", "-C", workdir]

            if not self.source:
                self.render()

            with open(f"{workdir}/challenge.c", "w") as f:
                f.write(self.source)

            subprocess.run(cmd, stdout=sys.stderr, check=True)

            with open(f"{workdir}/challenge.ko", "rb") as f:
                self.binary = f.read()
                with open(self.bin_path, "wb") as o:
                    o.write(self.binary)

            return self.binary, None, None

    @contextlib.contextmanager
    def run_challenge( #pylint:disable=arguments-differ
        self,
        *,
        flag_symlink=None,
        **kwargs,
    ):
        if flag_symlink:
            os.symlink("/flag", f"{flag_symlink}")

        # ./run.sh ./generate.py -m BabyKernel -i1 -v -l1 -vvv
        subprocess.run(["passwd", "-d", "root"], check=True)
        subprocess.run(["vm", "restart"], check=True)
        subprocess.run(["ln", "-sf", self.bin_path, "/challenge/challenge.ko"], check=True)

        yield

    def run_sh(self, command, **kwargs):
        return pwn.process(["vm", "exec", command], **kwargs)

    def run_c(self, src, *, user=None, flags=()):
        with open("/tmp/program.c", "w") as f:
            f.write(textwrap.dedent(src))
        subprocess.run(
            ["gcc", "-static", "/tmp/program.c", "-o", "/tmp/program"] + list(flags),
            check=True
        )
        command = "/tmp/program"
        if user:
            command = f"su {user} -c {command}"
        return self.run_sh(command)

    def symbol_address(self, symbol):
        data = self.run_sh(f"grep -P '^[0-9a-f]+\\ .\\ {symbol}(\\t|$)' /proc/kallsyms | grep -oP '^[0-9a-f]+'").readall().strip()
        assert len(data.split()) == 1
        return int(data, 16)


class ChallengeGroup(Challenge, register=False):
    challenges = [ ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.challenge_instances = [
            challenge(*args, **kwargs) for challenge in self.challenges
        ]

    def render(self):
        for challenge in self.challenge_instances:
            yield challenge.render()

    def build(self):
        for challenge in self.challenge_instances:
            yield challenge.build()

    def run_challenge(self, **kwargs): #pylint:disable=arguments-differ
        challenge = self.challenge_instances[0]
        result = challenge.run_challenge()

        return result

def retry(max_attempts, timeout=None):
    def wrapper(func):
        @contextlib.wraps(func)
        def wrapped(*args, **kwargs):
            for _ in range(max_attempts):
                try:
                    if timeout:
                        def alarm(*args):
                            raise AssertionError("ATTEMPT TIMED OUT")
                        signal.signal(signal.SIGALRM, alarm)
                        signal.alarm(timeout)
                    return func(*args, **kwargs)
                except AssertionError:
                    traceback.print_exc()
                finally:
                    signal.alarm(0)

            raise RuntimeError(f"Failed after {max_attempts} attempts!")

        return wrapped

    return wrapper
