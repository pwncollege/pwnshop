import sys
import os
import re
import string
import random
import inspect
import subprocess
import tempfile
import textwrap
import contextlib
import inspect
import traceback

import docker
import pyastyle
import pwn
from jinja2 import Environment, PackageLoader, ChoiceLoader, contextfilter

pwn.context.arch = "x86_64"
pwn.context.encoding = "latin"

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
    CANARY = None
    FRAME_POINTER = None
    STATIC = False
    EXEC_STACK = False
    STRIP = False
    LINK_LIBRARIES = []

    build_image = None

    context = {
        "min": min,
        "max": max,
        "hex": hex,
        "hex_str_repr": hex_str_repr,
        "layout_text": layout_text,
        "layout_text_walkthrough": layout_text,
    }

    def __init__(self, *, seed, **kwargs):
        self.seed = seed
        self.random = random.Random(seed)
        self.walkthrough = kwargs.get("walkthrough")

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

    def generate_source(self):
        env = Environment(loader=ChoiceLoader([
            PackageLoader(__name__, ""),
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
        return result

    def build_binary(self, source=None):
        if not source:
            source = self.generate_source()

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

        if self.STRIP:
            cmd.append("-s")

        cmd.append("-masm=intel")

        cmd.append("-w")

        cmd.append("-x")
        cmd.append("c")

        cmd.append("-")

        for lib in self.LINK_LIBRARIES:
            cmd.append("-l" + lib)


        if self.build_image is None:
            with tempfile.TemporaryDirectory(prefix='pwnshop-') as workdir:
                bin_path = f"{workdir}/{self.__class__.__name__.lower()}"
                cmd.append("-o")
                cmd.append(bin_path)

                subprocess.check_output(cmd, input=source.encode())
                with open(bin_path, 'rb') as f:
                    binary = f.read()
                libs = None
        else:
            binary, libs = self._containerized_build(cmd, source)

        return binary, libs

    @contextlib.contextmanager
    def setup_environment(self, binary=None, *, path=None, flag_symlink=None):
        work_dir = tempfile.mkdtemp(prefix='pwnshop-')
        libs = None

        if not binary:
            binary, libs = self.build_binary()
        if not path:
            os.makedirs(work_dir, exist_ok=True)
            path = work_dir + self.__class__.__name__.lower()
            if isinstance(self, KernelChallenge):
                path += ".ko"

        with open(path, "wb") as f:
            f.write(binary)
        os.chmod(path, 0o4755)

        if libs:
            lib_dir = work_dir + '/lib'
            os.makedirs(lib_dir, exist_ok=True)
            for lib_name, lib_bytes in libs:
                lib_file = lib_dir + '/' + lib_name
                with open(lib_file, 'wb') as f:
                    f.write(lib_bytes)
                os.chmod(lib_file, 0o0755)

        if flag_symlink:
            os.symlink("/flag", f"/{flag_symlink}")

        yield path

    @contextlib.contextmanager
    def verify(
        self,
        binary=None,
        cmd_args=None,
        argv=None,
        *,
        executable_path=None,
        flag_symlink=None,
        close_stdin=False,
        strace=False,
        **kwargs,
    ):
        environment_ctx = None
        if not executable_path:
            environment_ctx = self.setup_environment(
                binary=binary, flag_symlink=flag_symlink
            )
            executable_path = environment_ctx.__enter__()

        with open("/flag", "rb") as f:
            assert f.read() == self.flag

        if argv is None:
            argv = [executable_path]
            if cmd_args:
                argv += cmd_args
            if strace:
                argv = ["strace"] + argv
                executable = "strace"
        else:
            assert not strace

        cwd = os.path.dirname(executable_path)

        with pwn.process(
            argv, executable=executable_path, cwd="/", **kwargs
        ) as process:
            if close_stdin:
                process.stdin.close()
            try:
                yield process
            finally:
                if environment_ctx:
                    environment_ctx.__exit__(*sys.exc_info())

    def metadata(self):
        """
        Returns a dictionary to be yaml'ed for the dojo.
        """
        return {
            "class_name": self.__class__.__name__,
            "description": inspect.cleandoc(self.__doc__) if self.__doc__ else ""
        }

    def _containerized_build(self, cmd, source):
        """
        Spins up a docker container to build target, returns binary and linked libraries
        """
        cont_vpath =  '/mnt/pwnshop'
        bin_path =  cont_vpath + '/' + self.__class__.__name__.lower()

        cmd.append("-o")
        cmd.append(bin_path)
        cmd.append(f'{cont_vpath}/source.c')

        with tempfile.TemporaryDirectory(prefix='pwnshop-') as workdir:
            os.makedirs(f"{workdir}/lib", exist_ok=True)
            client = docker.from_env()
            img, tag = self.build_image.split(':')
            #client.images.pull(img, tag=tag)

            #TODO: container life is context manager
            container = client.containers.run('wtf',
                                    'sleep 300',
                                    auto_remove=True,
                                    detach=True,
                                    volumes = {workdir : {'bind': cont_vpath,
                                                                'mode': 'rw'}})
            #code, out = container.exec_run('/bin/bash -c "apt update && apt install -y gcc patchelf && mkdir -p /tmp/pwnshop"')
            with open(f'{workdir}/source.c', 'w+') as f:
                f.write(source)

            ret, out = container.exec_run(cmd)
            #container.exec_run(f'chmod 0777 ' + bin_path)
            #container.exec_run(f'chown {os.getuid()}:{os.getgid()} ' + bin_path)
            assert ret == 0, out

            ret, out = container.exec_run(f"ldd " + bin_path)
            assert ret == 0
            lib_paths = filter(lambda x: '/' in x, out.decode().split())

            libs = []
            for p in lib_paths:
                lib_name = os.path.basename(p)
                container.exec_run(f'cp {p} {cont_vpath}/lib/{lib_name}')

                container.exec_run(f'chmod 0766 {cont_vpath}/lib/{lib_name}')
                container.exec_run(f'chown {os.getuid()}:{os.getgid()} {cont_vpath}/lib/{lib_name}')

                with open(f'{workdir}/lib/{lib_name}', 'rb') as f:
                    libs.append((lib_name, f.read()))
                if "ld-linux" in lib_name:
                    ret, out = container.exec_run(f'patchelf --set-interpreter /challenge/lib/{lib_name} ' + bin_path, workdir=cont_vpath)
                else:
                    container.exec_run(f'patchelf --replace-needed {lib_name} /challenge/lib/{lib_name} ' + bin_path, workdir=cont_vpath)

            with open(f"{workdir}/{self.__class__.__name__.lower()}", 'rb') as f:
                binary = f.read()

            return binary, libs

class KernelChallenge(Challenge):
    def build_binary(self, source=None):
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

            if not source:
                source = self.generate_source()

            with open(f"{workdir}/challenge.c", "w") as f:
                f.write(source)

            subprocess.run(cmd, stdout=sys.stderr)

            with open(f"{workdir}/challenge.ko", "rb") as f:
                binary = f.read()

            return binary, None

    @contextlib.contextmanager
    def verify(
        self,
        binary=None,
        *,
        executable_path=None,
        flag_symlink=None,
        **kwargs,
    ):
        environment_ctx = None
        if not executable_path:
            environment_ctx = self.setup_environment(
                binary=binary, flag_symlink=flag_symlink
            )
            executable_path = environment_ctx.__enter__()

        # ./run.sh ./generate.py -m BabyKernel -i1 -v -l1 -vvv
        subprocess.run(["passwd", "-d", "root"])
        subprocess.run(["vm", "restart"])
        subprocess.run(["ln", "-sf", executable_path, "/challenge/challenge.ko"])

        try:
            yield
        finally:
            if environment_ctx:
                environment_ctx.__exit__(*sys.exc_info())

    def run(self, command, **kwargs):
        return pwn.process(["vm", "exec", command], **kwargs)

    def run_c(self, src, *, user=None, flags=[]):
        with open("/tmp/program.c", "w") as f:
            f.write(textwrap.dedent(src))
        subprocess.run(
            ["gcc", "-static", "/tmp/program.c", "-o", "/tmp/program"] + flags
        )
        command = "/tmp/program"
        if user:
            command = f"su {user} -c {command}"
        return self.run(command)

    def symbol_address(self, symbol):
        data = self.run(f"grep -P '^[0-9a-f]+\\ .\\ {symbol}(\\t|$)' /proc/kallsyms | grep -oP '^[0-9a-f]+'").readall().strip()
        assert len(data.split()) == 1
        return int(data, 16)


class ChallengeGroup(Challenge):
    challenges = NotImplemented

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.challenge_instances = [
            challenge(*args, **kwargs) for challenge in self.challenges
        ]

    def generate_source(self):
        for challenge in self.challenge_instances:
            yield challenge.generate_source()

    def build_binary(self):
        for challenge in self.challenge_instances:
            yield challenge.build_binary()

    @contextlib.contextmanager
    def setup_environment(self, binary=None, *, path=None, flag_symlink=None):
        environment_ctxs = [
            challenge.setup_environment() for challenge in self.challenge_instances
        ]
        paths = [ctx.__enter__() for ctx in environment_ctxs]
        try:
            yield paths[0]
        finally:
            for ctx in environment_ctxs:
                ctx.__exit__(*sys.exc_info())

    def verify(self, binary=None, *, executable_path=None, **kwargs):
        environment_ctx = None
        if not executable_path:
            environment_ctx = self.setup_environment(binary=binary)
            executable_path = environment_ctx.__enter__()

        challenge = self.challenge_instances[0]
        result = challenge.verify(binary=binary, executable_path=executable_path)

        if environment_ctx:
            environment_ctx.__exit__(*sys.exc_info())

        return result


def retry(max_attempts):
    def wrapper(func):
        @contextlib.wraps(func)
        def wrapped(*args, **kwargs):
            for i in range(max_attempts):
                try:
                    return func(*args, **kwargs)
                except AssertionError:
                    traceback.print_exc()
            else:
                raise Exception(f"Failed after {max_attempts} attempts!")

        return wrapped

    return wrapper
