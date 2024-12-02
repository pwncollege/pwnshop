import sys
import os
import re
import shlex
import string
import random
import shutil
import inspect
import logging
import subprocess
import tempfile
import textwrap
import contextlib

import black
import docker
import pyastyle
import pwnlib.tubes
import pwnlib.context
from jinja2 import Environment, PackageLoader, ChoiceLoader, contextfilter

from .register import register_challenge
from .util import retry

pwnlib.context.context.arch = "x86_64"
pwnlib.context.context.encoding = "latin"

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

class BaseChallenge:
    BUILD_IMAGE = None
    VERIFY_IMAGE = None
    APT_DEPENDENCIES = []

    def __init__(self, seed, work_dir=None, walkthrough=False, basename=None):
        self.work_dir = tempfile.mkdtemp(prefix='pwnshop-') if work_dir is None else work_dir
        if os.path.exists(self.work_dir):
            self._owns_workdir = False
        else:
            self._owns_workdir = True
            os.makedirs(self.work_dir)

        self._build_container = None
        self._verify_container = None

        self.seed = seed
        self.random = random.Random(seed)
        self.walkthrough = walkthrough

        self.basename = basename or self.default_basename()

    @classmethod
    def default_basename(cls):
        return cls.__name__.lower().replace("_", "-")

    def __init_subclass__(cls, register=True):
        cls_module = inspect.getmodule(cls)
        if register and getattr(cls_module, "PWNSHOP_AUTOREGISTER", True):
            register_challenge(cls)

    @property
    def flag(self):
        with open("/flag", "rb") as f:
            return f.read()

    def random_word(self, length, vocabulary=string.ascii_lowercase):
        return "".join(self.random.choice(vocabulary) for _ in range(length))

    def ensure_containers(self):
        if not self._build_container:
            self._build_container = self._create_container(self.BUILD_IMAGE)
        if not self._verify_container:
            self._verify_container = self._create_container(self.VERIFY_IMAGE)

    def cleanup(self):
        if self._build_container:
            self._build_container.kill()
            self._build_container = None
        if self._verify_container:
            self._verify_container.kill()
            self._verify_container = None
        if self._owns_workdir:
            shutil.rmtree(self.work_dir)

    def __enter__(self):
        self.ensure_containers()
        return self

    def __exit__(self, exc_type, value, tb):
        self.cleanup()

    def render(self):
        pass

    def build(self):
        pass

    def flaky_verify(self, num_attempts=4, timeout=300, **kwargs):
        retry(num_attempts, timeout=timeout)(self.verify)(**kwargs)

    def verify(self, **kwargs):
        raise NotImplementedError()

    @contextlib.contextmanager
    def run_challenge(self, *, argv=None, close_stdin=False, flag_symlink=None, **kwargs):
        self.ensure_containers()

        assert argv

        if flag_symlink:
            self.run_sh(f"ln -s /flag {flag_symlink}")

        if self._verify_container:
            ret, _ = self._verify_container.exec_run(f"""/bin/bash -c 'echo -n "{self.flag.decode()}" | tee /flag'""", user="root")
            assert ret == 0
            _, out = self._verify_container.exec_run("cat /flag", user="root")
            assert out == self.flag
        else:
            with open("/flag", "rb") as f:
                assert f.read() == self.flag

        if not self._verify_container:
            stdout_fds = kwargs.pop("stdout_fds", ())
            def preexec_fn():
                for i in stdout_fds:
                    os.dup2(1, i)

            process = pwnlib.tubes.process.process(argv, preexec_fn=kwargs.pop("preexec_fn", preexec_fn), **kwargs)
        else:
            env = kwargs.pop("env", {})
            alarm = kwargs.pop("alarm", None)
            stdout_fds = kwargs.pop("stdout_fds", ())

            process = pwnlib.tubes.process.process([
                "docker", "exec", "-u", "root", "-i", "-w", self.work_dir,
                self._verify_container.name, "/bin/bash"
            ], **kwargs)

            redirects = ""
            for fd in stdout_fds:
                redirects += f" {fd}>&1" #pylint:disable=consider-using-join

            for k,v in env.items():
                kstr = k.decode('latin1') if type(k) is bytes else k
                with open(f"{self.work_dir}/.pwnshop-env-var", "wb") as o:
                    o.write(v.encode('latin1') if type(v) is str else v)
                process.sendline(f"read {kstr} < {self.work_dir}/.pwnshop-env-var; export {kstr}")
                process.clean()
                os.unlink(f"{self.work_dir}/.pwnshop-env-var")

            if alarm:
                argv = [ "/bin/timeout", "--preserve-status", "-sALRM", str(alarm) ] + argv

            process.sendline("echo PWNSHOP-READY")
            process.sendline(shlex.join(["exec"]+argv) + redirects)
            process.readuntil("PWNSHOP-READY\n")

        if close_stdin:
            process.stdin.close()

        try:
            yield process
        finally:
            process.kill()
            if self._verify_container:
                self._verify_container.exec_run(f'chown {os.getuid()}:{os.getgid()} {self.work_dir}/core', user="root")

    def run_sh(self, command, user="hacker", **kwargs):
        self.ensure_containers()
        if self._verify_container:
            command = f"docker exec -u {user} -i {self._verify_container.name} {command}"

        return pwnlib.tubes.process.process(command, shell=True, **kwargs)

    @property
    def hostname(self):
        self.ensure_containers()
        return "localhost" if not self._verify_container else self._verify_container.attrs['NetworkSettings']['IPAddress']

    def _create_container(self, image=None):
        if not image:
            return None

        client = docker.from_env()
        if ":" in image:
            img, tag = image.split(':')
        else:
            img, tag = image, "latest"
        client.images.pull(img, tag=tag)

        #TODO: container life is context manager
        container = client.containers.run(
            img + ':' + tag,
            'sleep 300',
            auto_remove=True,
            detach=True,
            cap_add=["SYS_PTRACE"],
            security_opt=["seccomp=unconfined"],
            sysctls={"net.ipv4.ip_unprivileged_port_start": 1024},
            network_mode="bridge",
            ulimits = [ docker.types.Ulimit(name='core', soft=-1, hard=-1) ],
            volumes = {
                "/tmp": {"bind": "/tmp", "mode": "rw"},
                self.work_dir : {'bind': self.work_dir, 'mode': 'rw'},
                self.work_dir : {'bind': "/challenge", 'mode': 'rw'}
            }
        )

        requirements = [ "gcc", "patchelf" ] + self.APT_DEPENDENCIES
        _, out = container.exec_run(
            f"""/bin/bash -c 'dpkg -l | cut -f3 -d" " | grep -E "^({ "|".join(requirements) })$"'""",
            user="root"
        )

        missing = set(requirements) - set(out.decode().strip().split("\n"))

        if missing:
            ret, out = container.exec_run(f'/bin/bash -c "apt-get update && apt-get install -y {" ".join(missing)}"', user="root")
            if ret != 0:
                print("DEPENDENCY INSTALL ERROR:")
                print(out.decode('latin1'))
            assert ret == 0, out

        container.reload()
        return container

    def deploy(self, dst_dir, *, bin=True, src=True, libs=True): #pylint:disable=redefined-builtin
        pass

class TemplatedChallenge(BaseChallenge, register=False):
    context = { }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.source = None

        self.src_path = f"{self.work_dir}/{self.basename}"

    @property
    def TEMPLATE_PATH(self):
        raise NotImplementedError()

    def style(self, src):
        return src

    def render(self):
        loader_list = [
            PackageLoader(__name__, ""),
            PackageLoader(__name__, "templates"),
        ]
        for cls in self.__class__.__mro__:
            if not issubclass(cls, BaseChallenge):
                continue
            loader_list.append(PackageLoader(inspect.getmodule(cls).__name__, ""))
            loader_list.append(PackageLoader(inspect.getmodule(cls).__name__, ".."))

        env = Environment(loader=ChoiceLoader(loader_list), trim_blocks=True)
        env.filters["layout_text"] = layout_text
        env.filters["layout_text_walkthrough"] = layout_text_walkthrough
        template = env.get_template(self.TEMPLATE_PATH)
        result = template.render(
            challenge=self,
            walkthrough=self.walkthrough,
            **self.context,
            **self.local_context,
        )
        result = self.style(result)

        self.source = result
        with open(self.src_path, "w") as o:
            o.write(self.source)

        return result

    @property
    def local_context(self):
        return {
            e: getattr(self, e)
            for e in dir(self)
            if not e.startswith("_") and e == e.upper()
        }

    def deploy(self, dst_dir, *, src=False, **kwargs):
        super().deploy(dst_dir, **kwargs)
        if src:
            shutil.copy2(self.src_path, os.path.join(dst_dir, os.path.basename(self.src_path)))


class PythonChallenge(TemplatedChallenge, register=False):
    @property
    def bin_path(self):
        return self.src_path

    def build(self):
        if not self.source:
            self.render()
        os.chmod(self.src_path, 0o4755)

    def style(self, src):
        return black.format_file_contents(src, fast=False, mode=black.FileMode(line_length=120))

    @contextlib.contextmanager
    def run_challenge(self, argv=None, **kwargs):
        kwargs.pop("strace", None)
        if not self.source:
            self.render()

        argv = argv or ["python3", self.src_path]
        with super().run_challenge(argv=argv, **kwargs) as y:
            yield y

    def deploy(self, dst_dir, *, src=False, **kwargs):
        super().deploy(dst_dir, src=src or bin, **kwargs)

class Challenge(TemplatedChallenge, register=False):
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
    PIN_LIBRARIES = False
    DEPLOYMENT_LIB_PATH = "/challenge/lib"

    vbuf_in_main = True
    vbuf_in_constructor = False
    print_greeting = True
    constant_goodbye = True
    win_message = "You win! Here is your flag:"
    static_win_function_variables = True

    context = {
        "min": min,
        "max": max,
        "hex": hex,
        "hex_str_repr": hex_str_repr,
        "layout_text": layout_text,
        "layout_text_walkthrough": layout_text,
    }

    def __init__(self, *, seed, work_dir=None, basename=None, src_extension=".c", bin_extension="", walkthrough=False):
        super().__init__(seed, work_dir=work_dir, basename=basename, walkthrough=walkthrough)

        self.binary = None
        self.libraries = None

        self.src_path = f"{self.work_dir}/{self.basename}{src_extension}"
        self.bin_path = f"{self.work_dir}/{self.basename}{bin_extension}"
        self.lib_path = f"{self.work_dir}/lib"

    def style(self, src):
        src = pyastyle.format(src, "--style=allman")
        src = re.sub("\n{2,}", "\n\n", src)
        return src

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

        cmd.append(f"-ffile-prefix-map={self.work_dir}=/challenge")

        cmd.append("-w")

        cmd.append(self.src_path)

        for lib in self.LINK_LIBRARIES:
            cmd.append("-l" + lib)

        cmd.append("-o")
        cmd.append(self.bin_path)

        return cmd

    def build(self):
        if not self.source:
            self.render()
        self.ensure_containers()
        cmd = self.build_compiler_cmd()

        if self._build_container:
            ret, out = self._build_container.exec_run(cmd)
            if ret != 0:
                print("BUILD ERROR:")
                print(out.decode('latin1'))
            assert ret == 0, out
            self.libraries = self.pin_libraries() if self.PIN_LIBRARIES else []
        else:
            subprocess.check_output(cmd)
            self.libraries = None

        with open(self.bin_path, 'rb') as f:
            self.binary = f.read()

        return self.binary, self.libraries, None

    @contextlib.contextmanager
    def run_challenge(
        self,
        *,
        cmd_args=None,
        argv=None,
        strace=False,
        **kwargs,
    ):
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

        with super().run_challenge(argv=argv, **kwargs) as y:
            yield y

    def pin_libraries(self):
        assert self._build_container

        ret, out = self._build_container.exec_run("ldd " + self.bin_path)
        assert ret == 0
        lib_paths = filter(lambda x: '/' in x, out.decode().split())

        libs = [ ]
        os.makedirs(f"{self.lib_path}", exist_ok=True)
        for p in lib_paths:
            lib_name = os.path.basename(p)
            self._build_container.exec_run(f'cp {p} {self.lib_path}/{lib_name}')

            self._build_container.exec_run(f'chmod 0766 {self.lib_path}/{lib_name}')
            self._build_container.exec_run(f'chown {os.getuid()}:{os.getgid()} {self.lib_path}/{lib_name}')

            with open(f'{self.lib_path}/{lib_name}', 'rb') as f:
                libs.append((lib_name, f.read()))
            if self.DEPLOYMENT_LIB_PATH and "ld-linux" in lib_name:
                ret, out = self._build_container.exec_run(
                    f'patchelf --set-interpreter {self.DEPLOYMENT_LIB_PATH}/{lib_name} ' + self.bin_path,
                    workdir=self.work_dir
                )
            elif self.DEPLOYMENT_LIB_PATH:
                self._build_container.exec_run(
                    f'patchelf --replace-needed {lib_name} {self.DEPLOYMENT_LIB_PATH}/{lib_name} ' + self.bin_path,
                    workdir=self.work_dir
                )

        # the interpreter is set to */challenge*/lib/ld-blah
        if os.path.exists(self.DEPLOYMENT_LIB_PATH):
            os.unlink(self.DEPLOYMENT_LIB_PATH)
        if not os.path.exists(os.path.dirname(self.DEPLOYMENT_LIB_PATH)):
            os.makedirs(os.path.dirname(self.DEPLOYMENT_LIB_PATH))
        if os.path.islink(self.DEPLOYMENT_LIB_PATH):
            os.unlink(self.DEPLOYMENT_LIB_PATH)
        os.symlink(self.work_dir+"/lib", self.DEPLOYMENT_LIB_PATH)

        return libs

    def deploy(self, dst_dir, *, bin=True, libs=True, **kwargs): #pylint:disable=redefined-builtin
        super().deploy(dst_dir, **kwargs)
        if bin:
            shutil.copy2(self.bin_path, os.path.join(dst_dir, os.path.basename(self.bin_path)))

        if libs and os.path.exists(self.lib_path):
            shutil.copytree(self.lib_path, os.path.join(dst_dir, os.path.basename(self.lib_path)), dirs_exist_ok=True)



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

        if self.BUILD_IMAGE is None:
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
        return pwnlib.tubes.process.process(["vm", "exec", command], **kwargs)

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
    challenge_names = None

    def __init__(self, *args, challenge_names=None, basename=None, **kwargs):
        super().__init__(*args, **kwargs)

        self.challenge_names = challenge_names or self.challenge_names or [ self.basename + "-" + c.default_basename() for c in self.challenges ]

        kwargs.pop("workdir", None)
        self.challenge_instances = [
            challenge(*args, work_dir=self.work_dir, basename=name, **kwargs)
            for challenge,name in zip(self.challenges, self.challenge_names)
        ]

    def render(self):
        return { c: c.render() for c in self.challenge_instances }

    def build(self):
        self.ensure_containers()
        return { c: c.build() for c in self.challenge_instances }

    def verify(self, **kwargs):
        self.ensure_containers()

    def ensure_containers(self):
        super().ensure_containers()
        for c in self.challenge_instances:
            c.BUILD_IMAGE = self.BUILD_IMAGE
            c._build_container = self._build_container
            c.VERIFY_IMAGE = self.VERIFY_IMAGE
            c._verify_container = self._verify_container


    def run_challenge(self, **kwargs): #pylint:disable=arguments-differ
        pass

    def deploy(self, dst_dir, **kwargs):
        for c in self.challenge_instances:
            c.deploy(dst_dir, **kwargs)
