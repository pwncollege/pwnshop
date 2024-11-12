import pwnshop
import pwn
import os

class ShellBase(pwnshop.Challenge, register=False): # don't register this as an actual challenge
    TEMPLATE_PATH = "example_shell.c"
    EXEC_STACK = True
    CANARY = True
    LINK_LIBRARIES = ["capstone"]

    stack_shellcode = False
    shellcode_size = 0x1000
    allocation_size = 0x1000
    remap_rx_size = 0x0
    shellcode_filter = None
    close_stdin = False
    close_stdout = False
    close_stderr = False

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.shellcode_address = self.random.randrange(0x13370000, 0x31337000, 0x1000)

class ShellExample(ShellBase):
    """
    An example shellcode loader.
    """

    stack_shellcode = True
    shellcode_size = 0x1000
    allocation_size = 0x1000

    def verify(self, **kwargs):
        """
        Read 0x1000 bytes onto the stack (address varies every time that it is run)
        """
        with self.run_challenge(**kwargs) as process:
            shellcode = pwn.asm(
                pwn.shellcraft.open("/flag") + pwn.shellcraft.sendfile(1, 3, 0, 1024) + pwn.shellcraft.exit(0)
            )
            process.write(shellcode)
            assert self.flag in process.readall()

class ShellOptimized(ShellExample):
    """
    The same example, but optimized with -O3.
    """
    OPTIMIZATION_FLAG = "-O3"
    DEBUG_SYMBOLS = True

class ShellBadVerifier(ShellExample):
    """
    The same example, with a verifier that fails.
    """

    def verify(self, binary=None, **kwargs):
        assert False

class Shell1604(ShellExample):
    """
    The same example, built using 16.04.
    """

    BUILD_IMAGE = "ubuntu:16.04"
    BUILD_DEPENDENCIES = "libcapstone-dev"
    PIN_LIBRARIES = True
