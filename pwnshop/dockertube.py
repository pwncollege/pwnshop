import tempfile
import pwnlib.tubes.process
import shlex
import os

class docker_process(pwnlib.tubes.process.process):
	def __init__(
		self, argv=None,
		container_name=None, user=1000, work_dir=None, suffix="",
		shell=False, executable=None, cwd=None, env=None, aslr=None, setuid=None, alarm=None,
		**kwargs
	):
		assert container_name is not None, "must provide container name" # don't want to mess up the arg order everyone is used to
		assert aslr is None, "docker_process doesn't support aslr kwarg"
		assert executable is None, "docker_process doesn't support executable kwarg"
		assert setuid is None, "docker_process doesn't support setuid kwarg"
		assert not alarm or not shell, "alarm is not supported with shell=True"

		work_dir = work_dir or tempfile.mkdtemp()
		self.container_name = container_name

		docker_cmd = [
			"docker", "exec", "-u", str(user), "-i", "-w", cwd or work_dir, self.container_name, "/bin/bash"
		]
		super().__init__(docker_cmd, **kwargs)

		env = env or { }
		for k,v in env.items():
			kstr = k.decode('latin1') if type(k) is bytes else k
			with open(f"{work_dir}/.pwnshop-env-var", "wb") as o:
				o.write(v.encode('latin1') if type(v) is str else v)
			self.sendline(f"read {kstr} < {work_dir}/.pwnshop-env-var; export {kstr}")
			self.clean()
			os.unlink(f"{work_dir}/.pwnshop-env-var")

		self.sendline("echo PWNSHOP-PID:$$")
		self.readuntil("PWNSHOP-PID:")
		self.actual_pid = int(self.readline().strip())

		if alarm:
			self.sendline(f"( sleep {alarm}; kill -ALRM {self.actual_pid} )")

		self.sendline("echo PWNSHOP-READY")
		actual_cmd = argv if shell else "exec " + shlex.join(argv)
		self.sendline(actual_cmd + suffix)
		self.readuntil("PWNSHOP-READY\n")

	def kill(self):
		pwnlib.tubes.process.process(f"docker exec -u root {self.container_name} kill -9 -- -{self.actual_pid}", shell=True).readall()

	def __exit__(self, *args, **kwargs):
		super().__exit__(*args, **kwargs)
		self.kill()
