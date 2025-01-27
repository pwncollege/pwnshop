import pathlib
import psutil

# This function determines the process that is on the
# other side of the file descriptor we pass in.
def peer_process_of(fd):
    server_connection = next(
        connection
        for connection in psutil.Process().connections()
        if connection.fd == fd
    )
    client_connection = next(
        connection
        for connection in psutil.net_connections()
        if connection.raddr == server_connection.laddr
        and connection.laddr == server_connection.raddr
    )
    return psutil.Process(client_connection.pid)

# This function returns the filename of a peer process for a given
# file descriptor, verifying that the path is owned by root and
# not open to shenanigans.
def name_of_program_for(process):
    client_path = pathlib.Path(process.exe())
    for p in reversed(client_path.parents):
        if not p.owner() == "root":
            return None
        if p in ("/home", "/tmp", "/var/tmp", "/dev/shm"):
            return None
    return client_path.stem
