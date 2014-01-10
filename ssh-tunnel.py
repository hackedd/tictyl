#!/usr/bin/env python
import os
import sys
import yaml
import time
import fcntl
import pipes
import errno
import socket
import subprocess
from contextlib import contextmanager


__version__ = "1.0a1"


def get_config_directory(app, create=True):
    """Get the path of an application-specific configuration directory in
    XDG_CONFIG_HOME. If create is True and the directory does not exists,
    it will be created.

    """
    if "XDG_CONFIG_HOME" in os.environ:
        config_home = os.environ["XDG_CONFIG_HOME"]
    else:
        config_home = os.path.expanduser("~/.config")

    directory = os.path.join(config_home, app)
    if create and not os.path.exists(directory):
        os.makedirs(directory)
    return directory


def load_yaml_file(directory, name):
    filename = os.path.join(directory, name)

    if not os.path.exists(filename):
        return {}

    with open(filename, "r") as fp:
        return yaml.load(fp) or {}


def write_yaml_file(directory, name, value):
    filename = os.path.join(directory, name)
    with open(filename, "w") as fp:
        yaml.dump(value, fp, default_flow_style=False)


def is_executable(filename):
    return os.path.isfile(filename) and os.access(filename, os.X_OK)


def which(program):
    fpath, fname = os.path.split(program)
    if fpath:
        return program if is_executable(program) else None

    for path in os.environ["PATH"].split(os.pathsep):
        filename = os.path.join(path.strip("\""), program)
        if is_executable(filename):
            return filename

    return None


@contextmanager
def locked_open(filename, mode, operation=None):
    if operation is None:
        if mode.startswith("r") and not mode.startswith("r+"):
            operation = fcntl.LOCK_SH
        else:
            operation = fcntl.LOCK_EX

    try:
        fp = open(filename, mode)
        fcntl.lockf(fp, operation)
        yield fp
    finally:
        fcntl.lockf(fp, fcntl.LOCK_UN)
        fp.close()


def check_pid(pid):
    try:
        # If sig is 0, then no signal is sent, but error checking is still
        # performed; this can be used to check for the existence of a process.
        os.kill(pid, 0)
        return True
    except OSError as ex:
        if ex.errno == errno.ESRCH:
            # The pid or process group does not exist.
            return False
        if ex.errno != errno.EPERM:
            raise


def check_socket(ssh, socket, hostname):
    if not os.path.exists(socket):
        return False

    # TODO: Figure out the socket protocol, so we can connect to the socket
    # ourselves. This would save spawning a SSH process each time we want to
    # check the socket in `background_wait`.

    check_command = [ssh, "-S", socket, "-O", "check", hostname]

    try:
        output = subprocess.check_output(check_command,
                                         stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError:
        return False

    if output.startswith("Master running"):
        return True

    print >>sys.stderr, "ssh-tunnel: unrecognized ouput:"
    print >>sys.stderr, output.strip()
    return False


def get_free_port():
    s = socket.socket(socket.AF_INET)
    s.bind(("", 0))
    addr, port = s.getsockname()
    s.close()
    return port


def get_socket_name(directory, hostname):
    filename = os.path.join(directory, hostname + "-socket")
    if not os.path.exists(filename):
        return filename

    filename += "-%d"
    number = 2
    while os.path.exists(filename % number):
        number += 1
    return filename % number


def background_wait(ssh, socket, hostname, interval=60):
    if os.fork() != 0:
        os._exit(0)

    # Make this process a session leader.
    os.setsid()

    if os.fork() != 0:
        os._exit(0)

    time.sleep(interval)
    while check_socket(ssh, socket, hostname):
        time.sleep(interval)


def format_ssh_forward(tunnel, local_port):
    if isinstance(tunnel, dict):
        host = tunnel["host"]
        port = tunnel["port"]
    else:
        host = "localhost"
        port = tunnel

    return "-L%d:%s:%d" % (local_port, host, port)


def print_usage(prog):
    print "Usage: %s [options] [user@]hostname [command]" % prog
    print "   or: %s --port hostname [tunnel]" % prog
    print "   or: %s --list" % prog
    print
    print "In the first form, a SSH connection to hostname is established,"
    print "automatically selecting appropriate local ports for any tunnels"
    print "defined in the confuration file. In the second form, the chosen"
    print "local port for the tunnel is printed."
    print
    print "Example:"
    print "  %s --bg prod-sql-1 sleep 60" % prog
    print "  # connects to the production SQL server"
    print "  mysql -h 127.0.0.1 -P $(%s --port prod-sql-1 mysql)" % prog
    print "  # starts a mysql monitor, connecting using the tunnel"
    print
    print "Options:"
    print "  --list        print the status of all known tunnels and exit"
    print "  --port        print the port used for a tunnel and exit"
    print "  --background  go into the background after the SSH connection"
    print "                has been established."
    print
    print "  all other options are passed on to ssh"
    print


def print_error(message, *args, **kwargs):
    status = kwargs.pop("status", 1)

    if args:
        message = message % args

    print >>sys.stderr, "ssh-tunnel:", message
    sys.exit(status)


def print_list():
    config = load_yaml_file(directory, "config")
    status = load_yaml_file(directory, "status")

    all_tunnels = config.get("tunnels")
    if not all_tunnels:
        print >>sys.stderr, "You do not have any tunnels set up.",
        print >>sys.stderr, "You can define them in ",
        print >>sys.stderr, os.path.join(directory, "config")
        return

    format = "%-15s %-15s %7s"
    print format % ("Host", "Tunnel", "Status")
    print "-" * 39

    for hostname in sorted(all_tunnels.keys()):
        tunnels = all_tunnels[hostname]

        connected = {}
        if hostname in status:
            for pid, process in status[hostname].iteritems():
                connected.update(process["ports"])

        for name in sorted(tunnels.keys()):
            print format % (hostname, name, connected.get(name, "-"))


def print_port(hostname, tunnel):
    if not tunnel:
        if len(tunnels) != 1:
            print_error("tunnel name not specified")
        tunnel = tunnels.keys()[0]

    if tunnel not in tunnels:
        print_error("unknown tunnel '%s/%s'", hostname, tunnel)

    host_processes = status.get(hostname)
    if host_processes is None:
        print_error("tunnel '%s/%s' not active", hostname, tunnel, status=2)

    for pid, process in host_processes.iteritems():
        if process["socket"]:
            alive = check_socket(ssh, process["socket"], hostname)
        else:
            alive = check_pid(pid)

        if not alive:
            # TODO: ssh process died, remove from status file?
            continue

        # XXX: We assume the pid is still valid. This might not be the case
        # if the pid has been recycled and now refers to some other process.
        if tunnel in process["ports"]:
            print process["ports"][tunnel]
            break
    else:
        print_error("tunnel '%s/%s' not active", hostname, tunnel, status=2)

    sys.exit(0)


if __name__ == "__main__":
    ssh_args = []
    do_print_port = False
    hostname = None
    tunnel = None
    background = False

    directory = get_config_directory("ssh-tunnel")

    for arg in sys.argv[1:]:
        if arg == "--help":
            print_usage(sys.argv[0])
            sys.exit(0)
        elif arg == "--list":
            print_list()
            sys.exit(0)
        elif arg == "--port":
            do_print_port = True
        elif arg == "--bg" or arg == "--background":
            background = True
        else:
            if not arg.startswith("-"):
                if hostname is None:
                    hostname = arg.split("@")[-1]
                elif tunnel is None:
                    tunnel = arg
            ssh_args.append(arg)

    config = load_yaml_file(directory, "config")
    status = load_yaml_file(directory, "status")
    all_tunnels = config.get("tunnels", {})

    if not hostname:
        print_error("not enough arguments")

    tunnels = all_tunnels.get(hostname, {})
    ssh = which("ssh")

    if do_print_port:
        if len(ssh_args) > 2:
            arguments = " ".join([pipes.quote(arg) for arg in ssh_args])
            print_error("unexpected arguments: %s", arguments)

        print_port(hostname, tunnel)

    status_file = os.path.join(directory, "status")

    with locked_open(status_file, "w") as fp:
        host_processes = status.setdefault(hostname, {})
        cmdline = [ssh]

        # Figure out what tunnels are not yet connected.
        tunnel_names = set(tunnels.keys())
        for host_process in host_processes:
            tunnel_names -= set(host_processes["ports"].keys())

        tunnel_ports = {}
        for name in tunnel_names:
            port = get_free_port()
            cmdline.append(format_ssh_forward(tunnels[name], port))
            tunnel_ports[name] = port

        if background:
            socket_name = get_socket_name(directory, hostname)
            cmdline.extend(["-f", "-M", "-S", socket_name])
        else:
            socket_name = None

        cmdline.extend(ssh_args)
        proc = subprocess.Popen(cmdline)

        host_processes[proc.pid] = {
            "pid": proc.pid,
            "cmd": cmdline,
            "socket": socket_name,
            "ports": tunnel_ports
        }

        yaml.dump(status, fp, default_flow_style=False)

    proc.wait()

    if background and proc.returncode == 0:
        # The original SSH process has now exited, but we can use the control
        # socket to check on the new process.
        background_wait(ssh, socket_name, hostname)

    with locked_open(status_file, "r+") as fp:
        status = yaml.load(fp)

        host_processes = status[hostname]
        del host_processes[proc.pid]
        if not host_processes:
            del status[hostname]

        yaml.dump(status, fp, default_flow_style=False)
