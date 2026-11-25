#!/usr/bin/env python3
"""Run a native SGLogin test against root-owned disposable D-Bus fixtures only.

Usage: sudo -n python3 test/integration/sglogin-provider.py BUILT_TEST_BINARY
No installed bus, services, policy, PAM, devices or containment are modified.
"""
import argparse
import contextlib
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

SID = "0123456789abcdef0123456789abcdef"
SESSION = "org.SGLogin.Sessiond1"
SEAT = "org.SGLogin.Multiseatd1.Seat_seat0"
SI = SESSION + ".Manager"
MI = "org.SGLogin.Multiseatd1.Manager"


class MissingSession(dbus.DBusException):
    _dbus_error_name = SESSION + ".Error.SessionNotFound"


class InvalidProcess(dbus.DBusException):
    _dbus_error_name = SESSION + ".Error.ProcessChanged"


class MissingContext(dbus.DBusException):
    _dbus_error_name = "org.SGLogin.Multiseatd1.Error.NotFound"


class Ambiguous(dbus.DBusException):
    _dbus_error_name = "org.SGLogin.Multiseatd1.Error.AmbiguousContext"


def start_time(pid):
    return int(pathlib.Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[19])


class Session(dbus.service.Object):
    def __init__(self, connection, state):
        super().__init__(connection, "/org/SGLogin/Sessiond1")
        self.state = state

    def info(self):
        self.state.queries += 1
        if self.state.mode == "absent":
            raise MissingSession("fixture session is unready or dead")
        return SID, dbus.UInt32(1000), "/fixture/runtime/1000"

    @dbus.service.method(SI, in_signature="ut", out_signature="(sus)")
    def GetSessionByPid(self, pid, expected):
        try:
            actual = start_time(pid)
        except (OSError, ValueError):
            raise InvalidProcess("process disappeared") from None
        if expected != actual:
            raise InvalidProcess("expected start time does not match")
        return self.info()

    @dbus.service.method(SI, in_signature="s", out_signature="(sus)")
    def GetSession(self, sid):
        assert sid == SID
        return self.info()

    @dbus.service.method(SI, in_signature="s", out_signature="ut")
    def GetSessionMasterPid(self, sid):
        self.info()
        return dbus.UInt32(os.getpid()), dbus.UInt64(start_time(os.getpid()))

    @dbus.service.method(SI, in_signature="s", out_signature="a{ss}")
    def GetSessionAttrs(self, sid):
        self.info()
        return {} if self.state.mode == "unseated" else {"XDG_SEAT": "seat0"}

    @dbus.service.signal(SI, signature="su")
    def SessionRemoved(self, sid, uid):
        pass


class Seat(dbus.service.Object):
    def __init__(self, connection, state):
        super().__init__(connection, "/org/SGLogin/Multiseatd1")
        self.state = state

    @dbus.service.method(MI, in_signature="ut", out_signature="(suauaubbb)")
    def GetContextByMasterPid(self, pid, expected):
        assert pid == os.getpid() and expected == start_time(os.getpid())
        self.state.queries += 1
        if self.state.mode == "no-context":
            raise MissingContext("no exact master context")
        if self.state.mode == "ambiguous":
            raise Ambiguous("multiple contexts have this exact master")
        return ("aabbccdd-1234-7567-89ab-0123456789ab", dbus.UInt32(0), dbus.Array([], signature="u"),
                dbus.Array([], signature="u"), True, False, self.state.mode != "inactive")

    @dbus.service.signal(MI, signature="t")
    def StateChanged(self, revision):
        pass


class Control(dbus.service.Object):
    def __init__(self, connection, address):
        super().__init__(connection, "/org/example/Test")
        self.address = address
        self.mode = "active"
        self.queries = 0
        self.revision = 0
        self.connections = {}
        self.objects = {}
        self.spoof = None
        self.client = None
        self.client_binary = None
        self.client_environment = None
        self.restart(SESSION)
        self.restart(SEAT)

    def restart(self, name):
        if name == SEAT and self.spoof is not None:
            self.spoof.terminate()
            self.spoof.wait()
            self.spoof.stdout.close()
            self.spoof = None
        if name in self.connections:
            self.connections[name].release_name(name)
            self.objects[name].remove_from_connection()
        connection = dbus.bus.BusConnection(self.address)
        connection.request_name(name, dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
        self.connections[name] = connection
        self.objects[name] = Session(connection, self) if name == SESSION else Seat(connection, self)

    @dbus.service.method("org.example.SGLoginTest")
    def StartClient(self):
        assert self.client is None
        self.client = subprocess.Popen([self.client_binary, "--client"],
                                       env=self.client_environment,
                                       user=65534, group=65534, extra_groups=[])

    @dbus.service.method("org.example.SGLoginTest", out_signature="i")
    def ClientStatus(self):
        result = self.client.poll()
        return -999 if result is None else result

    @dbus.service.method("org.example.SGLoginTest", out_signature="u")
    def Queries(self):
        return self.queries

    @dbus.service.method("org.example.SGLoginTest", in_signature="s")
    def SetState(self, mode):
        if mode in ("seat-restart", "session-restart"):
            self.restart(SEAT if mode == "seat-restart" else SESSION)
        elif mode == "spoof-seat":
            self.connections.pop(SEAT).release_name(SEAT)
            self.objects.pop(SEAT).remove_from_connection()
            self.spoof = subprocess.Popen(
                [sys.executable, "-c",
                 "import dbus,sys,time; c=dbus.bus.BusConnection(sys.argv[1]); "
                 "c.request_name(sys.argv[2],dbus.bus.NAME_FLAG_DO_NOT_QUEUE); "
                 "print('ready',flush=True); time.sleep(60)", self.address, SEAT],
                user=65534, group=65534, extra_groups=[], stdout=subprocess.PIPE, text=True)
            assert self.spoof.stdout.readline().strip() == "ready"
        else:
            self.mode = str(mode)
        self.revision += 1
        if SEAT in self.objects:
            self.objects[SEAT].StateChanged(self.revision)
        if mode == "absent":
            self.objects[SESSION].SessionRemoved(SID, 1000)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("binary")
    parser.add_argument("--action-dir", type=pathlib.Path,
                        help="explicit empty disposable /tmp action directory compiled into this test build")
    args = parser.parse_args()
    if os.geteuid() != 0:
        print("SKIP: root-owned private services required", file=sys.stderr)
        return 77
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    with tempfile.TemporaryDirectory(prefix="polkit-sglogin-") as directory, contextlib.ExitStack() as cleanup:
        if args.action_dir is not None:
            actions = args.action_dir.resolve()
            if not str(actions).startswith("/tmp/") or not actions.is_dir() or any(actions.iterdir()):
                raise SystemExit("--action-dir must name an existing empty disposable /tmp directory")
            policy = actions / "sglogin-test.policy"
            policy.write_bytes((pathlib.Path(__file__).resolve().parents[1] / "data/sglogin.policy").read_bytes())
            cleanup.callback(policy.unlink)
        # Only this deliberately permissive fake bus is exposed to the spoofing
        # UID; it has no installed policy or connection to a real system bus.
        pathlib.Path(directory).chmod(0o755)
        address = "unix:path=" + directory + "/bus"
        config = pathlib.Path(directory) / "bus.conf"
        config.write_text(f'''<busconfig><listen>{address}</listen><auth>EXTERNAL</auth>
<policy context="default"><allow user="*"/><allow own="*"/>
<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
        bus = subprocess.Popen(["dbus-daemon", "--nofork", "--config-file=" + str(config)])
        test = None
        try:
            for _ in range(200):
                if pathlib.Path(directory, "bus").exists():
                    break
                time.sleep(0.005)
            connection = dbus.bus.BusConnection(address)
            connection.request_name("org.example.SGLoginTest", dbus.bus.NAME_FLAG_DO_NOT_QUEUE)
            control = Control(connection, address)
            environment = os.environ.copy()
            environment["DBUS_SYSTEM_BUS_ADDRESS"] = address
            if args.action_dir is not None:
                environment["POLKIT_SGLOGIN_FULL_POLICY"] = "1"
            # The caller's checkout may be private (e.g. a mode-0700 home).
            # Copy the supplied binary and its two provider libraries, without
            # opening the checkout or changing its permissions for another UID.
            binary = pathlib.Path(args.binary).resolve()
            client_dir = pathlib.Path(directory) / "client"
            client_dir.mkdir(mode=0o755)
            shutil.copy2(binary, client_dir / "test-provider")
            linked = subprocess.check_output(["ldd", str(binary)], text=True)
            for name in ("libpolkit-gobject-1.so.0", "libsglogin.so.0"):
                match = re.search(r"^\s*" + re.escape(name) + r"\s+=>\s+(\S+)", linked, re.MULTILINE)
                if match is None:
                    raise RuntimeError("missing provider test dependency: " + name)
                shutil.copy2(match.group(1), client_dir / name)
            control.client_binary = str(client_dir / "test-provider")
            control.client_environment = environment.copy()
            control.client_environment["LD_LIBRARY_PATH"] = str(client_dir)
            test = subprocess.Popen([str(binary)], env=environment)
            loop = GLib.MainLoop()
            def finished():
                if test.poll() is not None:
                    loop.quit()
                    return GLib.SOURCE_REMOVE
                return GLib.SOURCE_CONTINUE
            GLib.timeout_add(10, finished)  # Harness process supervision, not provider polling.
            GLib.timeout_add_seconds(45, lambda: (test.kill(), loop.quit(), GLib.SOURCE_REMOVE)[-1])
            loop.run()
            return test.wait()
        finally:
            if test is not None and test.poll() is None:
                test.kill()
                test.wait()
            if 'control' in locals() and control.client is not None and control.client.poll() is None:
                control.client.kill()
                control.client.wait()
            if 'control' in locals() and control.spoof is not None:
                control.spoof.terminate()
                control.spoof.wait()
                control.spoof.stdout.close()
            bus.terminate()
            bus.wait()


if __name__ == "__main__":
    raise SystemExit(main())
