"""Liminal's services on Windows containers (0.3.0; liminal-libs 1.93.0's one "run a service" interface;
service-containers-design §4.2 and the networking design's §5.2): the library's `DockerRuntime` at a Windows engine's
own pipe, with what Windows containers do otherwise.

- **docker.exe, run directly** (`docker.exe -H npipe:////./pipe/<pipe> ...`), windowless, never inside a PowerShell
  script: a script is a command line, and a secret's value would ride on it. There is no UAC path for a service's
  commands: a pipe this user may not open is refused in docker's own words (its rights are Docker's: docker-users), so
  a value given by environment is never handed to an elevation.
- **Windows images alone.** Each part's pin is judged by its `os_build` against this Windows' build (the plugin's own
  `runs_here`, Microsoft's version compatibility): process isolation where that build runs that way here, Hyper-V
  isolation otherwise (it needs Hyper-V), and an image newer than this Windows cannot run. A Linux image cannot.
  GoCD and Buildbot are "not yet": their makers publish Linux images alone (decision 14 a).
- **The engine's one NAT network** (N26). Windows holds one NAT network per host, and a second leaves WinNAT in an
  unknown state, so Liminal makes none and removes none: every service joins the engine's own `nat`, read at each
  plan, and the fit says "differs" (one service can reach another's ports), which asks accept_differs. Since 0.3.1
  (liminal-libs 1.95.0's `Runtime.network_want`) the firewall is told so in the library's words: the network `nat`,
  its prefix as read (`found`), HNS giving the addresses, shared by every service, no route (this PC holds the NAT
  gateway on vEthernet (nat)); the base names `nat` on the install line and never drops it. HNS gives the addresses (no --ip:
  whether it works on the engine's own NAT network is still to check), and Docker's own names on a NAT network find
  the containers by their names (no network aliases there).
- **Ports** are WinNAT's mappings on every IPv4 address of this PC: Windows' NAT takes no host address, so a port
  meant for this PC alone is published on every address too ("differs", said), and Windows Firewall decides who
  reaches it.
- **Backups and files** through the image's own tar.exe and cmd (Server Core and Nano Server have both); a rollback's
  emptying of a volume through the image's PowerShell (Server Core's)."""
from __future__ import annotations

import io
import json
import os
import re
import subprocess
import tarfile
import threading
from pathlib import Path
from typing import Mapping

from liminal_libs.instances import Refusal
from liminal_libs.machines.containerhost import Create
from liminal_libs.machines.containers import Aspect, Fit, ImagePin, ServiceSpec
from liminal_libs.machines.dockerruntime import BACKUP_S, CHANGE_S, DockerFailed, DockerRuntime, _label_args, _labelled_spec
from liminal_libs.proc import no_window

from .engines import build_of, runs_here, server_name

NAT = "nat"  # the engine's own NAT network (HNS makes it when the docker service starts)
NAT_BRIDGE = "vEthernet (nat)"
NOT_YET = {  # decision 14 a: no maker publishes a Windows image for these, so they wait for images built here
    "gocd": "not yet: GoCD's makers publish its server for Linux alone (linux/amd64, linux/arm64); Windows images built "
            "here from pinned downloads come later (decision 14 a)",
    "buildbot": "not yet: Buildbot's makers publish its master for Linux alone (linux/amd64); Windows images built here "
                "from pinned downloads come later (decision 14 a)",
}
NO_NAT_WORDS = ("the engine's nat network is not there now (HNS makes it when the docker service starts): Liminal never "
                "makes one, since Windows holds one NAT network per host and a second leaves it in an unknown state")
SHARED_WORDS = ("it joins the engine's one NAT network ({prefix}), which every Windows-containers service shares: one "
                "service can reach another's ports there (Windows holds one NAT network per host, so Liminal makes none; "
                "N26). HNS gives its address; Docker's own names find it by its container's name")
HOST_ADDRESS_WORDS = ("Windows' NAT takes no host address, so {ports} meant for this PC alone is published on every "
                      "address of this PC too: Windows Firewall decides who reaches it (no rule of Liminal's lets your "
                      "network in)")
LAN_WORDS = ("WinNAT publishes it on every IPv4 address of this PC; Windows Firewall decides whether your network reaches "
             "it (its rule svc-…, offered on the firewall's page)")
SIZE_WORDS = "Server Core images are several GB"
TAR_ENTRY = "tar"  # Windows' own tar.exe (bsdtar, in System32 since build 17063), found on the image's PATH
WIN_PATH = re.compile(r"^[A-Za-z]:[\\/]")
WATCH_S = 0.25


# -- the windowless runner ----------------------------------------------------------------------------------------------
def _text(raw) -> str:
    return raw if isinstance(raw, str) else (raw or b"").decode("utf-8", "replace")


def _dropped(env: Mapping) -> dict:
    """A child's environment without Liminal's own variables (LIMINAL_*) and the pairs the installed plugins declare
    (their keys: on Windows user variables every process inherits)."""
    try:
        from liminal_libs.sources.registry import variables

        declared = set(variables() or ())
    except Exception:  # noqa: BLE001 - a registry that cannot say: Liminal's own names still go
        declared = set()
    return {k: v for k, v in env.items() if not k.upper().startswith("LIMINAL_") and k not in declared}


def service_run(args, timeout: float, stdin: bytes | None = None, env: Mapping | None = None, binary: bool = False,
                out: str | None = None):
    """A service's docker.exe command (DockerRuntime's runner): run directly, without a window and without this
    process's standard input; `stdin` given to it; `env` laid over its environment (a secret's value travels there
    alone, never on its command line); its output as bytes (`binary`) or written to the file `out` (a backup).
    (exit code, output, errors)."""
    args = [str(a) for a in args]
    environment = {**_dropped(os.environ), **dict(env or {})}
    feed = {"input": stdin} if stdin is not None else {"stdin": subprocess.DEVNULL}
    try:
        if out:
            with open(out, "wb") as sink:
                done = subprocess.run(args, stdout=sink, stderr=subprocess.PIPE, timeout=timeout, env=environment,
                                      **feed, **no_window())
            return done.returncode, b"", _text(done.stderr)
        done = subprocess.run(args, capture_output=True, timeout=timeout, env=environment, **feed, **no_window())
    except subprocess.TimeoutExpired:
        raise DockerFailed(f"docker {args[3] if len(args) > 3 else ''} took more than {timeout:g} s") from None
    except OSError as e:
        raise DockerFailed(f"docker.exe could not run: {e}") from None
    return done.returncode, (done.stdout or b"") if binary else _text(done.stdout), _text(done.stderr)


def stream(args, timeout: float, line, stop=None) -> tuple[int, str]:
    """A pull, windowless, each line it prints given to `line` as it comes; killed past `timeout`, or once `stop()`
    says so (looked at every WATCH_S). (exit code, its errors)."""
    args = [str(a) for a in args]
    try:
        proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
                                env=_dropped(os.environ), **no_window())
    except OSError as e:
        raise DockerFailed(f"docker.exe could not run: {e}") from None
    errors: list[bytes] = []
    reader = threading.Thread(target=lambda: errors.append(proc.stderr.read()), name="wincont-pull-errors", daemon=True)
    reader.start()
    ended = threading.Event()
    asked = threading.Event()
    timer = threading.Timer(timeout, proc.kill)
    timer.daemon = True
    timer.start()

    def watch() -> None:
        while not ended.wait(WATCH_S):
            try:
                if stop():
                    asked.set()
                    proc.kill()
                    return
            except Exception:  # noqa: BLE001 - a stop that cannot say is not asked
                pass
    if stop is not None:
        threading.Thread(target=watch, name="wincont-pull-stop", daemon=True).start()
    try:
        for raw in iter(proc.stdout.readline, b""):
            got = _text(raw).rstrip("\r\n")
            if got.strip():
                line(got[:2000])
        proc.wait()
    finally:
        ended.set()
        timer.cancel()
        reader.join(5)
    if asked.is_set():
        raise DockerFailed("the pull was asked to stop: stopped")
    return proc.returncode, _text(b"".join(errors))


# -- which image runs here, and how ---------------------------------------------------------------------------------------
def isolation_for(host_build: int, client: bool, hyperv: bool, image_build: int) -> tuple[str, str]:
    """(isolation, words) for an image of `image_build` here: "process", "hyperv", or "" with why it cannot run."""
    if not image_build:
        return "", "its Windows build is not pinned (os_build): which isolation it needs here cannot be said"
    if not host_build:
        return "", "this Windows' build was not read: which isolation the image needs cannot be said"
    said = runs_here(host_build, client, image_build)
    name = server_name(image_build) or f"build {image_build}"
    if said.startswith("not here"):
        return "", f"{name}'s image (build {image_build}) is newer than this Windows (build {host_build}): it cannot run"
    if said.startswith("process"):
        return "process", f"process isolation: {name}'s image shares this Windows' kernel (build {host_build})"
    if not hyperv:
        return "", (f"{name}'s image (build {image_build}) needs Hyper-V isolation on this Windows (build {host_build}), "
                    "and Hyper-V is off")
    return "hyperv", (f"Hyper-V isolation: {name}'s image (build {image_build}) runs in a utility VM of its own on this "
                      f"Windows (build {host_build}): more memory, a slower start")


def choose_pin(pins, host_build: int, client: bool, hyperv: bool) -> ImagePin | None:
    """Of a service's Windows pins (one per Windows Server build: ltsc2022, ltsc2025), the one this Windows runs best:
    process isolation first, then the newest that runs with Hyper-V isolation; None when none runs here. The plugin's
    own, for its fit: a service plugin picks with liminal-libs 1.95.0's `containers.choose_pin(pins,
    options["target"])` at Install… (each target says its `os_build` and `isolation` since 0.3.1)."""
    best = None
    for raw in pins:
        pin = raw if isinstance(raw, ImagePin) else ImagePin.of(raw)
        iso, _ = isolation_for(host_build, client, hyperv, pin.os_build)
        if not iso:
            continue
        rank = (iso == "process", pin.os_build)
        if best is None or rank > best[0]:
            best = (rank, pin)
    return best[1] if best else None


def win_path(path: str) -> str:
    """A path inside a Windows container, as Windows writes it (C:\\ProgramData\\...): a volume's path joined with a
    file's by the base with "/"."""
    p = str(path or "").replace("/", "\\")
    return re.sub(r"\\{2,}", r"\\", p)


def _tar_name(path: str) -> str:
    """A path inside the container as a tar member's name, relative to C:\\ (docker cp - <c>:C:\\)."""
    p = str(path or "").replace("\\", "/")
    if not WIN_PATH.match(p):
        raise Refusal(f"{p[:80]} is not a path on the container's own drive (C:\\...)")
    if p[0].upper() != "C":
        raise Refusal(f"{p[:80]}: a Windows container has its C: drive alone")
    return re.sub(r"/{2,}", "/", p[3:]).lstrip("/")


class WindowsRuntime(DockerRuntime):
    """One Windows engine at its pipe: docker.exe -H npipe:////./pipe/<pipe>, through the plugin's windowless runner.
    `host_build`, `client` and `hyperv`: this Windows' build, whether it is a client edition, whether Hyper-V is on."""

    mechanism = "docker-windows"

    def __init__(self, exe: str, endpoint: str, runner, streamer=None, *, version: str = "", host_build: int = 0,
                 client: bool = True, hyperv: bool = False, where_data: str = "", lan_words: str = LAN_WORDS):
        if not exe or not str(endpoint).startswith("npipe:"):
            raise Refusal("a Windows engine is reached at its own pipe (npipe:) by docker.exe alone")
        # 0.3.1: read_root (liminal-libs 1.95.0): docker info's DockerRootDir (C:\ProgramData\docker) said on each plan
        super().__init__([exe, "-H", endpoint], runner, streamer, version=version, arch="amd64", wsl=False, trusted=(),
                         lan=("direct", lan_words), where_data=where_data or "in the engine's data folder",
                         read_root=True)
        self.host_build, self.client, self.hyperv = int(host_build or 0), bool(client), bool(hyperv)

    # -- what it reads ----------------------------------------------------------------------------------------------------
    def isolation(self, pin: ImagePin) -> tuple[str, str]:
        return isolation_for(self.host_build, self.client, self.hyperv, pin.os_build)

    def nat(self) -> dict | None:
        """The engine's own NAT network as it is now ({"subnet", "gateway", "members"}); None when it is not there."""
        found = self._inspect("network", NAT)
        if not found:
            return None
        n = found[0]
        ipam = [c for c in ((n.get("IPAM") or {}).get("Config") or []) if isinstance(c, dict)]
        return {"subnet": str((ipam[0] if ipam else {}).get("Subnet") or ""),
                "gateway": str((ipam[0] if ipam else {}).get("Gateway") or ""),
                "members": dict(n.get("Containers") or {})}

    def network_want(self, spec: ServiceSpec | None, sid: str) -> dict:
        """0.3.1 (liminal-libs 1.95.0): what the engine has for every service's network, laid over the base's Want: its
        one `nat`, its prefix as read now (`found`, reserved as it is and never handed out of the pool), HNS giving the
        addresses, shared by every service (never dropped), and no route (the Windows firewall's own stack). With no
        nat there the prefix is not said, and the firewall refuses the shared network in words."""
        want = {"network": NAT, "assigns": "hns", "shared": True, "route": False}
        nat = self.nat()
        if nat is not None and nat["subnet"]:
            want["found"] = nat["subnet"]
        return want

    def fit(self, spec: ServiceSpec | None) -> Fit:
        aspects: dict[str, Aspect] = {}
        nat = self.nat()
        if nat is None:
            aspects["network"] = Aspect("cannot", NO_NAT_WORDS)
        else:
            aspects["network"] = Aspect("differs", SHARED_WORDS.format(prefix=nat["subnet"] or "its prefix not read"))
        if spec is None:
            return Fit.judged(aspects)
        if spec.owner in NOT_YET:
            aspects["image"] = Aspect("cannot", NOT_YET[spec.owner])
            return Fit.judged(aspects)
        images, cannot = [], []
        for p in spec.parts:
            pin = p.image
            if pin.system != "windows":
                cannot.append(f"{pin.ref} is a Linux image: Windows containers run Windows images alone")
                continue
            if not any(x == "windows/amd64" for x in pin.platforms):
                cannot.append(f"{pin.ref} is not published for windows/amd64")
                continue
            iso, words = self.isolation(pin)
            if not iso:
                cannot.append(words)
                continue
            size = f"{pin.size / 1e9:,.1f} GB" if pin.size else "its size not pinned"
            images.append(f"{p.name}: {words}; {size} ({SIZE_WORDS})")
        aspects["image"] = Aspect("cannot", "; ".join(cannot)) if cannot else Aspect("exact", "; ".join(images))
        here_only = [f"{x.protocol.upper()} {x.host}" for x in spec.ports() if not x.lan]
        aspects["ports"] = (Aspect("differs", HOST_ADDRESS_WORDS.format(ports=", ".join(here_only))) if here_only else
                            Aspect("exact", "WinNAT's mappings on this PC's IPv4 addresses"))
        if any(p.shm for p in spec.parts):
            aspects["memory"] = Aspect("differs", "a shared-memory size is Linux's: Windows containers take none, so "
                                                  "it is left out")
        aspects["volumes"] = Aspect("exact", f"named volumes, {self.where_data}")
        aspects["lifecycle"] = Aspect("exact", "--restart no: it stays stopped through an engine restart")
        return Fit.judged(aspects)

    def segments(self) -> list[dict]:
        """The engine's one NAT network, shared (found, not Liminal's: no sid), its members by their containers'
        labels; [] when it is not there."""
        nat = self.nat()
        if nat is None:
            return []
        services = {}
        for row in self.hosted():
            for part in row["parts"]:
                services[part["container"]] = (row["sid"], part["name"])
        members = []
        for _cid, m in nat["members"].items():
            cname = str(m.get("Name") or "")
            sid, part = services.get(cname, ("", ""))
            members.append({"sid": sid, "part": part, "container": cname, "mac": str(m.get("MacAddress") or ""),
                            "ipv4": str(m.get("IPv4Address") or "").split("/")[0], "assigned": "hns"})
        return [{"segment": NAT, "network": NAT, "kind": "hns-nat", "bridge": NAT_BRIDGE, "sid": "", "platform": "",
                 "shared": True, "subnets": [nat["subnet"]] if nat["subnet"] else [],
                 "gateways": [nat["gateway"]] if nat["gateway"] else [], "trusted": [], "members": members}]

    def service_of(self, container: str) -> str:
        """The service a container is, by its liminal.service label ("" for none)."""
        found = self._inspect("container", container)
        return str(((found[0].get("Config") or {}).get("Labels") or {}).get("liminal.service") or "") if found else ""

    def read(self, container: str, path: str, most: int) -> bytes:
        path = win_path(path)
        st = self.state(container) or {}
        if st.get("state") == "running":
            _, out, _ = self.run("exec", container, "cmd", "/S", "/C", "type", path, binary=True)
            return bytes(out or b"")[:most]
        _, out, _ = self.run("cp", f"{container}:{path}", "-", binary=True)
        with tarfile.open(fileobj=io.BytesIO(bytes(out or b"")), mode="r:") as tar:
            member = next((m for m in tar.getmembers() if m.isfile()), None)
            f = tar.extractfile(member) if member is not None else None
            return f.read(most) if f is not None else b""

    def _image_isolation(self, pinned: str) -> str:
        """The isolation a throwaway container of `pinned` (an update's backup, a rollback's restore) gets here: its
        Windows build read from the image itself."""
        _, out, _ = self.run("image", "inspect", "--format", "{{.OsVersion}}", pinned)
        iso, words = isolation_for(self.host_build, self.client, self.hyperv, build_of(str(out or "").strip()))
        if not iso:
            raise Refusal(f"{pinned.split('@', 1)[0]}: {words}")
        return iso

    # -- what it changes, inside an approved plan's work alone ----------------------------------------------------------
    def make_network(self, name: str, grant: Mapping, labels: Mapping) -> bool:
        """None is made: the engine's own nat is joined (found, so False), and refused when it is not there."""
        if self.nat() is None:
            raise Refusal(NO_NAT_WORDS)
        return False

    def drop_network(self, name: str) -> None:
        raise Refusal("the engine's nat network is every Windows-containers service's: it stays (Liminal never makes or "
                      "removes a NAT network)")

    def create(self, c: Create) -> None:
        part = c.part
        iso, words = self.isolation(part.image)
        if not iso:
            raise Refusal(f"{c.name}: {words}")
        if c.network != NAT:  # 0.3.1: the base names the network network_want gives; any other is never joined
            raise Refusal(f"{c.name}: a Windows container joins the engine's own {NAT} network alone, not "
                          f"{str(c.network)[:60]}")
        labels = dict(c.labels)
        if "liminal.spec" in labels:
            labels["liminal.spec"] = _labelled_spec(ServiceSpec.of(json.loads(labels["liminal.spec"])))
        args = ["create", "--name", c.name, *_label_args(labels), "--restart", "no", "--isolation", iso,
                "--memory", str(part.memory)]
        if part.cpus:
            args += ["--cpus", f"{part.cpus:g}"]
        args += ["--hostname", c.hostname or part.name, "--network", c.network]
        for h in c.add_hosts:
            args += ["--add-host", h]
        for p in c.ports:
            args += ["-p", f"{p.host}:{p.container}/{p.protocol}"]
        for vol, path in c.volumes:
            args += ["-v", f"{vol}:{win_path(path)}"]
        for k, v in c.env.items():
            args += ["-e", f"{k}={v}"]
        for k in c.secret_env:
            args += ["-e", k]
        args += [c.pinned, *part.command]
        self.run(*args, timeout=CHANGE_S, env=self._env(c.secret_env))

    def seed(self, container: str, seeds, line) -> None:
        """Each seed into the new volume as one tar on standard input, its names relative to C:\\ (a Windows volume
        keeps no uid: a seed's owner is left to the image)."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for path, seed, _owner in seeds:
                raw = seed.text.encode("utf-8")
                info = tarfile.TarInfo(_tar_name(path))
                info.size, info.mode, info.mtime = len(raw), seed.mode, 0
                tar.addfile(info, io.BytesIO(raw))
        self.run("cp", "-", f"{container}:C:\\", stdin=buf.getvalue(), timeout=CHANGE_S)

    def backup(self, volume: str, pinned: str, into: Path, line, cancelled) -> int:
        iso = self._image_isolation(pinned)
        self.run("run", "--rm", "--network", "none", "--isolation", iso, "--entrypoint", TAR_ENTRY,
                 "-v", f"{volume}:C:\\v:ro", pinned, "-C", "C:\\v", "-cf", "-", ".", timeout=BACKUP_S, binary=True,
                 out=str(into))
        try:
            return Path(into).stat().st_size
        except OSError:
            return 0

    def restore(self, volume: str, pinned: str, source: Path, line, cancelled) -> int:
        raw = Path(source).read_bytes()
        iso = self._image_isolation(pinned)
        self.run("run", "--rm", "--network", "none", "--isolation", iso, "--entrypoint", "powershell",
                 "-v", f"{volume}:C:\\v", pinned, "-NoProfile", "-NonInteractive", "-Command",
                 "Get-ChildItem -LiteralPath C:\\v -Force | Remove-Item -Recurse -Force", timeout=BACKUP_S)
        self.run("run", "--rm", "-i", "--network", "none", "--isolation", iso, "--entrypoint", TAR_ENTRY,
                 "-v", f"{volume}:C:\\v", pinned, "-C", "C:\\v", "-xf", "-", timeout=BACKUP_S, stdin=raw)
        return len(raw)
