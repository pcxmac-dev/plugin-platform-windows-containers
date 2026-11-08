"""Windows containers for Liminal (the user, 2026-11-08: "also if there is a windows container format, a plugin for that,
... and a plugin for windows virtualization too"; earlier: "basically the platform is the interface for the
software/hardware which facilitates the liminal framework"): Windows' own containers on this PC, read and driven through
PowerShell (the library's machines.windows.PowerShell, windowless).

Windows has two: Windows Server containers (the Containers feature; images made from Windows Server Core or Nano Server,
run by an engine through the Host Compute Service, each with process isolation, sharing this Windows' kernel, or Hyper-V
isolation, a utility VM of its own: Windows 10 and 11 default to Hyper-V's), and Windows Sandbox (a throwaway Windows in a
window, Hyper-V isolated, configured by a .wsb file). The plugin reads the features (Containers, Windows Sandbox, Hyper-V),
the services under them (the Host Compute Service vmcompute, the Host Network Service hns), the engines that run Windows
containers (Docker's at each of its pipes: Docker Engine, Docker Desktop switched to Windows containers; containerd through
nerdctl) with their containers (their isolation) and images (the Windows build each was made from, and whether this
Windows runs it with process isolation), Windows Sandbox's .wsb configurations and the sandboxes running, and, given the
rights, the compute systems the Host Compute Service runs (hcsdiag). And, each confirmed on the platform's page: a
container started, stopped or removed; a sandbox launched (with a .wsb's settings said first) or closed.

Present when this Windows has Windows containers or Windows Sandbox turned on; not for Linux or macOS. What was read is kept
READ_S; a change reads again. Nothing runs between asks.

    python -m plugin_platform_windows_containers status | engines | containers | images | sandboxes
                                                 | start CONTAINER | stop CONTAINER | remove CONTAINER [--force]
                                                 | sandbox [FILE.wsb] [--accept] | close-sandbox ID     ([--engine KEY])
"""
from __future__ import annotations

import json
import os
import re
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

from liminal_libs.machines.plugin import CommandError, MachinePlugin
from liminal_libs.machines.windows import ELEVATE_VAR, PowerShell

from . import scripts, wsb
from .engines import (CONTAINER_ID, Container, Engine, compute_systems, containerd_engine, denied_words, docker_engine, json_doc,
                      native, runs_here, server_name, short, words)

__version__ = "0.1.0"
READ_S = 10.0  # what was read is kept this long: the page's status, the tray's presence and a hook's look share it
ON, OFF, ABSENT = 1, 2, 3  # Win32_OptionalFeature.InstallState
CONTAINERS, SANDBOX, HYPERV = "Containers", "Containers-DisposableClientVM", "Microsoft-Hyper-V"
GROUP = "Hyper-V Administrators"
GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DOCKER_RIGHTS = ("join docker-users (Docker Desktop's group, or the one the engine's daemon.json names; then sign out of "
                 "Windows and in again), or run the platform as administrator")
SYSTEMS = {"linux": "Linux", "darwin": "macOS"}
ISOLATIONS = {"hyperv": "Hyper-V", "process": "process"}
NO_ENGINE = ("no engine for Windows containers is installed: Docker Desktop (switched to Windows containers), Docker Engine "
             "(Microsoft's install-docker-ce.ps1) or containerd with nerdctl runs them")


class Refusal(ValueError):
    """A change not made, and why: nothing was asked of the engine or of Windows Sandbox. `accept`: the argument that, set,
    makes it anyway (a running container removed, a sandbox launched with a .wsb's settings); the platform's page asks it
    as a second, explicit confirmation."""

    def __init__(self, message: str, accept: str | None = None):
        super().__init__(message)
        self.accept = accept


def cell(text, sub: str | None = None):
    return {"text": text, "sub": sub} if sub else text


def plural(n: int, word: str, many: str | None = None) -> str:
    return f"{n} {word if n == 1 else many or word + 's'}"


def truthy(v) -> bool:
    return v if isinstance(v, bool) else str(v if v is not None else "").strip().lower() in ("1", "true", "yes", "on")


def windows_words(w: dict) -> str:
    if not w:
        return ""
    caption = str(w.get("Caption") or "Windows").replace("Microsoft ", "")
    build = ".".join(x for x in (str(w.get("Build") or ""), str(w.get("Revision") or "")) if x)
    return " ".join(x for x in (caption, str(w.get("Release") or ""), f"(build {build})" if build else "") if x)


def turn_on(*names: str) -> str:
    """How a Windows feature is turned on, in words."""
    return (f"Windows Features (optionalfeatures.exe) turns {'them' if len(names) > 1 else 'it'} on, as administrator "
            f"(Enable-WindowsOptionalFeature -Online -FeatureName {', '.join(names)} -All), then a restart")


def isolation_words(isolation: str) -> str:
    return ISOLATIONS.get(str(isolation or "").lower(), str(isolation or ""))


# -- what was read -----------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class Sandbox:
    """Windows Sandbox as read: its command (wsb: Windows 11 24H2's), its program (WindowsSandbox.exe), its processes
    running, and the sandboxes wsb lists ({id, status, uptime})."""

    cli: str = ""
    classic: str = ""
    processes: tuple = ()
    running: tuple = ()
    error: str = ""

    @property
    def program(self) -> bool:
        return bool(self.cli or self.classic)


def sandboxes_listed(d) -> tuple[tuple, str]:
    """`wsb --raw list`'s sandboxes ({"WindowsSandboxEnvironments": [{Id, Status, Uptime}]}; its table read for the Ids
    when it is not JSON), and why it could not say."""
    code, out, err = native(d)
    if code is None:
        return (), ""
    if code != 0:
        return (), words(code, out, err)
    data = json_doc(out)
    found = data.get("WindowsSandboxEnvironments") if data else None
    if isinstance(found, list):
        return tuple({"id": str(e.get("Id") or ""), "status": str(e.get("Status") or ""), "uptime": str(e.get("Uptime") or "")}
                     for e in found if isinstance(e, dict) and e.get("Id")), ""
    rows = []
    for line in out.splitlines():
        m = GUID.search(line)
        if m:
            rest = line[m.end():].split()
            rows.append({"id": m.group(0), "status": rest[0] if rest else "", "uptime": " ".join(rest[1:])})
    return tuple(rows), ""


@dataclass(frozen=True)
class Reading:
    """One read (scripts.READ): the rights, Windows, the features and services, the engines with their containers and
    images, Windows Sandbox, the compute systems (None: not asked); `error`: why nothing could be read at all."""

    elevated: bool = False
    group: bool = False
    windows: dict = field(default_factory=dict)
    hypervisor: bool | None = None
    features: dict = field(default_factory=dict)
    features_read: bool = False
    services: dict = field(default_factory=dict)  # name -> {Status, StartType, Title}
    docker: str = ""
    nerdctl: str = ""
    hcsdiag: str = ""
    pipes: tuple = ()
    contexts_error: str = ""
    engines: tuple = ()
    sandbox: Sandbox = field(default_factory=Sandbox)
    hcs: tuple | None = None
    hcs_error: str = ""
    error: str = ""

    @classmethod
    def of(cls, row: dict) -> "Reading":
        def rows(key: str) -> list:
            found = row.get(key) or []
            return [r for r in (found if isinstance(found, list) else [found]) if isinstance(r, dict)]

        services = {str(s.get("Name")): s for s in rows("Services")}
        docker, nerdctl = str(row.get("Docker") or ""), str(row.get("Nerdctl") or "")
        desktop = "com.docker.service" in services
        engines = [docker_engine(e, docker, desktop) for e in rows("Engines")]
        if isinstance(row.get("Containerd"), dict) and nerdctl:
            engines.append(containerd_engine(row["Containerd"], nerdctl))
        code, out, err = native(row.get("Contexts"))
        s = row.get("Sandbox") if isinstance(row.get("Sandbox"), dict) else {}
        running, list_error = sandboxes_listed(s.get("List"))
        processes = s.get("Running") or []
        sandbox = Sandbox(cli=str(s.get("Cli") or ""), classic=str(s.get("Classic") or ""),
                          processes=tuple(str(p) for p in (processes if isinstance(processes, list) else [processes])),
                          running=running, error=list_error)
        hcs_code, hcs_out, hcs_err = native(row.get("Hcs"))
        pipes = row.get("Pipes") or []
        return cls(elevated=bool(row.get("Elevated")), group=bool(row.get("Group")),
                   windows=dict(row.get("Windows") or {}) if isinstance(row.get("Windows"), dict) else {},
                   hypervisor=row.get("Hypervisor") if isinstance(row.get("Hypervisor"), bool) else None,
                   features={str(f.get("Name")): int(f.get("State") or 0) for f in rows("Features")},
                   features_read=bool(row.get("FeaturesRead")), services=services, docker=docker, nerdctl=nerdctl,
                   hcsdiag=str(row.get("Hcsdiag") or ""), pipes=tuple(str(p) for p in (pipes if isinstance(pipes, list) else [pipes])),
                   contexts_error=words(code, out, err) if code not in (None, 0) else "", engines=tuple(engines), sandbox=sandbox,
                   hcs=tuple(compute_systems(hcs_out)) if hcs_code == 0 else None,
                   hcs_error=words(hcs_code, hcs_out, hcs_err) if hcs_code not in (None, 0) else "")

    @property
    def rights(self) -> bool:
        return self.elevated or self.group

    @property
    def host_build(self) -> int:
        b = str(self.windows.get("Build") or "")
        return int(b) if b.isdigit() else 0

    @property
    def client(self) -> bool:
        return str(self.windows.get("Kind") or "Client") == "Client"

    def on(self, feature: str) -> bool:
        return self.features.get(feature) == ON

    @property
    def containers_on(self) -> bool:
        """The Containers feature on (an engine answering for Windows containers where the features could not be read)."""
        return self.on(CONTAINERS) or (not self.features_read and any(e.listed for e in self.engines))

    @property
    def sandbox_on(self) -> bool:
        return self.on(SANDBOX) or (not self.features_read and self.sandbox.program)

    @property
    def listed(self) -> list[Engine]:
        return [e for e in self.engines if e.listed]

    @property
    def containers(self) -> list[Container]:
        return [c for e in self.listed for c in e.containers]

    @property
    def images(self) -> list:
        return [i for e in self.listed for i in e.images]

    def engine(self, key: str) -> Engine | None:
        return next((e for e in self.engines if e.key == key), None)


def validity(r: Reading) -> tuple[bool, bool, str]:
    """(present, valid, why): Windows containers or Windows Sandbox turned on here; why not, in words."""
    if r.error:
        return False, False, f"Windows containers could not be read: {r.error}"
    if r.containers_on or r.sandbox_on:
        return True, True, ""
    states = (r.features.get(CONTAINERS), r.features.get(SANDBOX))
    if r.features_read and all(s in (None, ABSENT) for s in states):
        return False, False, ("this edition of Windows has neither Windows containers nor Windows Sandbox (Windows Home): Pro, "
                              "Enterprise or Education has them")
    return False, False, "Windows containers and Windows Sandbox are off: " + turn_on(CONTAINERS, SANDBOX)


def problems(r: Reading) -> list[str]:
    """What stands in the way while valid, in words."""
    out = []
    if r.containers_on:
        docker = [e for e in r.engines if e.kind == "docker"]
        if not r.listed:
            if not r.docker and not r.nerdctl:
                out.append(NO_ENGINE)
            elif any(e.answers and e.os_type == "linux" for e in docker) and not any(e.windows and e.answers for e in docker):
                out.append("Docker Desktop runs Linux containers now: its menu's Switch to Windows containers (or `docker desktop "
                           "engine use windows`) runs Windows ones")
            elif any(e.denied for e in r.engines):
                out.append(f"the engine's pipe answers administrators and its group only: {DOCKER_RIGHTS}")
            elif r.docker and not docker:
                out.append("Docker is installed but no Docker engine's pipe is open: start Docker Desktop, or the docker service "
                           "(Start-Service docker, as administrator)")
            elif r.engines:
                why = next((e.why for e in r.engines if e.why), "")
                out.append("no engine for Windows containers answers" + (f": {why}" if why else ""))
        if not r.on(HYPERV) and r.client:
            out.append("Hyper-V is off, so Hyper-V isolation (Windows 10 and 11's default) cannot run: process isolation can, "
                       f"for images of this Windows' build ({turn_on(HYPERV)})")
    if r.sandbox_on and not r.sandbox.program:
        out.append("Windows Sandbox is on but its program was not found: a restart finishes turning it on")
    return out


def summary(r: Reading, valid: bool, why: str) -> str:
    if not valid:
        return why.split(":")[0] if why else "not present"
    parts = []
    if r.containers_on:
        if r.listed:
            cs = r.containers
            parts.append(f"{plural(len(cs), 'container')}, {sum(1 for c in cs if c.up)} running · {plural(len(r.images), 'image')}")
        else:
            parts.append("containers on, no engine answering")
    else:
        parts.append("containers off")
    if r.sandbox_on:
        running = len(r.sandbox.running) or (1 if r.sandbox.processes else 0)
        parts.append("Windows Sandbox on" + (f", {running} running" if running else ""))
    else:
        parts.append("Windows Sandbox off")
    return " · ".join(parts)


class _Kept:
    """What the plugin keeps between asks, shared by its copies (the registry hands out a shallow one): the last read."""

    def __init__(self):
        self.lock = threading.Lock()
        self.reading: Reading | None = None
        self.at = 0.0


class WindowsContainersPlugin(MachinePlugin):
    """Windows containers and Windows Sandbox on this PC: present when either is turned on."""

    name = "windows-containers"
    title = "Windows containers"
    about = ("Windows' own containers on this PC: the features, the engines and their containers (process or Hyper-V "
             "isolation) and images, Windows Sandbox and its .wsb files; a container started, stopped or removed, a sandbox "
             "launched or closed, each change confirmed")
    api = "2.1"
    order = 745
    ICON = "scan"  # a box's corners: what runs inside is kept within them
    HOOKS = (*MachinePlugin.HOOKS, "engines", "containers", "images", "sandboxes", "start_container", "stop_container",
             "remove_container", "launch_sandbox", "stop_sandbox")

    def __init__(self, powershell: PowerShell | None = None, system: str | None = None, env=None, clock=None,
                 folder: Path | None = None, exists=None):
        self.ps = powershell if powershell is not None else PowerShell()
        self._system = sys.platform if system is None else system  # a test's; this machine's otherwise
        self._env = env  # where LIMINAL_ELEVATE is read (a test's; os.environ otherwise)
        self._clock = clock or time.monotonic
        self._folder = Path(folder) if folder is not None else None  # where .wsb files are looked for (wsb.sandboxes_dir())
        self._exists = exists or os.path.isdir  # a mapped folder checked on this PC (a test's stand-in)
        self._kept = _Kept()

    @property
    def folder(self) -> Path:
        return self._folder if self._folder is not None else wsb.sandboxes_dir()

    # -- what is read ----------------------------------------------------------------------------------------------------
    def not_for_here(self) -> str:
        if self._system.startswith(("win32", "cygwin")):
            return ""
        return f"Windows containers are Windows' own, and this machine runs {SYSTEMS.get(self._system, self._system)}"

    def read(self, fresh: bool = False) -> Reading:
        """Windows containers as they are now (kept READ_S unless `fresh`)."""
        now = self._clock()
        with self._kept.lock:
            kept, at = self._kept.reading, self._kept.at
        if kept is not None and not fresh and now - at < READ_S:
            return kept
        try:
            rows = self.ps.json(scripts.READ, timeout=300)
            r = Reading.of(rows[0] if rows and isinstance(rows[0], dict) else {})
        except (CommandError, ValueError) as e:
            r = Reading(error=str(e) or type(e).__name__)
        with self._kept.lock:
            self._kept.reading, self._kept.at = r, self._clock()
        return r

    def forget(self) -> None:
        with self._kept.lock:
            self._kept.reading, self._kept.at = None, 0.0

    def detach(self) -> None:
        self.forget()
        super().detach()

    def present(self) -> bool:
        return not self.not_for_here() and validity(self.read())[0]

    def usable(self) -> Reading:
        """Read again now, present; CommandError saying why not."""
        note = self.not_for_here()
        if note:
            raise CommandError(note)
        r = self.read(fresh=True)
        _, valid, why = validity(r)
        if not valid:
            raise CommandError(why)
        return r

    def configurations(self) -> list:
        return wsb.listed(self.folder, exists=self._exists)

    def engines(self) -> list[dict]:
        return [e.describe() for e in self.usable().engines]

    def containers(self) -> list[dict]:
        return [c.describe() for c in self.usable().containers]

    def images(self) -> list[dict]:
        r = self.usable()
        return [{**i.describe(), "runsHere": runs_here(r.host_build, r.client, i.build)} for i in r.images]

    def sandboxes(self) -> dict:
        r = self.usable()
        return {"on": r.sandbox_on, "command": r.sandbox.cli, "program": r.sandbox.classic, "running": list(r.sandbox.running),
                "processes": list(r.sandbox.processes), "folder": str(self.folder),
                "configurations": [{"path": str(f), "ok": c is not None and not c.problem, "why": why or (c.problem if c else ""),
                                    "lines": c.lines() if c else []} for f, c, why in self.configurations()]}

    # -- the platform's page ---------------------------------------------------------------------------------------------
    def status(self) -> dict:
        note = self.not_for_here()
        if note:
            return self.not_here_status(note)
        r = self.read()
        present, valid, why = validity(r)
        out: dict = {"present": present, "summary": summary(r, valid, why)}
        out.update(self._facts(r))
        out["valid"], out["why"] = valid, why
        if not valid:
            return out
        configs = self.configurations() if r.sandbox_on else []
        tables = []
        if r.containers_on:
            tables += [engines_table(r), containers_table(r), images_table(r)]
        if r.sandbox_on:
            tables.append(sandbox_table(self.folder, configs, r))
            if r.sandbox.cli:
                tables.append(running_table(r))
        if r.hcs is not None:
            tables.append({"title": "Compute systems", "note": "hcsdiag list: what the Host Compute Service runs (Windows "
                                                               "containers, Windows Sandbox, WSL 2's VM), as it says it",
                           "columns": [{"title": "hcsdiag list"}], "rows": [[line] for line in r.hcs],
                           "empty": "The Host Compute Service runs nothing now."})
        out["tables"] = tables
        out["forms"] = forms(r, configs)
        if r.sandbox_on and r.sandbox.program:
            out["actions"] = [{"form": "sandbox", "title": "Launch Windows Sandbox…",
                               "note": "with a .wsb's settings (said first), or Windows Sandbox's own"}]
        trouble = problems(r)
        if trouble:
            out["problem"] = "; ".join(trouble)
        return out

    def _facts(self, r: Reading) -> dict:
        out: dict = {}
        if r.windows:
            out["windows"] = windows_words(r.windows)

        def feature(name: str) -> str:
            return {ON: "on", OFF: "off", ABSENT: "not in this edition"}.get(r.features.get(name), "not read")
        out["containersFeature"] = feature(CONTAINERS)
        sandbox = feature(SANDBOX)
        if r.on(SANDBOX):
            sandbox += " (its command, wsb: Windows 11 24H2's)" if r.sandbox.cli else " (its program)" if r.sandbox.classic else ""
        out["windowsSandbox"] = sandbox
        out["hyperV"] = feature(HYPERV) + (" (Hyper-V isolation needs it)" if not r.on(HYPERV) else "")
        if r.hypervisor is not None:
            out["hypervisor"] = "running" if r.hypervisor else "not running"
        starts = {"Automatic": "starts with Windows", "Manual": "started when needed", "Disabled": "disabled"}
        for key, name in (("hostComputeService", "vmcompute"), ("hostNetworkService", "hns"), ("dockerService", "docker"),
                          ("dockerDesktopService", "com.docker.service"), ("containerdService", "containerd")):
            s = r.services.get(name)
            if s:
                out[key] = f"{name} {str(s.get('Status')).lower()} ({starts.get(str(s.get('StartType')), str(s.get('StartType')).lower())})"
        out["docker"] = r.docker or "not installed"
        if r.nerdctl:
            out["nerdctl"] = r.nerdctl
        answering = [e for e in r.listed]
        out["engines"] = ("; ".join(f"{e.title} {e.version} at {e.key}" + (f", {isolation_words(e.isolation)} isolation by default"
                                                                           if e.isolation else "") for e in answering)
                          or "none answering for Windows containers")
        if r.host_build:
            out["processIsolationHere"] = process_words(r.host_build, r.client)
        out["rights"] = ("administrator (the platform runs elevated)" if r.elevated else f"a member of {GROUP}" if r.group
                         else f"neither administrator nor a member of {GROUP}")
        if r.hcs is None:
            out["computeSystems"] = (f"not read: {r.hcs_error}" if r.hcs_error else "listed to administrators and Hyper-V "
                                     "Administrators (hcsdiag)" if not r.rights else "not read (no hcsdiag here)")
        env = os.environ if self._env is None else self._env
        prompt = (env.get(ELEVATE_VAR) or "").strip().lower() == "prompt"
        out["aChangeDenied"] = ("is asked again through Windows' prompt (UAC)" if prompt else
                                f"fails, saying how to give it the rights ({ELEVATE_VAR}=prompt: Windows asks, UAC)")
        if r.on(SANDBOX):
            out["sandboxFiles"] = str(self.folder)
        return out

    # -- the changes -----------------------------------------------------------------------------------------------------
    def _container(self, name, engine=None, container_id=None, r: Reading | None = None) -> tuple[Engine, Container]:
        """The container named (by its name or its Id; with the Id, the name must still be its name), on the engine named
        or on the only one that has it, as read again now."""
        r = r if r is not None else self.usable()
        name, key, cid = str(name or "").strip(), str(engine or "").strip(), str(container_id or "").strip().lower()
        if not cid and CONTAINER_ID.match(name.lower()):
            cid, name = name.lower(), ""
        if not name and not cid:
            raise ValueError("which container: its name or its Id")
        if cid and not CONTAINER_ID.match(cid):
            raise ValueError(f"{container_id!r} is not a container's Id (12 to 64 hexadecimal digits)")
        engines = r.listed
        if key:
            engines = [e for e in engines if e.key == key]
            if not engines:
                found = r.engine(key)
                raise ValueError(f"no engine {key} runs Windows containers here" + (f" ({found.why})" if found and found.why else "")
                                 + f": {', '.join(e.key for e in r.listed) or 'none answers'}")
        matches = [(e, c) for e in engines for c in e.containers
                   if ((c.id == cid or (len(cid) < 64 and c.id.startswith(cid))) if cid else c.name == name)]
        if not matches:
            raise ValueError(f"no container {'with the Id ' + cid if cid else 'named ' + name}"
                             + (f" on {key}" if key else "") + ": look again")
        if len(matches) > 1:
            raise ValueError(f"{len(matches)} containers are {'Ids starting ' + cid if cid else 'named ' + name}: name the engine "
                             f"({', '.join(sorted({e.key for e, _ in matches}))}) or the whole Id")
        e, c = matches[0]
        if cid and name and c.name != name:
            raise ValueError(f"the container {short(c.id)} is named {c.name} now, not {name}: look again")
        return e, c

    def _change(self, script: str, timeout: float, elevate: bool = True) -> dict:
        """A change run as the platform runs: what its program said ({Code, Out, Err}). Denied (the engine's pipe is for
        administrators and its group), asked again through Windows' prompt (UAC) when LIMINAL_ELEVATE=prompt, else a
        CommandError saying how to give it the rights. What was read is dropped either way."""
        try:
            try:
                result = self._result(self.ps.run(script, timeout))
            except CommandError as e:
                if not (elevate and (e.denied or denied_words(str(e)))):
                    raise
                result = {"Code": -1, "Out": "", "Err": str(e)}
            if result["Code"] == 0:
                return result
            said = words(result["Code"], result["Out"], result["Err"])
            if elevate and denied_words(said):
                env = os.environ if self._env is None else self._env
                if (env.get(ELEVATE_VAR) or "").strip().lower() == "prompt":
                    result = self._result(self.ps.run_elevated(script, max(timeout, 600.0)))
                    if result["Code"] == 0:
                        return result
                    said = words(result["Code"], result["Out"], result["Err"])
                else:
                    raise CommandError(f"the engine refused it for want of rights: {DOCKER_RIGHTS}; or set {ELEVATE_VAR}=prompt to "
                                       f"be asked (UAC) when a change needs them ({said})", denied=True)
            raise CommandError(said, denied=denied_words(said))
        finally:
            self.forget()

    @staticmethod
    def _result(text: str) -> dict:
        line = next((x for x in str(text or "").splitlines() if x.startswith(scripts.RESULT)), None)
        if line is None:
            raise CommandError("the change said nothing back")
        try:
            data = json.loads(line[len(scripts.RESULT):])
        except ValueError:
            raise CommandError("the change's answer was not read") from None
        code = data.get("Code")
        return {"Code": int(code) if isinstance(code, (int, float)) else -1, "Out": str(data.get("Out") or ""), "Err": str(data.get("Err") or "")}

    def start_container(self, name, engine=None, container_id=None) -> dict:
        """A container that is not running started, as it was made (its image, its isolation, its ports)."""
        e, c = self._container(name, engine, container_id)
        if c.up:
            raise ValueError(f"{c.name} is {c.state}: a container that is not running starts")
        self._change(scripts.container(e.exe, e.endpoint or None, "start", c.id), 150)
        return {"said": f"{c.name} started on {e.title} ({e.key})", "lines": [], "ok": True}

    def stop_container(self, name, engine=None, container_id=None) -> dict:
        """A running container asked to shut down, ended after the engine's time (10 s) if it has not."""
        e, c = self._container(name, engine, container_id)
        if not c.up:
            raise ValueError(f"{c.name} is {c.state}: a running container stops")
        self._change(scripts.container(e.exe, e.endpoint or None, "stop", c.id), 150)
        return {"said": f"{c.name} stopped", "lines": ["its files stay: Start runs it again"], "ok": True}

    def remove_container(self, name, engine=None, container_id=None, accept_force=False) -> dict:
        """A container removed, its image and its named volumes kept; a running one only once `accept_force` is given
        (a second confirmation: it is ended at once)."""
        e, c = self._container(name, engine, container_id)
        if c.state == "removing":
            raise ValueError(f"{c.name} is being removed already")
        force = c.up
        if force and not truthy(accept_force):
            raise Refusal(f"{c.name} was not removed: it is {c.state}, so removing it ends it at once, and what it has not saved "
                          "is lost.", accept="accept_force")
        self._change(scripts.container(e.exe, e.endpoint or None, "rm", c.id, force=force), 150)
        return {"said": f"{c.name} removed", "lines": [f"its image {c.image} stays"], "ok": True}

    def launch_sandbox(self, path=None, accept_settings=False, seen=None) -> dict:
        """Windows Sandbox started: with a .wsb's settings (said and accepted first: `accept_settings`, or `seen`, the file's
        digest as the page showed it) or its own defaults; through wsb (its Id given back, its window opened) or its
        program."""
        r = self.usable()
        if not r.sandbox_on:
            raise CommandError("Windows Sandbox is off: " + turn_on(SANDBOX))
        if not r.sandbox.program:
            raise CommandError("Windows Sandbox's program was not found: a restart finishes turning it on")
        path = str(path or "").strip().strip('"')
        cfg = None
        if path:
            cfg = wsb.read(path, exists=self._exists)
            if cfg.problem:
                raise ValueError(f"{cfg.name} cannot start a sandbox: {cfg.problem}")
            if not truthy(accept_settings) and str(seen or "") != cfg.digest:
                raise Refusal(f"{cfg.name} was not launched yet, its settings being said first. {cfg.words()}", accept="accept_settings")
            if r.sandbox.cli and len(cfg.xml) > wsb.CONFIG_MAX:
                raise ValueError(f"{cfg.name} is too long to give wsb ({len(cfg.xml):,} characters; at most {wsb.CONFIG_MAX:,})")
        lines = (cfg or wsb.DEFAULT).lines()
        if r.sandbox.cli:
            result = self._change(scripts.sandbox_start(r.sandbox.cli, cfg.xml if cfg else None), 240, elevate=False)
            m = GUID.search(result["Out"])
            return {"said": "Windows Sandbox started" + (f" ({m.group(0)})" if m else "") + ": its window opens",
                    "lines": lines, "ok": True}
        self._change(scripts.sandbox_classic(r.sandbox.classic, cfg.path if cfg else None), 60, elevate=False)
        return {"said": "Windows Sandbox is starting: its window opens", "lines": lines, "ok": True}

    def stop_sandbox(self, sandbox_id) -> dict:
        """A sandbox wsb runs closed: everything in it gone, but what it wrote to a writable mapped folder."""
        r = self.usable()
        if not r.sandbox.cli:
            raise ValueError("a sandbox is closed here through wsb (Windows 11 24H2's command); close its window instead")
        sid = str(sandbox_id or "").strip().strip("{}")
        if not GUID.fullmatch(sid):
            raise ValueError(f"{sandbox_id!r} is not a sandbox's Id (a GUID)")
        if not r.sandbox.error and not any(s["id"].lower() == sid.lower() for s in r.sandbox.running):
            raise ValueError(f"no sandbox {sid} runs (closed since?): look again")
        self._change(scripts.sandbox_stop(r.sandbox.cli, sid), 150, elevate=False)
        return {"said": f"the sandbox {sid} is closed", "lines": ["everything in it is gone"], "ok": True}


# -- the tables and the forms ------------------------------------------------------------------------------------------
def process_words(host_build: int, client: bool) -> str:
    """Which images this Windows runs with process isolation (Microsoft's version compatibility)."""
    builds = [b for b in sorted(_SERVER) if runs_here(host_build, client, b) == "process or Hyper-V isolation"]
    names = [server_name(b) for b in builds]
    own = host_build not in builds
    return ((", ".join(names) + (" and " if names and own else "")) if names else "") + (f"this build's ({host_build})" if own else "") \
        + " images; older ones with Hyper-V isolation"


_SERVER = (14393, 17763, 20348, 26100)


def engines_table(r: Reading) -> dict:
    rows = []
    for e in r.engines:
        if e.same_as:
            state = f"the same engine as {e.same_as}"
        elif e.answers and e.windows:
            state = "runs Windows containers"
        elif e.answers:
            state = f"runs {e.os_type or 'other'} containers" + (": switch Docker Desktop to Windows containers" if e.desktop else "")
        elif e.denied:
            state = cell("denied", DOCKER_RIGHTS)
        else:
            state = cell("not answering", e.why or None)
        total, running, images = e.counted or (0, 0, 0)
        rows.append([cell(e.title, e.endpoint or e.source), cell(e.version or "–", e.os or None),
                     isolation_words(e.isolation) or "–", f"{running} running of {total}" if e.answers else "–",
                     str(images) if e.answers else "–", state])
    return {"title": "Engines", "note": "the engines Windows containers run on: Docker's at each of its pipes, containerd's through nerdctl",
            "empty": NO_ENGINE[0].upper() + NO_ENGINE[1:] + ".",
            "columns": [{"title": "Engine"}, {"title": "Version"}, {"title": "Default isolation"}, {"title": "Containers", "num": True},
                        {"title": "Images", "num": True}, {"title": "State"}],
            "rows": rows}


def _container_button(form: str, title: str, e: Engine, c: Container) -> dict:
    return {"form": form, "title": title, "label": f"{title} {c.name}", "values": {"name": c.name, "engine": e.key, "container_id": c.id}}


def containers_table(r: Reading) -> dict:
    rows = []
    for e in r.listed:
        for c in sorted(e.containers, key=lambda x: x.name.lower()):
            isolation = isolation_words(c.isolation) or (f"{isolation_words(e.isolation)} (the engine's default)" if e.isolation else "–")
            power = (_container_button("stop", "Stop", e, c) if c.up else
                     _container_button("start", "Start", e, c) if c.state in ("created", "exited") else "")
            remove = _container_button("remove", "Remove…", e, c) if c.state != "removing" else ""
            rows.append([cell(c.name, short(c.id)), c.image, cell(c.state, c.status or None), isolation, c.ports or "–",
                         e.key, power, remove])
    return {"title": "Containers", "note": "process isolation shares this Windows' kernel; Hyper-V isolation gives each container a utility VM of its own",
            "empty": "No Windows containers on the engines that answer.",
            "columns": [{"title": "Container"}, {"title": "Image"}, {"title": "State"}, {"title": "Isolation"}, {"title": "Ports"},
                        {"title": "Engine"}, {"title": "Start · stop"}, {"title": "Remove"}],
            "rows": rows}


def images_table(r: Reading) -> dict:
    rows = []
    for i in sorted(r.images, key=lambda x: x.ref.lower()):
        here = runs_here(r.host_build, r.client, i.build)
        rows.append([cell(i.ref, short(i.id)), cell(i.os_version or "–", server_name(i.build) or None), here or "–",
                     i.size or "–", i.created or "–", i.engine])
    return {"title": "Images", "note": f"what runs here is this Windows' build ({r.host_build or 'not read'}) against each image's",
            "empty": "No images: docker pull mcr.microsoft.com/windows/nanoserver:ltsc2025 (or servercore) fetches one.",
            "columns": [{"title": "Image"}, {"title": "Windows"}, {"title": "Runs here with"}, {"title": "Size", "num": True},
                        {"title": "Made"}, {"title": "Engine"}],
            "rows": rows}


def sandbox_table(folder: Path, configs: list, r: Reading) -> dict:
    rows = []
    for i, (f, c, why) in enumerate(configs):
        if c is None:
            rows.append([cell(f.name, str(f)), cell("not read", why), "–", "–", ""])
            continue
        writable = sum(1 for x in c.folders if not x.read_only)
        mapped = (cell(plural(len(c.folders), "folder"), f"{writable} writable" if writable else "read-only") if c.folders else "none")
        launch = ({"form": f"sandbox:{i}", "title": "Launch…", "label": f"Launch Windows Sandbox with {f.name}", "values": {"path": str(f)}}
                  if not c.problem and r.sandbox.program else "")
        rows.append([cell(f.name, str(f)), "on" if c.on("Networking") else "off", mapped,
                     cell(c.logon, None) if c.logon else "–", launch if not c.problem else cell("cannot start", c.problem)])
    return {"title": "Windows Sandbox", "note": f"the .wsb files in {folder}; any other is launched by its path (Launch Windows Sandbox…)",
            "empty": f"No .wsb files in {folder}: put one there, or launch Windows Sandbox with its own defaults or any .wsb's path.",
            "columns": [{"title": "Configuration"}, {"title": "Network"}, {"title": "Folders mapped"}, {"title": "At logon"},
                        {"title": "Launch"}],
            "rows": rows}


def running_table(r: Reading) -> dict:
    rows = [[s["id"], s["status"] or "–", s["uptime"] or "–",
             {"form": "close_sandbox", "title": "Close…", "label": f"Close the sandbox {s['id']}", "values": {"sandbox_id": s["id"]}}]
            for s in r.sandbox.running]
    return {"title": "Sandboxes running", "note": "wsb list",
            "empty": f"None running{': ' + r.sandbox.error if r.sandbox.error else ''}.",
            "columns": [{"title": "Sandbox"}, {"title": "Status"}, {"title": "Up"}, {"title": "Close"}], "rows": rows}


def forms(r: Reading, configs: list) -> list[dict]:
    """The changes, each a hook asked with the fields in the order of its arguments once the user has confirmed it
    (liminal-platform 0.6.0); removing a running container and launching with a .wsb not yet seen are confirmed twice
    (the accept fields, asked when the hook refuses without them)."""
    name = {"name": "name", "label": "Container", "type": "fixed"}
    engine = {"name": "engine", "label": "Engine", "type": "fixed"}
    cid = {"name": "container_id", "label": "Its Id", "type": "fixed"}
    out = [] if not r.containers_on else [
        {"id": "start", "hook": "start_container", "title": "Start a container", "fields": [name, engine, cid],
         "confirm": {"title": "Start {name}?", "yes": "Start",
                     "words": "The engine starts it as it was made: its image, its isolation, its ports."}},
        {"id": "stop", "hook": "stop_container", "title": "Stop a container", "fields": [name, engine, cid],
         "confirm": {"title": "Stop {name}?", "yes": "Stop",
                     "words": "The engine asks it to shut down and ends it after 10 seconds if it has not; its files stay, and Start runs it again."}},
        {"id": "remove", "hook": "remove_container", "title": "Remove a container",
         "fields": [name, engine, cid, {"name": "accept_force", "type": "accept", "title": "Remove it while it runs?", "yes": "Remove it",
                                        "words": "{name} is ended at once and removed: what it has not saved is lost."}],
         "confirm": {"title": "Remove {name}?", "yes": "Remove", "danger": True,
                     "words": "The container and what it wrote inside it are deleted; its image stays, and so do its named volumes."}},
    ]
    if r.sandbox_on and r.sandbox.program:
        accept = {"name": "accept_settings", "type": "accept", "title": "Launch it with these settings?", "yes": "Launch",
                  "words": "Windows Sandbox starts with what {path} gives it, as said above."}
        out.append({"id": "sandbox", "hook": "launch_sandbox", "title": "Launch Windows Sandbox",
                    "note": "A clean, throwaway Windows in a window of its own, Hyper-V isolated; everything in it is gone when it closes.",
                    "fields": [{"name": "path", "label": "A .wsb file", "type": "text", "placeholder": "C:\\Users\\you\\Desktop\\tools.wsb",
                                "note": "its whole path; empty: Windows Sandbox's own defaults", "empty": "Windows Sandbox's own defaults"},
                               accept],
                    "submit": "Review",
                    "confirm": {"title": "Launch Windows Sandbox?", "yes": "Launch",
                                "words": ("With a .wsb, its settings are read and said before it launches. With none, Windows "
                                          "Sandbox's own: " + wsb.DEFAULT.words())}})
        for i, (f, c, _) in enumerate(configs):
            if c is None or c.problem:
                continue
            out.append({"id": f"sandbox:{i}", "hook": "launch_sandbox", "title": f"Launch Windows Sandbox with {f.name}",
                        "fields": [{"name": "path", "label": "Configuration", "type": "fixed"}, accept,
                                   {"name": "seen", "label": "Read", "type": "fixed", "value": c.digest,
                                    "choices": [{"value": c.digest, "title": c.read_as}]}],
                        "confirm": {"title": f"Launch Windows Sandbox with {f.name}?", "yes": "Launch", "words": c.words()}})
    if r.sandbox.cli:
        out.append({"id": "close_sandbox", "hook": "stop_sandbox", "title": "Close a sandbox",
                    "fields": [{"name": "sandbox_id", "label": "Sandbox", "type": "fixed"}],
                    "confirm": {"title": "Close this sandbox?", "yes": "Close it", "danger": True,
                                "words": "Windows Sandbox ends it at once: everything in it is gone, but what it wrote to a writable mapped folder."}})
    return out


MACHINE = WindowsContainersPlugin()
