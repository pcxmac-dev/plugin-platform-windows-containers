"""Windows containers: the plugin over a stand-in for powershell.exe only (nothing of this PC read, nothing run): the read's
recorded JSON (THIS_PC is this PC's own read, 2026-11-08: the Containers and Windows Sandbox features off; the others are
the same read's shape with the commands' outputs as docker, nerdctl, wsb and hcsdiag print them), the status the platform's
page draws, the engines found at their pipes (Windows, Linux, denied, the same engine twice, containerd), the containers'
isolation and the images' builds against this Windows', each change's program and arguments, the refusals the page turns
into a second confirmation, a denied change asked again through UAC, and the command line."""
from __future__ import annotations

import copy
import inspect
import json
import re

import pytest

import plugin_platform_windows_containers as wc
import plugin_platform_windows_containers.__main__ as cli
from liminal_libs.machines.plugin import CommandError
from liminal_libs.machines.windows import ERROR_MARK, PowerShell, decoded
from plugin_platform_windows_containers import MACHINE, Refusal, WindowsContainersPlugin, scripts
from plugin_platform_windows_containers.engines import runs_here

DOCKER = "C:\\Program Files\\docker\\docker.exe"
NERDCTL = "C:\\Program Files\\nerdctl\\nerdctl.exe"
WSB = "C:\\Users\\you\\AppData\\Local\\Microsoft\\WindowsApps\\wsb.exe"
CLASSIC = "C:\\WINDOWS\\System32\\WindowsSandbox.exe"
HCSDIAG = "C:\\WINDOWS\\system32\\hcsdiag.exe"
ENGINE_ID = "8d4f9c2a-1b3e-4f5a-9c7d-2e6f8a0b1c3d"
PINGER, IIS, BUILD = "4f2b" + "a" * 60, "9c1e" + "b" * 60, "17ab" + "c" * 60
NANO, IIS_IMAGE, CORE19 = "sha256:" + "1" * 64, "sha256:" + "2" * 64, "sha256:" + "3" * 64
SANDBOX_ID = "5e8b1c2d-3f4a-4b6c-8d9e-0a1b2c3d4e5f"
WINDOWS = {"Caption": "Microsoft Windows 11 Pro", "Build": "26300", "Release": "26H2", "Revision": "9711", "Kind": "Client"}
FEATURES_OFF = [{"Name": "VirtualMachinePlatform", "State": 1, "Title": "Virtual Machine Platform"},
                {"Name": "HypervisorPlatform", "State": 1, "Title": "Windows Hypervisor Platform"},
                {"Name": "Microsoft-Hyper-V", "State": 1, "Title": "Hyper-V Platform"},
                {"Name": "Microsoft-Hyper-V-Management-PowerShell", "State": 1, "Title": "Hyper-V Module for Windows PowerShell"},
                {"Name": "Containers-DisposableClientVM", "State": 2, "Title": "Windows Sandbox"},
                {"Name": "Containers", "State": 2, "Title": "Containers"}]
SERVICES = [{"Name": "hns", "Status": "Running", "StartType": "Manual", "Title": "Host Network Service"},
            {"Name": "vmcompute", "Status": "Running", "StartType": "Manual", "Title": "Hyper-V Host Compute Service"}]

# this PC's read: Hyper-V on, the Containers and Windows Sandbox features off, no engine, no wsb
THIS_PC = {"Elevated": False, "Group": False, "Windows": WINDOWS, "Hypervisor": True, "Features": FEATURES_OFF, "FeaturesRead": True,
           "Services": SERVICES, "Docker": None, "Nerdctl": None, "Hcsdiag": HCSDIAG, "Pipes": [], "Contexts": None, "Engines": [],
           "Containerd": None, "Sandbox": {"Cli": None, "Classic": None, "Running": [], "List": None}, "Hcs": None}


def ran(out: str = "", code: int = 0, err: str = "") -> dict:
    return {"Code": code, "Out": out, "Err": err}


def docker_info(os_type="windows", running=1, total=3, images=3, isolation="hyperv", version="27.3.1") -> str:
    """`docker info --format '{{json .}}'` as an engine prints it (the fields the plugin reads, and some it passes over)."""
    windows = os_type == "windows"
    return json.dumps({"ID": ENGINE_ID if windows else "c3d4e5f6-0000-4000-8000-000000000001", "Containers": total,
                       "ContainersRunning": running, "ContainersPaused": 0, "ContainersStopped": total - running, "Images": images,
                       "Driver": "windowsfilter" if windows else "overlayfs", "ContainerdCommit": {"ID": ""}, "RuncCommit": {"ID": ""},
                       "Isolation": isolation if windows else "", "OSType": os_type, "Architecture": "x86_64",
                       "OperatingSystem": "Windows 11 Pro Version 26H2 (OS Build 26300.9711)" if windows else "Docker Desktop",
                       "Name": "DESKTOP" if windows else "docker-desktop", "ServerVersion": version,
                       "DockerRootDir": "C:\\ProgramData\\docker" if windows else "/var/lib/docker"}) + "\n"


class FakeWindows:
    """powershell.exe as the plugin uses it: the read answered from the model held (rendered as the read script's object,
    each command's output as the command prints it), and each change's program and arguments (Invoke-Native) kept and
    applied. `engine`: windows | linux (Docker Desktop on Linux containers) | denied | twice (two pipes, one engine) | none."""

    def __init__(self, engine="windows", sandbox="cli", rights=False, nerdctl=False, features_on=True, hyperv=True, docker=True):
        self.engine, self.sandbox, self.rights, self.nerdctl, self.docker = engine, sandbox, rights, nerdctl, docker
        self.features = copy.deepcopy(FEATURES_OFF)
        for f in self.features:
            if f["Name"] in ("Containers", "Containers-DisposableClientVM") and features_on:
                f["State"] = 1
            if f["Name"] == "Microsoft-Hyper-V" and not hyperv:
                f["State"] = 2
        self.containers = [
            {"id": PINGER, "name": "pinger", "image": "mcr.microsoft.com/windows/nanoserver:ltsc2025", "state": "running",
             "status": "Up 3 hours", "isolation": "hyperv", "ports": ""},
            {"id": IIS, "name": "iis", "image": "mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022",
             "state": "exited", "status": "Exited (0) 2 days ago", "isolation": "", "ports": ""},
            {"id": BUILD, "name": "build", "image": "mcr.microsoft.com/windows/servercore:ltsc2019", "state": "created",
             "status": "Created", "isolation": "hyperv", "ports": "0.0.0.0:8080->80/tcp"}]
        self.sandboxes = [SANDBOX_ID]
        self.denied = False
        self.scripts: list[str] = []
        self.ran: list[tuple[str, list[str]]] = []

    @property
    def reads(self) -> int:
        return sum(1 for s in self.scripts if scripts.READ_MARK in s)

    def ps(self) -> str:
        return "".join(json.dumps({"Command": "\"cmd /S /C 'ping -t localhost'\"", "CreatedAt": "2026-11-08 10:00:00 +0100 CET",
                                   "ID": c["id"], "Image": c["image"], "Labels": "", "LocalVolumes": "0", "Mounts": "", "Names": c["name"],
                                   "Networks": "nat", "Ports": c["ports"], "RunningFor": "3 hours ago", "Size": "0B", "State": c["state"],
                                   "Status": c["status"]}) + "\n" for c in self.containers)

    def windows_engine(self, endpoint: str, source: str) -> dict:
        running = sum(1 for c in self.containers if c["state"] == "running")
        images = [(NANO, "mcr.microsoft.com/windows/nanoserver", "ltsc2025", "297MB", "10.0.26100.6899"),
                  (IIS_IMAGE, "mcr.microsoft.com/windows/servercore/iis", "windowsservercore-ltsc2022", "5.21GB", "10.0.20348.4294"),
                  (CORE19, "mcr.microsoft.com/windows/servercore", "ltsc2019", "4.95GB", "10.0.17763.7792")]
        return {"Endpoint": endpoint, "From": source, "Same": None,
                "Info": ran(docker_info(running=running, total=len(self.containers))),
                "Ps": ran(self.ps()),
                "Inspect": ran("".join(f"{c['id']}|{c['isolation']}|windows|2026-11-08T09:00:01.1234567Z\n" for c in self.containers)),
                "Images": ran("".join(json.dumps({"Containers": "N/A", "CreatedAt": "2026-10-14 01:02:03 +0200 CEST",
                                                  "CreatedSince": "3 weeks ago", "Digest": "<none>", "ID": i, "Repository": repo,
                                                  "SharedSize": "N/A", "Size": size, "Tag": tag, "UniqueSize": "N/A",
                                                  "VirtualSize": size}) + "\n" for i, repo, tag, size, _ in images)),
                "ImageInspect": ran("".join(f"{i}|windows|{v}|amd64\n" for i, _, _, _, v in images))}

    def reading(self) -> dict:
        out = copy.deepcopy(THIS_PC)
        out.update(Elevated=False, Group=self.rights, Features=self.features)
        if self.docker:
            out["Docker"] = DOCKER
            out["Services"] = SERVICES + [{"Name": "docker", "Status": "Running", "StartType": "Automatic", "Title": "Docker Engine"}]
            out["Contexts"] = ran(json.dumps({"Current": True, "Description": "Current DOCKER_HOST based configuration",
                                              "DockerEndpoint": "npipe:////./pipe/docker_engine", "Error": "", "Name": "default"}) + "\n")
        if self.engine == "windows":
            out["Pipes"] = ["docker_engine"]
            out["Engines"] = [self.windows_engine("npipe:////./pipe/docker_engine", "the pipe docker_engine")]
        elif self.engine == "twice":
            out["Pipes"] = ["docker_engine", "dockerDesktopWindowsEngine"]
            out["Services"] = out["Services"] + [{"Name": "com.docker.service", "Status": "Running", "StartType": "Manual",
                                                  "Title": "Docker Desktop Service"}]
            first = self.windows_engine("npipe:////./pipe/docker_engine", "the pipe docker_engine")
            second = {"Endpoint": "npipe:////./pipe/dockerDesktopWindowsEngine", "From": "the pipe dockerDesktopWindowsEngine",
                      "Same": "npipe:////./pipe/docker_engine", "Info": first["Info"], "Ps": None, "Inspect": None, "Images": None,
                      "ImageInspect": None}
            out["Engines"] = [first, second]
        elif self.engine == "linux":
            out["Pipes"] = ["docker_engine", "dockerDesktopLinuxEngine"]
            out["Services"] = out["Services"] + [{"Name": "com.docker.service", "Status": "Running", "StartType": "Manual",
                                                  "Title": "Docker Desktop Service"}]
            out["Engines"] = [{"Endpoint": "npipe:////./pipe/docker_engine", "From": "the pipe docker_engine", "Same": None,
                               "Info": ran(docker_info("linux", running=2, total=2, images=5)), "Ps": None, "Inspect": None,
                               "Images": None, "ImageInspect": None},
                              {"Endpoint": "npipe:////./pipe/dockerDesktopLinuxEngine", "From": "the context desktop-linux", "Same": None,
                               "Info": ran(docker_info("linux", running=2, total=2, images=5)), "Ps": None, "Inspect": None,
                               "Images": None, "ImageInspect": None}]
        elif self.engine == "denied":
            out["Pipes"] = ["docker_engine"]
            out["Engines"] = [{"Endpoint": "npipe:////./pipe/docker_engine", "From": "the pipe docker_engine", "Same": None,
                               "Info": ran(json.dumps({"ID": "", "Containers": 0, "ServerErrors": [
                                   "error during connect: this error may indicate that the docker daemon is not running: Get "
                                   "\"http://%2F%2F.%2Fpipe%2Fdocker_engine/v1.47/info\": open //./pipe/docker_engine: Access is denied."]}) + "\n",
                                   code=1), "Ps": None, "Inspect": None, "Images": None, "ImageInspect": None}]
        if self.nerdctl:
            out["Nerdctl"] = NERDCTL
            out["Containerd"] = {"Info": ran(json.dumps({"ID": "", "ServerVersion": "v2.1.4", "OSType": "windows",
                                                         "OperatingSystem": "Microsoft Windows 11 Pro"}) + "\n"),
                                 "Ps": ran(json.dumps({"Command": "\"cmd /c ping -t localhost\"", "CreatedAt": "2026-11-08 11:00:00 +0100 CET",
                                                       "ID": "77" + "d" * 62, "Image": "mcr.microsoft.com/windows/nanoserver:ltsc2025",
                                                       "Platform": "windows/amd64", "Names": "nano-ping", "Ports": "", "Status": "Up 5 minutes",
                                                       "Runtime": "io.containerd.runhcs.v1", "Size": "", "Labels": ""}) + "\n"),
                                 "Images": ran(json.dumps({"CreatedAt": "2026-10-14 01:02:03 +0200 CEST", "CreatedSince": "3 weeks ago",
                                                           "Digest": "sha256:" + "e" * 64, "ID": "f" * 12, "Repository": "mcr.microsoft.com/windows/nanoserver",
                                                           "Tag": "ltsc2025", "Size": "297MB", "BlobSize": "120MB", "Platform": "windows/amd64"}) + "\n")}
        if self.sandbox == "cli":
            out["Sandbox"] = {"Cli": WSB, "Classic": CLASSIC, "Running": ["WindowsSandboxServer"] if self.sandboxes else [],
                              "List": ran(json.dumps({"WindowsSandboxEnvironments": [{"Id": s, "Status": "Running", "Uptime": "00:12:03"}
                                                                                     for s in self.sandboxes]}))}
        elif self.sandbox == "classic":
            out["Sandbox"] = {"Cli": None, "Classic": CLASSIC, "Running": [], "List": None}
        if self.rights:
            out["Hcs"] = ran("4F0C2AA1-0B4D-4D93-9C6B-1D5E0A6B7C8D\n    VM,                         Running, 4F0C2AA1-0B4D-4D93-9C6B-1D5E0A6B7C8D, WSL\n")
        return out

    def native(self, exe: str, argv: list[str]) -> dict:
        self.ran.append((exe, argv))
        if exe in (DOCKER, NERDCTL):
            if self.denied:
                return ran(code=1, err="Error response from daemon: open //./pipe/docker_engine: Access is denied.")
            rest = argv[2:] if argv[:1] == ["-H"] else argv
            verb, target = rest[0], rest[-1]
            if exe == NERDCTL:  # containerd's own container, held in the reading
                return ran(target + "\n")
            c = next(c for c in self.containers if c["id"] == target)
            if verb == "start":
                c.update(state="running", status="Up 1 second")
            elif verb == "stop":
                c.update(state="exited", status="Exited (0) 1 second ago")
            elif verb == "rm":
                self.containers.remove(c)
            return ran(target + "\n")
        if exe == WSB:
            if argv[:2] == ["--raw", "start"]:
                self.sandboxes.append("6f9c2d3e-4a5b-4c6d-9e0f-1a2b3c4d5e6f")
                return ran(json.dumps({"Id": self.sandboxes[-1]}))
            if argv[:1] == ["stop"]:
                self.sandboxes.remove(argv[2])
                return ran()
        return ran(code=1, err=f"{exe}: not stood in for")

    def __call__(self, args, timeout):
        s = decoded(args[-1])
        self.scripts.append(s)
        if scripts.READ_MARK in s:
            return 0, json.dumps(self.reading()) + "\r\n", ""
        m = re.search(r"\$r = Invoke-Native '((?:[^']|'')*)' @\((.*?)\) (\d+)\r?\n", s, re.DOTALL)
        if m:
            argv = [a.replace("''", "'") for a in re.findall(r"'((?:[^']|'')*)'", m.group(2))]
            return 0, scripts.RESULT + json.dumps(self.native(m.group(1).replace("''", "'"), argv)) + "\r\n", ""
        if "WindowsSandbox.exe" in s and "Process]::Start($psi)" in s:
            self.ran.append((CLASSIC, [s]))
            return 0, scripts.RESULT + json.dumps(ran("4242")) + "\r\n", ""
        return 1, ERROR_MARK + "not stood in for\r\n", ""


TOOLS = """<?xml version="1.0" encoding="utf-8"?>
<Configuration>
  <Networking>Disable</Networking>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>C:\\Users\\you\\Downloads</HostFolder>
      <SandboxFolder>C:\\Users\\WDAGUtilityAccount\\Desktop\\Downloads</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>C:\\Users\\you\\Scratch</HostFolder>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>explorer.exe C:\\Users\\WDAGUtilityAccount\\Desktop\\Downloads</Command>
  </LogonCommand>
  <MemoryInMB>4096</MemoryInMB>
</Configuration>
"""
HOST_FOLDERS = {"C:\\Users\\you\\Downloads", "C:\\Users\\you\\Scratch"}


@pytest.fixture
def folder(tmp_path):
    (tmp_path / "tools.wsb").write_text(TOOLS, encoding="utf-8")
    (tmp_path / "broken.wsb").write_text("<Configuration><Networking>Disable</Configuration>", encoding="utf-8")
    (tmp_path / "missing.wsb").write_text("<Configuration><MappedFolders><MappedFolder><HostFolder>D:\\gone</HostFolder>"
                                          "</MappedFolder></MappedFolders></Configuration>", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a configuration", encoding="utf-8")
    return tmp_path


def plugin(fake=None, env=None, system="win32", clock=None, folder=None):
    fake = fake if fake is not None else FakeWindows()
    p = WindowsContainersPlugin(PowerShell(runner=fake, env=env or {}), system=system, env=env or {}, clock=clock, folder=folder,
                                exists=lambda path: path in HOST_FOLDERS)
    return p, fake


def table(st: dict, title: str) -> dict:
    return next(t for t in st["tables"] if t["title"] == title)


def texts(row: list) -> list:
    return [c.get("text", c.get("title")) if isinstance(c, dict) else c for c in row]


# -- what it is ----------------------------------------------------------------------------------------------------------
def test_the_plugin_is_a_machine_plugin_with_its_changes_as_hooks(folder):
    assert MACHINE.name == "windows-containers" and MACHINE.title == "Windows containers" and MACHINE.KIND == "machine"
    assert MACHINE.SYSTEM == "platform" and MACHINE.ICON == "scan" and MACHINE.STEPS == () and wc.__version__ == "0.1.0"
    p, fake = plugin(folder=folder)
    hooks = p.interface()["hooks"]
    for hook in ("present", "status", "engines", "containers", "images", "sandboxes", "start_container", "stop_container",
                 "remove_container", "launch_sandbox", "stop_sandbox"):
        assert hook in hooks
    assert "setup" not in hooks and fake.scripts == [] and p.instances() == ()  # the Windows engine is not offered for Linux images


def test_each_form_gives_its_hooks_arguments_in_order(folder):
    p, _ = plugin(folder=folder)
    st = p.status()
    ids = {f["id"] for f in st["forms"]}
    assert {"start", "stop", "remove", "sandbox", "sandbox:2", "close_sandbox"} <= ids  # sandbox:2 is tools.wsb (by name)
    for f in st["forms"]:
        params = list(inspect.signature(getattr(p, f["hook"])).parameters)
        assert [x["name"] for x in f["fields"]] == params[:len(f["fields"])], f["id"]
    assert {x["name"] for f in st["forms"] for x in f["fields"] if x["type"] == "accept"} == {"accept_force", "accept_settings"}
    assert {f["id"] for f in st["forms"] if f["confirm"].get("danger")} == {"remove", "close_sandbox"}


# -- the status ----------------------------------------------------------------------------------------------------------
def test_this_pc_with_the_features_off_is_not_present_and_says_how_to_turn_them_on():
    p, fake = plugin(FakeWindows(engine="none", sandbox=None, features_on=False, docker=False))
    st = p.status()
    assert st["present"] is False and st["valid"] is False and "applies" not in st and "tables" not in st
    assert st["why"].startswith("Windows containers and Windows Sandbox are off: Windows Features (optionalfeatures.exe) turns them on")
    assert "-FeatureName Containers, Containers-DisposableClientVM -All" in st["why"]
    assert st["summary"] == "Windows containers and Windows Sandbox are off" and p.present() is False
    assert st["containersFeature"] == "off" and st["windowsSandbox"] == "off" and st["hyperV"] == "on" and st["docker"] == "not installed"
    assert st["hostComputeService"] == "vmcompute running (started when needed)" and st["engines"] == "none answering for Windows containers"
    assert st["processIsolationHere"] == ("Windows Server 2022, Windows Server 2025 and this build's (26300) images; older ones "
                                          "with Hyper-V isolation")
    assert st["computeSystems"] == "listed to administrators and Hyper-V Administrators (hcsdiag)"
    recorded = WindowsContainersPlugin(PowerShell(runner=lambda a, t: (0, json.dumps(THIS_PC), "")), system="win32", env={})
    assert recorded.status() == {**st, "aChangeDenied": recorded.status()["aChangeDenied"]}  # the recorded read, as it came
    home = copy.deepcopy(THIS_PC)
    home["Features"] = [f for f in FEATURES_OFF if not f["Name"].startswith("Containers")]
    assert "this edition of Windows has neither" in plugin(lambda a, t: (0, json.dumps(home), ""))[0].status()["why"]


def test_a_windows_engine_its_containers_isolation_and_images_builds(folder):
    p, fake = plugin(folder=folder)
    st = p.status()
    assert st["present"] is True and st["valid"] is True and "problem" not in st
    assert st["summary"] == "3 containers, 1 running · 3 images · Windows Sandbox on, 1 running"
    assert st["engines"] == "Docker Engine 27.3.1 at docker_engine, Hyper-V isolation by default"
    assert st["dockerService"] == "docker running (starts with Windows)" and st["windowsSandbox"] == "on (its command, wsb: Windows 11 24H2's)"
    engines = table(st, "Engines")
    assert texts(engines["rows"][0]) == ["Docker Engine", "27.3.1", "Hyper-V", "1 running of 3", "3", "runs Windows containers"]
    assert engines["rows"][0][0]["sub"] == "npipe:////./pipe/docker_engine"
    containers = {r[0]["text"]: r for r in table(st, "Containers")["rows"]}
    assert texts(containers["pinger"])[:6] == ["pinger", "mcr.microsoft.com/windows/nanoserver:ltsc2025", "running", "Hyper-V", "–",
                                               "docker_engine"]
    assert containers["pinger"][0]["sub"] == PINGER[:12] and containers["pinger"][2]["sub"] == "Up 3 hours"
    assert containers["iis"][3] == "Hyper-V (the engine's default)" and containers["build"][4] == "0.0.0.0:8080->80/tcp"
    assert [b["title"] if b else "" for b in containers["pinger"][6:]] == ["Stop", "Remove…"]
    assert [b["title"] if b else "" for b in containers["iis"][6:]] == ["Start", "Remove…"]
    assert containers["iis"][6]["values"] == {"name": "iis", "engine": "docker_engine", "container_id": IIS}
    images = {r[0]["text"]: r for r in table(st, "Images")["rows"]}
    nano = images["mcr.microsoft.com/windows/nanoserver:ltsc2025"]
    assert texts(nano) == ["mcr.microsoft.com/windows/nanoserver:ltsc2025", "10.0.26100.6899", "process or Hyper-V isolation", "297MB",
                           "3 weeks ago", "docker_engine"] and nano[1]["sub"] == "Windows Server 2025"
    assert images["mcr.microsoft.com/windows/servercore/iis:windowsservercore-ltsc2022"][2] == "process or Hyper-V isolation"
    assert images["mcr.microsoft.com/windows/servercore:ltsc2019"][2] == "Hyper-V isolation only"
    assert fake.reads == 1


def test_which_images_this_windows_runs_and_how():
    assert runs_here(26300, True, 26100) == runs_here(26300, True, 20348) == "process or Hyper-V isolation"  # Windows 11 26H2
    assert runs_here(26300, True, 17763) == "Hyper-V isolation only"
    assert runs_here(22631, True, 26100) == "not here: newer than this Windows"  # Windows 11 23H2: no Server 2025 images
    assert runs_here(22631, True, 20348) == "process or Hyper-V isolation"
    assert runs_here(26100, False, 20348) == "process or Hyper-V isolation"  # Windows Server 2025
    assert runs_here(20348, False, 17763) == "Hyper-V isolation only" and runs_here(17763, False, 17763) == "process or Hyper-V isolation"
    assert runs_here(19045, True, 17763) == "Hyper-V isolation only" and runs_here(26300, True, 0) == ""


def test_docker_desktop_on_linux_containers_a_denied_pipe_and_no_engine_are_said():
    st = plugin(FakeWindows(engine="linux", sandbox=None))[0].status()
    assert st["valid"] is True and "Docker Desktop runs Linux containers now" in st["problem"] and "docker desktop engine use windows" in st["problem"]
    rows = table(st, "Engines")["rows"]
    assert texts(rows[0])[0] == "Docker Desktop" and rows[0][5] == "runs linux containers: switch Docker Desktop to Windows containers"
    assert table(st, "Containers")["rows"] == [] and st["summary"] == "containers on, no engine answering · Windows Sandbox on"
    assert "Windows Sandbox is on but its program was not found" in st["problem"]  # its feature on, no wsb or program read
    assert "Windows Sandbox" not in [t["title"] for t in st["tables"]] or not table(st, "Windows Sandbox")["rows"]
    st = plugin(FakeWindows(engine="denied", sandbox=None))[0].status()
    assert "the engine's pipe answers administrators and its group only: join docker-users" in st["problem"]
    assert table(st, "Engines")["rows"][0][5]["text"] == "denied"
    st = plugin(FakeWindows(engine="none", sandbox=None, docker=False))[0].status()
    assert st["problem"].startswith("no engine for Windows containers is installed: Docker Desktop")
    st = plugin(FakeWindows(engine="none", sandbox=None, hyperv=False))[0].status()
    assert "Hyper-V is off, so Hyper-V isolation (Windows 10 and 11's default) cannot run" in st["problem"]
    assert "Docker is installed but no Docker engine's pipe is open" in st["problem"]


def test_one_engine_at_two_pipes_is_listed_once_and_containerd_beside_it():
    p, fake = plugin(FakeWindows(engine="twice", sandbox=None, nerdctl=True))
    st = p.status()
    rows = table(st, "Engines")["rows"]
    assert [texts(r)[0] for r in rows] == ["Docker Desktop", "Docker Desktop", "containerd (nerdctl)"]
    assert rows[1][5] == "the same engine as docker_engine" and rows[2][5] == "runs Windows containers"
    names = [r[0]["text"] for r in table(st, "Containers")["rows"]]
    assert names.count("pinger") == 1 and "nano-ping" in names
    nano = next(r for r in table(st, "Containers")["rows"] if r[0]["text"] == "nano-ping")
    assert nano[2]["text"] == "running" and nano[5] == "containerd"  # its state read from nerdctl's Status
    assert p.stop_container("nano-ping")["said"] == "nano-ping stopped"
    assert fake.ran[-1] == (NERDCTL, ["stop", "77" + "d" * 62])  # nerdctl: no -H


def test_the_compute_systems_are_read_only_with_the_rights():
    st = plugin(FakeWindows(rights=True, sandbox=None))[0].status()
    hcs = table(st, "Compute systems")
    assert hcs["rows"][0] == ["4F0C2AA1-0B4D-4D93-9C6B-1D5E0A6B7C8D"] and "WSL" in hcs["rows"][1][0] and "computeSystems" not in st
    assert st["rights"] == "a member of Hyper-V Administrators"
    assert "Compute systems" not in [t["title"] for t in plugin(FakeWindows(sandbox=None))[0].status()["tables"]]
    assert "Get-Process" in scripts.READ and "($out.Elevated -or $out.Group)" in scripts.READ  # hcsdiag only then


def test_on_linux_it_is_not_for_this_machine_and_asks_nothing():
    p, fake = plugin(system="linux")
    st = p.status()
    assert st["applies"] is False and st["summary"] == "not for this machine" and not p.present()
    assert st["why"] == "Windows containers are Windows' own, and this machine runs Linux"
    with pytest.raises(CommandError):
        p.start_container("iis")
    assert fake.scripts == []


def test_what_was_read_is_kept_a_while_and_read_again_after_a_change():
    now = [50.0]
    p, fake = plugin(FakeWindows(sandbox=None), clock=lambda: now[0])
    p.status()
    p.present()
    assert fake.reads == 1
    now[0] += wc.READ_S + 0.5
    p.status()
    assert fake.reads == 2
    p.start_container("iis")
    assert fake.reads == 3
    assert next(r for r in table(p.status(), "Containers")["rows"] if r[0]["text"] == "iis")[2]["text"] == "running"
    assert fake.reads == 4


# -- the changes ---------------------------------------------------------------------------------------------------------
def test_a_container_is_started_stopped_and_removed_on_its_engine():
    p, fake = plugin(FakeWindows(sandbox=None))
    assert p.start_container("iis", "docker_engine", IIS)["said"] == "iis started on Docker Engine (docker_engine)"
    assert fake.ran[-1] == (DOCKER, ["-H", "npipe:////./pipe/docker_engine", "start", IIS])
    script = fake.scripts[-1]
    assert "$psi.CreateNoWindow = $true" in script and "WaitForExit($seconds * 1000)" in script  # no window, a time limit
    assert p.stop_container(PINGER[:12])["said"] == "pinger stopped"  # by a short Id
    assert fake.ran[-1] == (DOCKER, ["-H", "npipe:////./pipe/docker_engine", "stop", PINGER])
    assert p.remove_container("build")["said"] == "build removed" and fake.ran[-1][1][-2:] == ["rm", BUILD]
    with pytest.raises(ValueError, match="iis is running: a container that is not running starts"):
        p.start_container("iis")
    with pytest.raises(ValueError, match="pinger is exited: a running container stops"):
        p.stop_container("pinger")
    with pytest.raises(ValueError, match="no container named nope"):
        p.start_container("nope")
    with pytest.raises(ValueError, match="no engine dockerDesktopWindowsEngine runs Windows containers here"):
        p.start_container("pinger", "dockerDesktopWindowsEngine")
    with pytest.raises(ValueError, match="is named iis now, not old"):
        p.stop_container("old", None, IIS)
    with pytest.raises(ValueError, match="not a container's Id"):
        p.start_container("pinger", None, "'; docker rm -f $(docker ps -q)")


def test_a_running_container_is_removed_only_once_that_is_accepted_too():
    p, fake = plugin(FakeWindows(sandbox=None))
    with pytest.raises(Refusal) as e:
        p.remove_container("pinger", "docker_engine", PINGER)
    assert e.value.accept == "accept_force" and isinstance(e.value, ValueError) and "ends it at once" in str(e.value)
    assert fake.ran == []
    assert p.ask("remove_container", "pinger", "docker_engine", PINGER, True)["said"] == "pinger removed"
    assert fake.ran[-1] == (DOCKER, ["-H", "npipe:////./pipe/docker_engine", "rm", "-f", PINGER])


def test_a_denied_change_says_how_to_have_the_rights_or_asks_windows_when_told_to():
    fake = FakeWindows(sandbox=None)
    fake.denied = True
    p, _ = plugin(fake)
    with pytest.raises(CommandError) as e:
        p.start_container("iis")
    assert e.value.denied and "the engine refused it for want of rights: join docker-users" in str(e.value)
    assert "LIMINAL_ELEVATE=prompt" in str(e.value) and "Access is denied" in str(e.value)
    p, _ = plugin(fake, env={"LIMINAL_ELEVATE": "prompt"})
    asked = []

    def elevated(script, timeout=600.0):  # Windows' prompt, stood in for: the same script, run as administrator
        asked.append(script)
        return scripts.RESULT + json.dumps(ran(IIS + "\n")) + "\r\n"
    p.ps.run_elevated = elevated
    assert p.start_container("iis")["said"].startswith("iis started")
    assert len(asked) == 1 and "'start'" in asked[0] and p.status()["aChangeDenied"] == "is asked again through Windows' prompt (UAC)"


# -- Windows Sandbox -----------------------------------------------------------------------------------------------------
def test_the_wsb_files_are_listed_with_what_they_give_the_sandbox(folder):
    p, _ = plugin(folder=folder)
    st = p.status()
    t = table(st, "Windows Sandbox")
    rows = {r[0]["text"]: r for r in t["rows"]}
    assert list(rows) == ["broken.wsb", "missing.wsb", "tools.wsb"] and str(folder) in t["note"] and st["sandboxFiles"] == str(folder)
    assert rows["broken.wsb"][1]["text"] == "not read" and "not well-formed XML" in rows["broken.wsb"][1]["sub"]
    assert rows["missing.wsb"][4]["text"] == "cannot start" and "D:\\gone is not a folder on this PC" in rows["missing.wsb"][4]["sub"]
    tools = rows["tools.wsb"]
    assert tools[1] == "off" and tools[2] == {"text": "2 folders", "sub": "1 writable"}
    assert tools[3] == "explorer.exe C:\\Users\\WDAGUtilityAccount\\Desktop\\Downloads"
    assert tools[4] == {"form": "sandbox:2", "title": "Launch…", "label": "Launch Windows Sandbox with tools.wsb",
                        "values": {"path": str(folder / "tools.wsb")}}
    form = next(f for f in st["forms"] if f["id"] == "sandbox:2")
    words = form["confirm"]["words"]
    assert words.startswith("Shared with it: the GPU, your microphone, the clipboard. Not shared: the network, your camera, your printers.")
    assert "It maps C:\\Users\\you\\Downloads as C:\\Users\\WDAGUtilityAccount\\Desktop\\Downloads, read-only" in words
    assert "C:\\Users\\you\\Scratch as C:\\Users\\WDAGUtilityAccount\\Desktop\\Scratch, writable" in words and "Memory: 4,096 MB." in words
    seen = form["fields"][2]
    assert seen["name"] == "seen" and seen["value"] == seen["choices"][0]["value"] and seen["choices"][0]["title"].endswith("bytes")
    running = table(st, "Sandboxes running")
    assert running["rows"][0][:3] == [SANDBOX_ID, "Running", "00:12:03"] and running["rows"][0][3]["form"] == "close_sandbox"
    assert st["actions"] == [{"form": "sandbox", "title": "Launch Windows Sandbox…",
                              "note": "with a .wsb's settings (said first), or Windows Sandbox's own"}]


def test_a_sandbox_is_launched_with_a_wsb_once_its_settings_are_said(folder):
    p, fake = plugin(folder=folder)
    tools = str(folder / "tools.wsb")
    with pytest.raises(Refusal) as e:  # typed on the page: its settings said before anything starts
        p.launch_sandbox(tools)
    assert e.value.accept == "accept_settings" and "its settings being said first" in str(e.value) and "Not shared: the network" in str(e.value)
    assert fake.ran == []
    answer = p.launch_sandbox(tools, True)
    assert answer["said"] == "Windows Sandbox started (6f9c2d3e-4a5b-4c6d-9e0f-1a2b3c4d5e6f): its window opens"
    assert "the network: off" in answer["lines"] and "memory: 4,096 MB" in answer["lines"]
    exe, argv = fake.ran[-1]
    assert exe == WSB and argv[:3] == ["--raw", "start", "--config"] and argv[3].startswith("<Configuration><Networking>Disable</Networking>")
    assert "\n" not in argv[3] and "<?xml" not in argv[3] and "connect --id" in fake.scripts[-1]  # its window opened apart
    digest = next(f for f in p.status()["forms"] if f["id"] == "sandbox:2")["fields"][2]["value"]
    p.launch_sandbox(tools, False, digest)  # the row's form: its words were the confirmation, the file as read then
    assert fake.ran[-1][0] == WSB
    (folder / "tools.wsb").write_text(TOOLS.replace("Disable", "Enable"), encoding="utf-8")
    with pytest.raises(Refusal, match="Shared with it: the network"):  # changed since the page read it: said again
        p.launch_sandbox(tools, False, digest)
    p.launch_sandbox(None)  # Windows Sandbox's own defaults
    assert fake.ran[-1] == (WSB, ["--raw", "start"])
    for bad, why in ((str(folder / "broken.wsb"), "not well-formed XML"), (str(folder / "missing.wsb"), "cannot start a sandbox"),
                     (str(folder / "notes.txt"), "is not a .wsb file"), ("tools.wsb", "not a full path"),
                     (str(folder / "absent.wsb"), "cannot be read")):
        with pytest.raises(ValueError, match=why):
            p.launch_sandbox(bad, True)


def test_a_wsb_declaring_entities_or_too_large_is_not_read(folder):
    p, _ = plugin(folder=folder)
    (folder / "laughs.wsb").write_text('<?xml version="1.0"?><!DOCTYPE lol [<!ENTITY a "aaaa">]><Configuration>&a;</Configuration>',
                                       encoding="utf-8")
    with pytest.raises(ValueError, match="declares a DOCTYPE or an ENTITY"):
        p.launch_sandbox(str(folder / "laughs.wsb"), True)
    (folder / "huge.wsb").write_text("<Configuration>" + " " * (wc.wsb.MAX_BYTES + 1) + "</Configuration>", encoding="utf-8")
    with pytest.raises(ValueError, match="is not read"):
        p.launch_sandbox(str(folder / "huge.wsb"), True)
    (folder / "odd.wsb").write_text("<Configuration><Networking>Maybe</Networking><Fancy>1</Fancy></Configuration>", encoding="utf-16")
    cfg = wc.wsb.read(folder / "odd.wsb")
    assert cfg.problem == "Networking is 'Maybe': Enable, Disable or Default" and cfg.unknown == ("Fancy",)


def test_without_wsb_windows_sandboxs_own_program_is_started(folder):
    p, fake = plugin(FakeWindows(sandbox="classic"), folder=folder)
    st = p.status()
    assert "Sandboxes running" not in [t["title"] for t in st["tables"]] and st["windowsSandbox"] == "on (its program)"
    assert p.launch_sandbox(str(folder / "tools.wsb"), True)["said"] == "Windows Sandbox is starting: its window opens"
    script = fake.ran[-1][1][0]
    assert f"$psi.FileName = '{CLASSIC}'" in script and str(folder / "tools.wsb") in script and "$psi.UseShellExecute = $false" in script
    with pytest.raises(ValueError, match="closed here through wsb"):
        p.stop_sandbox(SANDBOX_ID)


def test_a_running_sandbox_is_closed_by_its_id(folder):
    p, fake = plugin(folder=folder)
    assert p.stop_sandbox(SANDBOX_ID)["said"] == f"the sandbox {SANDBOX_ID} is closed"
    assert fake.ran[-1] == (WSB, ["stop", "--id", SANDBOX_ID]) and fake.sandboxes == []
    with pytest.raises(ValueError, match="no sandbox .* runs"):
        p.stop_sandbox(SANDBOX_ID)
    with pytest.raises(ValueError, match="not a sandbox's Id"):
        p.stop_sandbox("x; wsb stop --id *")


def test_the_read_hooks_give_what_is_there(folder):
    p, _ = plugin(folder=folder)
    assert [e["key"] for e in p.engines()] == ["docker_engine"] and {c["name"] for c in p.containers()} == {"pinger", "iis", "build"}
    assert {i["runsHere"] for i in p.images()} == {"process or Hyper-V isolation", "Hyper-V isolation only"}
    s = p.sandboxes()
    assert s["on"] is True and s["command"] == WSB and s["running"][0]["id"] == SANDBOX_ID
    assert [c["ok"] for c in s["configurations"]] == [False, False, True]


def test_the_read_script_asks_each_program_without_a_window_and_with_a_time_limit():
    s = scripts.READ
    assert s.count("Invoke-Native $out.Docker") == 6 and "'--raw', 'list'" in s and "docker_engine_windows" in s
    assert "$psi.CreateNoWindow = $true" in s and "$p.Kill()" in s and "Win32_OptionalFeature" in s
    assert s.index("$out.Pipes -contains") < s.index("'info', '--format'")  # only pipes there are asked


# -- the command line ----------------------------------------------------------------------------------------------------
def test_the_command_line_drives_the_same_hooks(folder):
    p, fake = plugin(folder=folder)
    said, told = [], []
    assert cli.main(["status"], plugin=p, out=said.append, err=told.append) == 0 and json.loads(said[-1])["valid"] is True
    assert cli.main(["containers"], plugin=p, out=said.append, err=told.append) == 0 and len(json.loads(said[-1])) == 3
    assert cli.main(["remove", "pinger"], plugin=p, out=said.append, err=told.append) == 1
    assert told[-1].startswith("refused: pinger was not removed") and told[-1].endswith("(--force removes it)")
    assert cli.main(["remove", "pinger", "--force"], plugin=p, out=said.append, err=told.append) == 0 and said[-2] == "pinger removed"
    assert cli.main(["sandbox", str(folder / "tools.wsb")], plugin=p, out=said.append, err=told.append) == 1
    assert told[-1].endswith("(--accept launches it with them)")
    assert cli.main(["sandbox", str(folder / "tools.wsb"), "--accept"], plugin=p, out=said.append, err=told.append) == 0
    assert cli.main(["close-sandbox", SANDBOX_ID], plugin=p, out=said.append, err=told.append) == 0
    assert cli.main(["start", "nope"], plugin=p, out=said.append, err=told.append) == 1 and told[-1].startswith("refused: no container")
    off, _ = plugin(FakeWindows(engine="none", sandbox=None, features_on=False, docker=False))
    assert cli.main(["images"], plugin=off, out=said.append, err=told.append) == 1 and told[-1].startswith("failed: Windows containers")
    assert cli.main(["status"], plugin=plugin(system="linux")[0], out=said.append, err=told.append) == 1
