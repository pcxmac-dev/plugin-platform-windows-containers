"""The engines that run Windows containers, as the read found them (scripts.READ): each command's raw output ({Code, Out,
Err}) parsed here. Docker's engine (Docker Engine, the docker service; Docker Desktop switched to Windows containers;
Mirantis Container Runtime) at each of its pipes, its containers with their isolation (process: sharing this Windows'
kernel; Hyper-V: a utility VM of their own) and its images with the Windows build they were made from; containerd through
nerdctl. And which images this Windows runs, with which isolation (Microsoft's version compatibility: process isolation
needs the image's build to be this host's, but for Windows Server 2022 images on Windows 11 and Windows Server 2025, and
Windows Server 2025 images on Windows 11 24H2 and later; Hyper-V isolation runs older images too, never newer ones)."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace

DENIED_WORDS = ("access is denied", "access denied", "permission denied", "insufficient privileges", "required permission",
                "0x80070005")
SERVER_BUILDS = {14393: "Windows Server 2016", 17763: "Windows Server 2019", 20348: "Windows Server 2022",
                 26100: "Windows Server 2025"}
CONTAINER_ID = re.compile(r"^[0-9a-f]{12,64}$")
UP = ("running", "restarting", "paused")


def denied_words(text: str) -> bool:
    low = str(text or "").lower()
    return any(w in low for w in DENIED_WORDS)


def native(d) -> tuple[int | None, str, str]:
    """A command's (exit code, output, errors) as the read gives it; (None, "", "") when it was not run."""
    if not isinstance(d, dict):
        return None, "", ""
    code = d.get("Code")
    return (int(code) if isinstance(code, (int, float)) else None), str(d.get("Out") or ""), str(d.get("Err") or "")


def json_lines(text: str) -> list[dict]:
    """The JSON objects a command printed one a line (`--format '{{json .}}'`); a line that is not one is passed over."""
    out = []
    for line in str(text or "").splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                out.append(row)
    return out


def json_doc(text: str) -> dict:
    """The first JSON object a command printed (`docker info --format '{{json .}}'`); {} when none."""
    rows = json_lines(text)
    if rows:
        return rows[0]
    try:
        data = json.loads(str(text or "").strip() or "{}")
    except ValueError:
        return {}
    return data if isinstance(data, dict) else {}


def words(code, out: str, err: str) -> str:
    """Why a command did not do what was asked, in its own words."""
    text = (err or "").strip() or (out or "").strip()
    return text.splitlines()[-1].strip() if text else f"it ended with {code}"


def build_of(version: str) -> int:
    """An image's Windows build from its OS version ("10.0.20348.2655": 20348); 0 when it has none."""
    parts = str(version or "").split(".")
    return int(parts[2]) if len(parts) >= 3 and parts[2].isdigit() else 0


def server_name(build: int) -> str:
    return SERVER_BUILDS.get(build, f"build {build}" if build else "")


def runs_here(host_build: int, client: bool, image_build: int) -> str:
    """Whether this Windows runs an image, and with which isolation (Microsoft's version compatibility)."""
    if not host_build or not image_build:
        return ""
    if image_build > host_build:
        return "not here: newer than this Windows"
    process = (image_build == host_build or (image_build == 20348 and ((client and host_build >= 22000) or host_build >= 26100))
               or (image_build == 26100 and host_build >= 26100))
    return "process or Hyper-V isolation" if process else "Hyper-V isolation only"


@dataclass(frozen=True)
class Image:
    engine: str
    id: str
    repository: str
    tag: str
    size: str = ""
    created: str = ""
    os: str = ""
    os_version: str = ""
    arch: str = ""

    @property
    def ref(self) -> str:
        if self.repository and self.repository != "<none>":
            return f"{self.repository}:{self.tag}" if self.tag and self.tag != "<none>" else self.repository
        return short(self.id)

    @property
    def build(self) -> int:
        return build_of(self.os_version)

    def describe(self) -> dict:
        return {"engine": self.engine, "id": self.id, "image": self.ref, "size": self.size, "created": self.created, "os": self.os,
                "osVersion": self.os_version, "architecture": self.arch}


@dataclass(frozen=True)
class Container:
    engine: str
    id: str
    name: str
    image: str
    state: str  # created, running, paused, restarting, removing, exited, dead
    status: str = ""  # "Up 3 minutes", "Exited (0) 2 hours ago"
    ports: str = ""
    created: str = ""
    command: str = ""
    isolation: str = ""  # process, hyperv; "" or default: the engine's default
    platform: str = ""

    @property
    def up(self) -> bool:
        return self.state in UP

    def describe(self) -> dict:
        return {"engine": self.engine, "id": self.id, "name": self.name, "image": self.image, "state": self.state,
                "status": self.status, "ports": self.ports, "created": self.created, "isolation": self.isolation,
                "platform": self.platform}


@dataclass(frozen=True)
class Engine:
    """An engine found: `key` (a Docker engine's pipe; containerd), whether it answers and why not, what it runs (OSType:
    windows or linux), its version, the Windows it reports, its default isolation, its containers and images (a Windows
    engine's), and `same_as`: another pipe reaching the same engine."""

    key: str
    kind: str  # docker | containerd
    exe: str
    endpoint: str = ""  # npipe:////./pipe/<key> (docker); "" for nerdctl's own
    source: str = ""  # how it was found: the pipe docker_engine, the context desktop-windows, nerdctl
    answers: bool = False
    why: str = ""
    os_type: str = ""
    version: str = ""
    os: str = ""
    isolation: str = ""
    name: str = ""
    id: str = ""
    desktop: bool = False
    same_as: str = ""
    containers: tuple = ()
    images: tuple = ()
    counted: tuple = ()  # (containers, running, images) as the engine counts them

    @property
    def windows(self) -> bool:
        return self.os_type == "windows"

    @property
    def denied(self) -> bool:
        return not self.answers and denied_words(self.why)

    @property
    def title(self) -> str:
        if self.kind == "containerd":
            return "containerd (nerdctl)"
        return "Docker Desktop" if self.desktop else "Docker Engine"

    @property
    def listed(self) -> bool:
        """Its containers and images are the plugin's: a Windows engine answering, not reached twice."""
        return self.answers and self.windows and not self.same_as

    def describe(self) -> dict:
        return {"key": self.key, "kind": self.kind, "title": self.title, "endpoint": self.endpoint, "source": self.source,
                "answers": self.answers, "why": self.why, "osType": self.os_type, "version": self.version, "os": self.os,
                "isolation": self.isolation, "sameAs": self.same_as, "containers": len(self.containers), "images": len(self.images)}


def short(identifier: str) -> str:
    s = str(identifier or "")
    return s[7:19] if s.startswith("sha256:") else s[:12]


def state_of(row: dict) -> str:
    """A container's state: docker's State, else read from its Status (nerdctl: "Up 2 minutes", "Exited (0) ...")."""
    state = str(row.get("State") or "").strip().lower()
    if state:
        return state
    status = str(row.get("Status") or "").strip().lower()
    for prefix, said in (("up", "running"), ("exited", "exited"), ("created", "created"), ("paused", "paused"),
                         ("restarting", "restarting"), ("removing", "removing"), ("dead", "dead")):
        if status.startswith(prefix):
            return "paused" if "paused" in status else said
    return status or "unknown"


def _inspected(text: str, fields: int) -> dict[str, list[str]]:
    """`inspect --format '{{.Id}}|...'` lines by the id they start with."""
    out = {}
    for line in str(text or "").splitlines():
        parts = line.strip().split("|")
        if len(parts) >= fields and parts[0]:
            out[parts[0]] = parts[1:]
    return out


def docker_engine(row: dict, exe: str, desktop: bool) -> Engine:
    """A Docker engine at one pipe (the read's Engines entry)."""
    endpoint = str(row.get("Endpoint") or "")
    key = endpoint.rsplit("/", 1)[-1] or endpoint
    code, out, err = native(row.get("Info"))
    info = json_doc(out)
    errors = [str(x) for x in (info.get("ServerErrors") or []) if x]
    answers = code == 0 and bool(info.get("ID") or info.get("ServerVersion")) and not errors
    why = "" if answers else ("; ".join(errors) or words(code, out if not info else "", err))
    same = str(row.get("Same") or "")
    desktop = desktop or "desktop" in key.lower() or "desktop" in str(row.get("From") or "").lower()
    found = Engine(key=key, kind="docker", exe=exe, endpoint=endpoint, source=str(row.get("From") or ""), answers=answers,
                   why=why, os_type=str(info.get("OSType") or ""), version=str(info.get("ServerVersion") or ""),
                   os=str(info.get("OperatingSystem") or ""), isolation=str(info.get("Isolation") or ""),
                   name=str(info.get("Name") or ""), id=str(info.get("ID") or ""), desktop=desktop,
                   same_as=same.rsplit("/", 1)[-1] if same else "",
                   counted=(int(info.get("Containers") or 0), int(info.get("ContainersRunning") or 0), int(info.get("Images") or 0)))
    if not found.listed:
        return found
    inspected = _inspected(native(row.get("Inspect"))[1], 4)
    containers = []
    for c in json_lines(native(row.get("Ps"))[1]):
        cid = str(c.get("ID") or "")
        isolation, platform, _ = (inspected.get(cid) or ["", "", ""])[:3]
        containers.append(Container(engine=key, id=cid, name=str(c.get("Names") or "").split(",")[0], image=str(c.get("Image") or ""),
                                    state=state_of(c), status=str(c.get("Status") or ""), ports=str(c.get("Ports") or ""),
                                    created=str(c.get("CreatedAt") or ""), command=str(c.get("Command") or "").strip('"'),
                                    isolation=isolation if isolation not in ("", "default") else "", platform=platform))
    images_inspected = _inspected(native(row.get("ImageInspect"))[1], 4)
    images = []
    for i in json_lines(native(row.get("Images"))[1]):
        iid = str(i.get("ID") or "")
        os_name, os_version, arch = (images_inspected.get(iid) or ["", "", ""])[:3]
        images.append(Image(engine=key, id=iid, repository=str(i.get("Repository") or ""), tag=str(i.get("Tag") or ""),
                            size=str(i.get("Size") or ""), created=str(i.get("CreatedSince") or i.get("CreatedAt") or ""),
                            os=os_name, os_version=os_version, arch=arch))
    return replace(found, containers=tuple(containers), images=tuple(images))


def containerd_engine(row: dict, exe: str) -> Engine:
    """containerd through nerdctl (the read's Containerd entry): its default namespace's containers and images."""
    code, out, err = native(row.get("Info"))
    info = json_doc(out)
    answers = code == 0 and bool(info)
    why = "" if answers else words(code, out, err)
    os_type = str(info.get("OSType") or ("windows" if answers else "")).lower()
    found = Engine(key="containerd", kind="containerd", exe=exe, source="nerdctl", answers=answers, why=why, os_type=os_type,
                   version=str(info.get("ServerVersion") or ""), os=str(info.get("OperatingSystem") or ""),
                   isolation=str(info.get("Isolation") or ""), name=str(info.get("Name") or ""), id=str(info.get("ID") or ""))
    if not found.listed:
        return found
    containers = tuple(Container(engine="containerd", id=str(c.get("ID") or ""), name=str(c.get("Names") or "").split(",")[0],
                                 image=str(c.get("Image") or ""), state=state_of(c), status=str(c.get("Status") or ""),
                                 ports=str(c.get("Ports") or ""), created=str(c.get("CreatedAt") or ""),
                                 command=str(c.get("Command") or "").strip('"'), platform=str(c.get("Platform") or ""))
                       for c in json_lines(native(row.get("Ps"))[1]))
    images = tuple(Image(engine="containerd", id=str(i.get("ID") or ""), repository=str(i.get("Repository") or ""),
                         tag=str(i.get("Tag") or ""), size=str(i.get("Size") or ""),
                         created=str(i.get("CreatedSince") or i.get("CreatedAt") or ""),
                         os=str(i.get("Platform") or "").split("/")[0]) for i in json_lines(native(row.get("Images"))[1]))
    running = sum(1 for c in containers if c.up)
    return replace(found, containers=containers, images=images, counted=(len(containers), running, len(images)))


def compute_systems(text: str) -> list[str]:
    """`hcsdiag list` as it says it: its lines (the Host Compute Service's containers and VMs: Windows containers, Windows
    Sandbox, WSL 2's VM), at most 60."""
    return [line.rstrip() for line in str(text or "").splitlines() if line.strip()][:60]
