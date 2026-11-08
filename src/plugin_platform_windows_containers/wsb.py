"""Windows Sandbox's configuration files (.wsb: XML, <Configuration> at its root), read and said in words before a
sandbox is launched with one: what the sandbox may reach (the network, this PC's folders mapped into it and whether it may
write to them, the microphone, the camera, the printers, the clipboard), what it runs once signed in, its memory, its GPU.
The settings and their defaults are Microsoft's (learn.microsoft.com, "Use and configure Windows Sandbox"): networking,
the GPU, the microphone and the clipboard are on unless the file turns them off; the camera, the printers and the
protected client are off unless it turns them on.

The file is the user's own; still, a .wsb holds no DOCTYPE or ENTITY, so one that does is refused rather than parsed,
and one larger than MAX_BYTES is refused unread."""
from __future__ import annotations

import hashlib
import os
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath

MAX_BYTES = 64 * 1024  # a .wsb larger than this is not read
CONFIG_MAX = 16 * 1024  # what `wsb start --config` is given (a Windows command line holds at most 32,767 characters)
LISTED = 50  # the .wsb files of the folder listed, at most
DIR_VAR = "LIMINAL_PLATFORM_DIR"  # the platform's own folder (its app's variable)
USER = "WDAGUtilityAccount"  # the sandbox's own user, whose desktop a folder without a SandboxFolder is mapped to
# each switch-like setting: (its words, on by default)
SETTINGS = {
    "Networking": ("the network", True),
    "vGPU": ("the GPU", True),
    "AudioInput": ("your microphone", True),
    "VideoInput": ("your camera", False),
    "PrinterRedirection": ("your printers", False),
    "ClipboardRedirection": ("the clipboard", True),
    "ProtectedClient": ("the protected client (an AppContainer around the sandbox's window)", False),
}
KNOWN = {k.lower() for k in (*SETTINGS, "MappedFolders", "LogonCommand", "MemoryInMB")}


def sandboxes_dir() -> Path:
    """Where the page looks for .wsb files: the platform's folder's windows-containers/sandboxes (LIMINAL_PLATFORM_DIR, else
    the data folder's platform/). Nothing is made there: a .wsb is the user's to put in."""
    named = (os.environ.get(DIR_VAR) or "").strip()
    if named:
        return Path(named).expanduser() / "windows-containers" / "sandboxes"
    from liminal_libs import layout

    return layout.data_dir() / "platform" / "windows-containers" / "sandboxes"


@dataclass(frozen=True)
class Folder:
    host: str
    sandbox: str  # "": the sandbox user's desktop
    read_only: bool

    def words(self) -> str:
        to = self.sandbox or str(PureWindowsPath("C:/Users", USER, "Desktop", PureWindowsPath(self.host).name))
        return f"{self.host} as {to}, " + ("read-only" if self.read_only else "writable: what the sandbox writes there stays")


@dataclass(frozen=True)
class Config:
    """A .wsb as read: its settings (True on, False off, None the default), its folders, its logon command, its memory;
    `xml` compact for `wsb start --config`; `problem`: why Windows Sandbox would not start with it ("" when it would)."""

    path: str = ""
    digest: str = ""
    size: int = 0
    modified: float = 0.0
    settings: tuple = ()  # ((name, True | False | None), ...)
    folders: tuple = ()
    logon: str = ""
    memory_mb: int | None = None
    xml: str = ""
    unknown: tuple = ()
    problem: str = ""

    @property
    def name(self) -> str:
        return Path(self.path).name if self.path else "Windows Sandbox's defaults"

    def on(self, setting: str) -> bool:
        value = dict(self.settings).get(setting)
        return SETTINGS[setting][1] if value is None else value

    @property
    def read_as(self) -> str:
        """When the file was read as it is, in words (the launch form's "Read" field)."""
        when = time.strftime("%b %d %H:%M", time.localtime(self.modified)) if self.modified else "–"
        return f"changed {when}, {self.size:,} bytes"

    def lines(self) -> list[str]:
        """What it gives the sandbox, a line each."""
        out = []
        for setting, (what, default) in SETTINGS.items():
            value = dict(self.settings).get(setting)
            state = self.on(setting)
            if setting == "ProtectedClient" and not state:
                continue
            out.append(f"{what}: {'on' if state else 'off'}" + (" (the default)" if value is None and state == default else ""))
        out += [f"mapped: {f.words()}" for f in self.folders]
        if self.logon:
            out.append(f"at logon it runs: {self.logon}")
        out.append(f"memory: {self.memory_mb:,} MB" if self.memory_mb else "memory: Windows Sandbox's own (at most 4 GB)")
        if self.unknown:
            out.append("settings this plugin does not know: " + ", ".join(self.unknown))
        return out

    def words(self) -> str:
        """What it gives the sandbox in one paragraph: what the confirmation says."""
        shared = [s for s in SETTINGS if s != "ProtectedClient"]
        reach = [SETTINGS[s][0] for s in shared if self.on(s)]
        if self.on("Networking"):
            reach[0] = "the network (yours and the internet, through Hyper-V's Default Switch)"
        off = [SETTINGS[s][0] for s in shared if not self.on(s)]
        said = "Shared with it: " + ", ".join(reach) + "." if reach else "Nothing of this PC's is shared with it."
        if off:
            said += " Not shared: " + ", ".join(off) + "."
        said += "".join(f" It maps {f.words()}." for f in self.folders) or " No folder of this PC is mapped into it."
        if self.logon:
            said += f" Once signed in it runs {self.logon}."
        said += f" Memory: {self.memory_mb:,} MB." if self.memory_mb else " Memory: Windows Sandbox's own (at most 4 GB)."
        if self.on("ProtectedClient"):
            said += " Its window is a protected client (an AppContainer)."
        if self.unknown:
            said += " Settings this plugin does not know: " + ", ".join(self.unknown) + "."
        return said


DEFAULT = Config()  # no file: Windows Sandbox's own defaults


def _flag(element, name: str) -> tuple[bool | None, str]:
    """A setting's value: Enable, Disable, Default (or absent: None); what is wrong with it otherwise."""
    if element is None:
        return None, ""
    text = (element.text or "").strip().lower()
    if text in ("enable", "enabled", "true"):
        return True, ""
    if text in ("disable", "disabled", "false"):
        return False, ""
    if text in ("", "default"):
        return None, ""
    return None, f"{name} is {element.text!r}: Enable, Disable or Default"


def parse(text: str, path: str = "", size: int = 0, modified: float = 0.0, digest: str = "", exists=os.path.isdir) -> Config:
    """A .wsb's text read (ValueError when it is not one); `exists` checks a mapped folder on this PC (Windows Sandbox
    does not start when one is missing)."""
    name = Path(path).name if path else "the configuration"
    if re.search(r"<!\s*(DOCTYPE|ENTITY)", text, re.IGNORECASE):
        raise ValueError(f"{name} declares a DOCTYPE or an ENTITY, which a .wsb never does: it is not read")
    body = re.sub(r"^\s*<\?xml[^>]*\?>", "", text.lstrip("\ufeff")).strip()
    try:
        root = ET.fromstring(body)
    except ET.ParseError as e:
        raise ValueError(f"{name} is not well-formed XML ({e})") from None
    if root.tag.lower() != "configuration":
        raise ValueError(f"{name}'s root is <{root.tag}>, not <Configuration>: it is not a Windows Sandbox configuration")
    children = {c.tag.lower(): c for c in root}
    settings, problems = [], []
    for setting in SETTINGS:
        value, wrong = _flag(children.get(setting.lower()), setting)
        settings.append((setting, value))
        if wrong:
            problems.append(wrong)
    folders = []
    mapped = children.get("mappedfolders")
    for f in (list(mapped) if mapped is not None else []):
        if f.tag.lower() != "mappedfolder":
            continue
        parts = {c.tag.lower(): (c.text or "").strip() for c in f}
        host = parts.get("hostfolder", "")
        if not host:
            problems.append("a MappedFolder has no HostFolder")
            continue
        expanded = os.path.expandvars(host)
        if not re.match(r"^([A-Za-z]:[\\/]|\\\\)", expanded):
            problems.append(f"{host} is not an absolute path (Windows Sandbox maps absolute ones only)")
        elif not exists(expanded):
            problems.append(f"{host} is not a folder on this PC (Windows Sandbox does not start without it)")
        folders.append(Folder(host, parts.get("sandboxfolder", ""), parts.get("readonly", "").lower() == "true"))
    logon = children.get("logoncommand")
    command = ""
    if logon is not None:
        command = " ".join((c.text or "").strip() for c in logon if c.tag.lower() == "command").strip()
    memory = None
    m = children.get("memoryinmb")
    if m is not None:
        raw = (m.text or "").strip()
        if raw.isdigit() and int(raw) > 0:
            memory = int(raw)
        else:
            problems.append(f"MemoryInMB is {raw!r}: a number of megabytes")
    unknown = tuple(sorted(c.tag for c in root if c.tag.lower() not in KNOWN))
    compact = re.sub(r">\s+<", "><", body)
    return Config(path=path, digest=digest, size=size, modified=modified, settings=tuple(settings), folders=tuple(folders),
                  logon=command, memory_mb=memory, xml=compact, unknown=unknown, problem="; ".join(problems))


def read(path, exists=os.path.isdir) -> Config:
    """A .wsb file read from this PC (ValueError saying why it is not one Windows Sandbox can start with)."""
    p = Path(str(path or "").strip().strip('"'))
    if p.suffix.lower() != ".wsb":
        raise ValueError(f"{p.name or path!r} is not a .wsb file (Windows Sandbox's configuration)")
    if not p.is_absolute():
        raise ValueError(f"{p} is not a full path: give the .wsb's whole path (C:\\Users\\you\\sandbox.wsb)")
    try:
        st = p.stat()
    except OSError as e:
        raise ValueError(f"{p} cannot be read: {e.strerror or e}") from None
    if not p.is_file():
        raise ValueError(f"{p} is not a file")
    if st.st_size > MAX_BYTES:
        raise ValueError(f"{p} is {st.st_size:,} bytes: a .wsb is a few lines, and one over {MAX_BYTES:,} bytes is not read")
    raw = p.read_bytes()
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        text = raw.decode("utf-16")
    else:
        text = raw.decode("utf-8-sig", errors="replace")
    return parse(text, path=str(p), size=st.st_size, modified=st.st_mtime, digest=hashlib.sha256(raw).hexdigest()[:16], exists=exists)


def listed(folder: Path, exists=os.path.isdir) -> list[tuple[Path, Config | None, str]]:
    """The folder's .wsb files (at most LISTED, by name): each read, or why it could not be."""
    try:
        files = sorted((f for f in folder.iterdir() if f.suffix.lower() == ".wsb" and f.is_file()), key=lambda f: f.name.lower())
    except OSError:
        return []
    out = []
    for f in files[:LISTED]:
        try:
            out.append((f, read(f, exists=exists), ""))
        except ValueError as e:
            out.append((f, None, str(e)))
    return out
