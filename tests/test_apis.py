"""What the plugin attaches to (plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the the API its attached
to, and present links that provide documentation"): its cards are sound; they name every program it runs and every
command it gives each (docker at a pipe, nerdctl, wsb, WindowsSandbox.exe, hcsdiag: read from the scripts the stand-in
powershell.exe is given, the read's and each change's) and every cmdlet the read runs, and none it does not; its facts
ask nothing; and, with LIMINAL_VENDOR_PAGES=1 alone, every address on them answers (the only test here that reaches the
network)."""
from __future__ import annotations

import os
import re

import pytest

import plugin_platform_windows_containers as wc
from liminal_libs.sources import apis as A
from liminal_libs.sources.conformance import problems
from plugin_platform_windows_containers import apis as cards
from plugin_platform_windows_containers import scripts
from test_plugin import BUILD, CLASSIC, DOCKER, IIS, NERDCTL, PINGER, SANDBOX_ID, WSB, FakeWindows, folder, plugin, ran  # noqa: F401

NATIVE = re.compile(r"Invoke-Native (\$out\.Docker|\$out\.Nerdctl|\$out\.Hcsdiag|\$wsb) \(?@\(([^)]*)\)")
PROGRAMS = {"$out.Docker": "docker", "$out.Nerdctl": "nerdctl", "$out.Hcsdiag": "hcsdiag", "$wsb": "wsb",
            DOCKER: "docker", NERDCTL: "nerdctl", WSB: "wsb", CLASSIC: "WindowsSandbox.exe"}
GROUPS = {"context", "container", "image"}  # docker's two-word commands among those asked
CMDLET = re.compile(r"(?<![-\w'])[A-Z][a-z]+-[A-Z][A-Za-z]+(?![-\w'])")  # Verb-Noun, never quoted (a feature's name is)
PLUMBING = {"ForEach-Object", "Where-Object", "Select-Object", "Write-Output", "Get-Command", "Test-Path", "Join-Path",
            "New-Object", "ConvertFrom-Json", "ConvertTo-Json", "Invoke-Native", "Find-Program"}  # PowerShell's, the script's


def command(program: str, words) -> str:
    """A program's command by its words, its pipe (-H PIPE) and wsb's --raw left out: docker info, wsb list."""
    words = [w for w in words if w]
    if "-H" in words:
        i = words.index("-H")
        words = words[:i] + words[i + 2:]
    words = [w for w in words if w != "--raw"]
    if program == "WindowsSandbox.exe":
        return program
    head = " ".join(words[:2]) if program == "docker" and words[0] in GROUPS else words[0]
    return f"{program} {head}"


class Containerd(FakeWindows):
    """The stand-in with containerd beside Docker, its container stopped and started as nerdctl is told."""

    def __init__(self, **kw):
        super().__init__(nerdctl=True, **kw)
        self.nano_up = True

    def native(self, exe, argv):
        if exe == NERDCTL and argv[0] in ("start", "stop"):
            self.ran.append((exe, argv))
            self.nano_up = argv[0] == "start"
            return ran(argv[-1] + "\n")
        return super().native(exe, argv)

    def reading(self):
        out = super().reading()
        if not self.nano_up:
            ps = out["Containerd"]["Ps"]
            ps["Out"] = ps["Out"].replace('"Status": "Up 5 minutes"', '"Status": "Exited (0) 1 second ago"')
        return out


def card(name: str) -> A.Api:
    return next(a for a in wc.MACHINE.apis if a.name == name)


def flows(folder):
    """The plugin reading and making every change it makes: containers on Docker's pipe and on containerd started,
    stopped and removed, a sandbox launched with a .wsb and with the defaults, closed, and one opened by Windows
    Sandbox's own program where wsb is not. Every command, as given."""
    p, fake = plugin(Containerd(rights=True), folder=folder)
    p.status()
    p.start_container("iis", "docker_engine", IIS)
    p.stop_container(PINGER[:12])
    p.remove_container("build", None, BUILD)
    p.stop_container("nano-ping", "containerd")
    p.start_container("nano-ping", "containerd")
    p.remove_container("nano-ping", "containerd", None, True)
    p.launch_sandbox(str(folder / "tools.wsb"), True)
    p.launch_sandbox(None)
    p.stop_sandbox(SANDBOX_ID)
    classic, old = plugin(FakeWindows(sandbox="classic"), folder=folder)
    classic.launch_sandbox(str(folder / "tools.wsb"), True)
    return fake, old


def test_its_cards_are_sound_and_written_for_plugin_api_2_2():
    p = wc.MACHINE
    assert p.api == "2.2" and problems(p) == [] and A.problems(p.apis) == []
    assert [a.name for a in p.apis] == [cards.PLATFORM, cards.DOCKER, cards.NERDCTL, cards.SANDBOX]
    for a in p.apis:
        assert a.verified == "2026-11-11" and a.docs.startswith("https://") and a.used and a.covered
        assert all(c.area in {x.name for x in a.areas} for c in a.calls), a.name
        assert len(a.areas) > len(a.covered) and len(a.calls) > len(a.used)  # more of the API than the plugin uses


def test_the_cards_name_every_command_and_cmdlet_the_plugin_runs_and_no_other(folder):
    fake, old = flows(folder)
    text = "\n".join(fake.scripts + old.scripts)
    ran_ = {command(PROGRAMS[exe], [a or b for a, b in re.findall(r"'([^']*)'|(\$\w+)", args)])
            for exe, args in NATIVE.findall(scripts.READ)}  # the read's programs, as its script writes them
    ran_ |= {command(PROGRAMS[exe], argv) for exe, argv in fake.ran + old.ran}  # each change's, as it was given
    if "'connect --id '" in text:  # the window of a sandbox wsb started, opened apart (ProcessStartInfo)
        ran_.add("wsb connect")
    programs = {cards.DOCKER: "docker", cards.NERDCTL: "nerdctl", cards.SANDBOX: "wsb", cards.PLATFORM: "hcsdiag"}
    claimed = set()
    for name, program in programs.items():
        for c in card(name).used:
            first = c.name.split()[0]
            if first in (program, "WindowsSandbox.exe"):
                claimed.add(command(first, c.name.split()[1:]) if first != "WindowsSandbox.exe" else first)
    assert ran_ == claimed, ran_ ^ claimed
    cmdlets = set(CMDLET.findall(scripts.READ)) - PLUMBING
    named = {c.name.split()[0] for a in wc.MACHINE.apis for c in a.used if CMDLET.fullmatch(c.name.split()[0])}
    assert cmdlets == named, cmdlets ^ named
    for a in wc.MACHINE.apis:  # each cmdlet as the read script writes it; the pipes as it lists them
        for c in a.used:
            if CMDLET.fullmatch(c.name.split()[0]) or c.name.startswith("GetFiles("):
                assert c.name.replace("WindowsSandbox*", "WindowsSandbox") in scripts.READ, c.name
    writes = {command(c.name.split()[0], c.name.split()[1:]) for a in wc.MACHINE.apis for c in a.used if c.writes
              and c.name.split()[0] in ("docker", "nerdctl", "wsb")}
    assert writes == {"docker start", "docker stop", "docker rm", "nerdctl start", "nerdctl stop", "nerdctl rm", "wsb start",
                      "wsb stop"}
    assert not any(c.costs for a in wc.MACHINE.apis for c in a.calls)


def test_its_facts_say_what_it_learned_and_ask_nothing(folder):
    assert wc.WindowsContainersPlugin(system="win32").api_facts() == {}  # nothing read yet: nothing asked
    p, fake = plugin(FakeWindows(nerdctl=True, rights=True), folder=folder)
    p.status()
    before = len(fake.scripts)
    facts = A.facts_of(p)
    assert len(fake.scripts) == before  # asked nothing to answer
    assert facts[cards.DOCKER]["docker_engine"].startswith("Docker Engine 27.3.1: windows containers, Hyper-V isolation")
    assert facts[cards.NERDCTL]["containerd"] == "v2.1.4, windows containers"
    assert facts[cards.SANDBOX]["Running"] == "1 (wsb list)" and facts[cards.PLATFORM]["Containers"] == "on"
    assert facts[cards.PLATFORM]["Compute systems"] == "2 lines listed"


@pytest.mark.skipif(os.environ.get("LIMINAL_VENDOR_PAGES") != "1", reason="reaches the makers' pages: LIMINAL_VENDOR_PAGES=1")
def test_every_address_on_its_cards_answers(monkeypatch):
    monkeypatch.undo()  # this test alone reaches the network (conftest refuses it to every other)
    assert A.dead_links(wc.MACHINE.apis) == []
