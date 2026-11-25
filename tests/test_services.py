"""0.3.0: the one "run a service" interface (liminal-libs 1.93.0's ContainerHost) on a Docker engine for Windows
containers at its pipe. The plugin reads this PC through its stand-in powershell.exe (test_plugin.FakeWindows: Windows
11, build 26300) and is attached to a real apps.App beside the library's stand-in firewall and stand-in service plugins,
so the asker's gates are the real ones. Every docker.exe command goes through the plugin's own runner to the library's
FakeDocker, taught Windows' paths and docker.exe's pipe (FakeWindowsDocker): nothing runs, nothing is pulled, no port is
opened, no NAT network is made."""
from __future__ import annotations

import copy
import io
import json
import subprocess
import tarfile

import pytest

from liminal_libs.apps import App, asking
from liminal_libs.apps.asking import AskRefused
from liminal_libs.instances import Refusal
from liminal_libs.machines import standins
from liminal_libs.machines.containers import ImagePin, ServiceSpec
from liminal_libs.machines.standins import FakeDocker, ServiceOwner, StandInNetworkHost
from plugin_platform_windows_containers import Refusal as PluginRefusal
from plugin_platform_windows_containers import WindowsContainersPlugin, scripts, services
from liminal_libs.machines.windows import PowerShell
from test_plugin import DOCKER, HOST_FOLDERS, FakeWindows

PIPE = "npipe:////./pipe/docker_engine"
DIG = "sha256:" + "a" * 64
SECRET = "canary-Wn42-never-shown"
HOME = "C:\\ProgramData\\Jenkins\\JenkinsHome"
NAT_PREFIX = "172.29.16.0/20"
BUILDS = {20348: "10.0.20348.2655", 17763: "10.0.17763.7792", 26100: "10.0.26100.6899", 26400: "10.0.26400.1"}


def _norm(path: str) -> str:
    return str(path or "").replace("\\", "/").rstrip("/")


class FakeWindowsDocker(FakeDocker):
    """The library's FakeDocker as docker.exe at a pipe answers: its global -H skipped, --isolation taken, Windows'
    paths inside a container (C:\\...), the engine's own nat network (HNS hands its members their addresses), an image's
    OsVersion, and the image's cmd, tar.exe and PowerShell in throwaway containers."""

    VALUED = (*FakeDocker.VALUED, "--isolation", "-H")

    def __init__(self, nat: bool = True, build: int = 20348):
        super().__init__(version="27.3.1")
        self.build = build
        self.next_ip = 10
        if nat:
            self.networks["nat"] = {"id": "e" * 64, "labels": {}, "options": {}, "subnet": NAT_PREFIX,
                                    "gateway": "172.29.16.1", "ip_range": "", "driver": "nat"}

    def _words(self, argv):
        argv = [str(a) for a in argv]
        if len(argv) > 2 and argv[1] == "-H":
            return argv[3:]
        return super()._words(argv)

    def _answer(self, key, args, stdin, env, out):
        if key == "image inspect" and "{{.OsVersion}}" in args:
            ref = args[-1]
            return (0, BUILDS.get(self.build, f"10.0.{self.build}.1"), "") if ref in self.images else \
                (1, "", f"Error: No such image: {ref}")
        return super()._answer(key, args, stdin, env, out)

    def _create(self, args, env):
        code, cid, err = super()._create(args, env)
        if code == 0:
            c = next(x for x in self.containers.values() if x["id"] == cid)
            c["mounts"] = []
            for v in [args[i + 1] for i, a in enumerate(args) if a == "-v"]:
                vol, _, path = v.partition(":")
                c["mounts"].append((vol, path[:-3] if path.endswith(":ro") else path))
            if c["network"] == "nat":
                self.next_ip += 1
                c["ip"] = f"172.29.16.{self.next_ip}"
        return code, cid, err

    def _volume_at(self, c, path):
        best = None
        for vol, mount in c["mounts"]:
            m = _norm(mount)
            p = _norm(path)
            if p == m or p.startswith(m + "/"):
                if best is None or len(m) > len(best[1]):
                    best = (vol, m)
        return best

    def _read_path(self, c, path):
        found = self._volume_at(c, path)
        if found is None:
            return None
        vol, mount = found
        return self.volumes.get(vol, {}).get("files", {}).get(_norm(path)[len(mount):].lstrip("/"))

    def _cp(self, args, stdin):
        words = [a for a in args[1:] if a != "-a"]
        if words[0] == "-":
            c = self._find(words[1].split(":", 1)[0])
            if words[1].split(":", 1)[1] != "C:\\":
                return 1, "", "the stand-in takes seeds at C:\\ alone"
            with tarfile.open(fileobj=io.BytesIO(stdin or b""), mode="r:") as tar:
                for m in tar.getmembers():
                    path = "C:/" + m.name
                    found = self._volume_at(c, path)
                    if found is None:
                        return 1, "", f"the stand-in writes seeds into volumes alone, not {path}"
                    vol, mount = found
                    rel = _norm(path)[len(mount):].lstrip("/")
                    if rel in self.volumes[vol]["files"]:
                        return 1, "", f"the stand-in: {path} is there already"
                    self.volumes[vol]["files"][rel] = tar.extractfile(m).read()
            return 0, "", ""
        return super()._cp(args, stdin)

    def _run(self, args, stdin, out):
        if args[args.index("--entrypoint") + 1] == "powershell":
            vol = [args[i + 1] for i, a in enumerate(args) if a == "-v"][0].split(":")[0]
            self.volumes[vol]["files"].clear()
            return 0, "", ""
        return super()._run(args, stdin, out)


class Frame(App):
    NAME = "frame"

    def __init__(self, login):
        super().__init__(log=lambda m: None, login=login)
        self.off: set[str] = set()

    def disabled(self):
        return set(self.off)

    def known_plugins(self):
        return list(self._plugins.values())


def spec(owner="jenkins", name="ci", host=8080, lan=True, secrets=(), build=20348, system="windows"):
    image = {"ref": "docker.io/jenkins/jenkins:2.528.2-lts-jdk21-windowsservercore-ltsc2022", "digest": DIG,
             "system": system, "platforms": [f"{system}/amd64"], "os_build": build if system == "windows" else 0,
             "size": 3_600_000_000, "licence": "MIT"}
    return {"owner": owner, "name": name, "title": owner.capitalize(), "system": system, "parts": [{
        "name": "controller", "image": image,
        "ports": [{"name": "web", "container": 8080, "host": host, "lan": lan}],
        "volumes": [{"name": "home", "path": HOME if system == "windows" else "/var/jenkins_home",
                     "holds": "its jobs and history"}],
        "env": {"JAVA_OPTS": "-Dhudson.model.UsageStatistics.disabled=true"}, "secrets": list(secrets),
        "readable": [{"name": "unlock", "volume": "home", "path": "secrets/initialAdminPassword"}],
        "seeds": [{"volume": "home", "path": "init.groovy.d/off.groovy", "text": "// usage statistics off\n"}],
        "memory": 2 << 30, "health": {"port": "web", "path": "/login", "ready_s": 30}}]}


class World:
    def __init__(self, tmp_path, windows: FakeWindows | None = None, nat=True, build=20348):
        self.fake = FakeWindowsDocker(nat=nat, build=build)
        self.windows = windows or FakeWindows()
        self.login = standins.login({"JENKINS_ADMIN_PASSWORD": SECRET})
        out = standins.Outside(sleep=lambda s: None, health=lambda h, p, path: True, platform="windows::TEST",
                               holders=lambda port: [], folder=tmp_path)
        self.plugin = WindowsContainersPlugin(PowerShell(runner=self.windows, env={}), system="win32", env={},
                                              exists=lambda path: path in HOST_FOLDERS, service_runner=self.fake,
                                              streamer=self.fake.stream, outside=out)
        self.app = Frame(self.login)
        self.firewall = StandInNetworkHost(own="windows", routes_to=("wsl",))
        self.jenkins = ServiceOwner("jenkins", host="windows-containers")
        self.gocd = ServiceOwner("gocd", host="windows-containers")
        for p in (self.plugin, self.firewall, self.jenkins, self.gocd):
            self.app.attach(p)

    def page(self, plugin, hook, *args):
        with asking.asking(asking.PAGE):
            return self.app.ask(plugin, hook, *args)

    def grant(self, plugin="jenkins"):
        self.page("windows-containers", "grant_service", plugin, "docker_engine")
        if "windows-containers" not in self.firewall.network_grants():
            self.page("standin-firewall", "grant_network", "windows-containers")

    def wait(self, work, who=None):
        w = self.plugin._svc.works.get(work)
        w.thread.join(20)
        assert not w.thread.is_alive()
        return (who or self.jenkins).call("service_work", work, 0)

    def carry(self, action, spec_=None, options=None, target="", who=None):
        who = who or self.jenkins
        plan = who.call("service_plan", action, f"{who.name}/ci", spec_, target, options or {})
        for a in plan["approve"]:
            words = self.page(a["plugin"], "plan_words", a["plan"])
            needed = {x["name"] for x in words["accepts"]}
            order = standins._ACCEPT_ORDER[a["plugin"] == "windows-containers"]
            self.page(a["plugin"], "approve_plan", a["plan"], *[k in needed for k in order])
        return plan, self.wait(who.call("apply_plan", plan["plan"])["work"], who=who)

    def runtime(self):
        return self.plugin.runtime_of(self.plugin.target("docker_engine"))


@pytest.fixture
def world(tmp_path):
    return World(tmp_path)


def test_each_windows_engine_at_its_pipe_is_a_target_and_its_fit_says_how(world):
    got = world.jenkins.call("hosting", "jenkins", {"windows": spec()})
    assert [t["id"] for t in got["targets"]] == ["docker_engine"] and got["runtime"] == "windows-containers"
    t = got["targets"][0]
    assert (t["state"], t["system"], t["mechanism"], t["stack"], t["path"], t["firewall"]) == (
        "ready", "windows", "docker-windows", "windows", "direct", "windows")
    assert t["version"] == "27.3.1" and "Windows build 26300" in t["title"] and t["wsl"] == ""
    fit = t["fit"]
    assert fit["takes"] == ""
    assert fit["parts"]["network"]["fit"] == "differs" and NAT_PREFIX in fit["parts"]["network"]["words"]
    assert "N26" in fit["parts"]["network"]["words"]
    image = fit["parts"]["image"]
    assert image["fit"] == "exact" and "process isolation" in image["words"] and "3.6 GB" in image["words"]
    assert "Server Core images are several GB" in image["words"]
    assert world.fake.argv_of("network inspect") == [[DOCKER, "-H", PIPE, "network", "inspect", "nat"]]


def test_an_install_runs_docker_exe_at_its_pipe_and_never_powershell(world):
    world.grant()
    plan, end = world.carry("install", spec(secrets=[{"variable": "JENKINS_ADMIN_PASSWORD", "env": "ADMIN_PASSWORD"}]),
                            target="docker_engine")
    assert end["ok"], end
    assert {a["name"] for a in plan["accepts"]} == {"accept_differs", "accept_kept_secret", "accept_lan"}
    assert all(c["argv"][:3] == [DOCKER, "-H", PIPE] for c in world.fake.calls)
    assert world.windows.scripts and all(scripts.READ_MARK in s for s in world.windows.scripts)  # PowerShell: the read alone
    create = world.fake.argv_of("create")[0]
    line = " ".join(create)
    assert "--restart no --isolation process" in line and f"--memory {2 << 30}" in line and "--network nat" in line
    assert "--ip" not in create and "--network-alias" not in create and "--shm-size" not in create
    assert "-p 8080:8080/tcp" in line and "-e ADMIN_PASSWORD" in line and SECRET not in line
    assert f"-v liminal-jenkins-ci-home:{HOME}" in line and line.endswith("@" + DIG)
    assert next(c for c in world.fake.calls if c["key"] == "create")["env"] == {"ADMIN_PASSWORD": SECRET}  # no WSLENV
    assert world.fake.argv_of("network create") == [] and set(world.fake.networks) == {"nat"}
    assert world.fake.volumes["liminal-jenkins-ci-home"]["files"]["init.groovy.d/off.groovy"] == b"// usage statistics off\n"
    cp = next(c for c in world.fake.calls if c["key"] == "cp")
    assert cp["argv"][-2:] == ["-", "liminal-jenkins-ci-controller:C:\\"]
    said = json.dumps([plan, end, world.page("windows-containers", "status")])
    assert SECRET not in said
    assert any("found" in line_ and "liminal-jenkins-ci" in line_ for line_ in end["lines"])  # nat joined, none made


def test_a_linux_image_cannot_run_on_windows_containers(world):
    world.grant()
    linux = spec(system="linux")
    got = world.jenkins.call("hosting", "jenkins", {"linux": linux})
    assert got["targets"][0]["fit"] is None  # a Windows engine is judged for a Windows spec alone
    fit = world.runtime().fit(ServiceSpec.of(linux))
    assert fit.parts["image"].fit == "cannot" and "Windows images alone" in fit.takes
    with pytest.raises(Refusal, match="Windows images alone"):
        world.jenkins.call("service_plan", "install", "jenkins/ci", linux, "docker_engine", {})
    assert world.fake.changes() == []


@pytest.mark.parametrize("owner", ["gocd", "buildbot"])
def test_gocd_and_buildbot_are_not_yet_on_windows_containers(tmp_path, owner):
    w = World(tmp_path)
    who = ServiceOwner(owner, host="windows-containers")
    if owner != "gocd":
        w.app.attach(who)
    else:
        who = w.gocd
    linux = spec(owner=owner, system="linux")
    got = who.call("hosting", owner, {"linux": linux})
    fit = got["targets"][0]["fit"]
    assert fit["parts"]["image"]["fit"] == "cannot" and "not yet" in fit["takes"] and "decision 14 a" in fit["takes"]
    w.page("windows-containers", "grant_service", owner, "docker_engine")
    with pytest.raises(Refusal, match="not yet"):  # a Windows spec made for one anyway is refused all the same
        who.call("service_plan", "install", f"{owner}/ci", spec(owner=owner), "docker_engine", {})
    assert w.fake.changes() == []


def test_the_isolation_is_chosen_from_the_recorded_builds(tmp_path):
    rt = World(tmp_path).runtime()  # Windows 11 build 26300, Hyper-V on
    for build, iso in ((20348, "process"), (26100, "process"), (26300, "process"), (17763, "hyperv"), (26400, "")):
        assert rt.isolation(ImagePin.of({**spec(build=build)["parts"][0]["image"]}))[0] == iso, build
    newer = rt.fit(ServiceSpec.of(spec(build=26400)))
    assert newer.parts["image"].fit == "cannot" and "newer than this Windows" in newer.takes
    unpinned = rt.fit(ServiceSpec.of(spec(build=0)))
    assert "not pinned (os_build)" in unpinned.takes
    off = World(tmp_path, windows=FakeWindows(hyperv=False)).runtime()
    assert "Hyper-V is off" in off.fit(ServiceSpec.of(spec(build=17763))).takes
    assert off.fit(ServiceSpec.of(spec(build=20348))).takes == ""
    pins = [ImagePin.of({**spec(build=b)["parts"][0]["image"], "digest": "sha256:" + d * 64}) for b, d in
            ((17763, "1"), (20348, "2"), (26100, "3"), (26400, "4"))]
    assert services.choose_pin(pins, 26300, True, True).os_build == 26100  # process isolation, the newest
    assert services.choose_pin(pins[:1], 26300, True, True).os_build == 17763  # Hyper-V isolation, as the only one
    assert services.choose_pin(pins[:1], 26300, True, False) is None


def test_an_older_build_is_made_with_hyper_v_isolation(tmp_path):
    w = World(tmp_path, build=17763)
    w.grant()
    _, end = w.carry("install", spec(build=17763), target="docker_engine")
    assert end["ok"], end
    assert "--isolation hyperv" in " ".join(w.fake.argv_of("create")[0])


def test_a_port_for_this_pc_alone_differs_since_windows_nat_takes_no_host_address(world):
    fit = world.runtime().fit(ServiceSpec.of(spec(lan=False)))
    assert fit.parts["ports"].fit == "differs" and "takes no host address" in fit.parts["ports"].words
    world.grant()
    _, end = world.carry("install", spec(lan=False), target="docker_engine")
    assert end["ok"] and "-p 8080:8080/tcp" in " ".join(world.fake.argv_of("create")[0])


def test_without_the_engines_nat_network_nothing_is_planned_and_none_is_made(tmp_path):
    w = World(tmp_path, nat=False)
    w.grant()
    with pytest.raises(Refusal, match="Liminal never makes one"):
        w.jenkins.call("service_plan", "install", "jenkins/ci", spec(), "docker_engine", {})
    assert w.fake.changes() == [] and w.fake.networks == {}
    with pytest.raises(Refusal, match="never makes one"):
        w.runtime().make_network("liminal-jenkins-ci", {"subnet": "10.77.1.0/24", "gateway": "10.77.1.1"}, {})


def test_remove_keeps_the_nat_network_and_its_data(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    _, end = world.carry("remove")
    assert end["ok"] and world.fake.argv_of("network rm") == [] and "nat" in world.fake.networks
    assert "liminal-jenkins-ci-home" in world.fake.volumes and world.fake.containers == {}
    assert any("it stays" in line for line in end["lines"])


def test_segments_are_the_shared_nat_network_with_its_members(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    segs = world.jenkins.call("segments")["segments"]
    assert len(segs) == 1
    s = segs[0]
    assert (s["kind"], s["network"], s["bridge"], s["shared"], s["subnets"]) == ("hns-nat", "nat", "vEthernet (nat)", True,
                                                                                 [NAT_PREFIX])
    assert s["members"] == [{"sid": "jenkins/ci", "part": "controller", "container": "liminal-jenkins-ci-controller",
                             "mac": "02:42:00:00:00:01", "ipv4": "172.29.16.11", "assigned": "hns"}]
    assert world.jenkins.call("segments", "jenkins/ci")["segments"] == []  # the shared segment is no service's own


def test_its_readable_file_is_read_running_and_stopped(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["secrets/initialAdminPassword"] = b"unlock-me"
    assert world.jenkins.call("hosted_file", "jenkins/ci", "controller", "unlock")["text"] == "unlock-me"
    assert world.fake.argv_of("exec")[-1][-6:] == ["liminal-jenkins-ci-controller", "cmd", "/S", "/C", "type",
                                                   f"{HOME}\\secrets\\initialAdminPassword"]
    world.carry("stop")
    assert world.jenkins.call("hosted_file", "jenkins/ci", "controller", "unlock")["text"] == "unlock-me"
    assert world.fake.argv_of("cp")[-1][-2:] == [f"liminal-jenkins-ci-controller:{HOME}\\secrets\\initialAdminPassword", "-"]


def test_an_update_backs_up_through_the_images_tar_and_a_rollback_puts_it_back(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["config.xml"] = b"<hudson/>"
    newer = copy.deepcopy(spec())
    newer["parts"][0]["image"]["digest"] = "sha256:" + "b" * 64
    _, end = world.carry("update", newer)
    assert end["ok"], end
    backup = world.fake.argv_of("run")[0]
    assert backup[3:13] == ["run", "--rm", "--network", "none", "--isolation", "process", "--entrypoint", "tar", "-v",
                            "liminal-jenkins-ci-home:C:\\v:ro"]
    assert backup[-5:] == ["-C", "C:\\v", "-cf", "-", "."] and backup[13].endswith("@" + DIG)  # the image it ran from
    world.fake.volumes["liminal-jenkins-ci-home"]["files"]["config.xml"] = b"<changed/>"
    _, end = world.carry("rollback", options={"choice": "backup"})
    assert end["ok"], end
    emptied, restored = world.fake.argv_of("run")[1:]
    assert emptied[emptied.index("--entrypoint") + 1] == "powershell" and "-Command" in emptied
    assert restored[-4:] == ["-C", "C:\\v", "-xf", "-"] and "-i" in restored
    assert world.fake.volumes["liminal-jenkins-ci-home"]["files"]["config.xml"] == b"<hudson/>"


def test_engines_that_are_not_ready_run_no_command_at_all(tmp_path):
    for kind, state in (("denied", "denied"), ("linux", "other kind")):
        w = World(tmp_path, windows=FakeWindows(engine=kind))
        targets = {t.id: t for t in w.plugin.runtime_targets()}
        assert targets["docker_engine"].state == state, kind
        with pytest.raises(PluginRefusal):
            w.plugin.runtime_of(targets["docker_engine"])
        w.page("windows-containers", "grant_service", "jenkins", "docker_engine")
        with pytest.raises(Refusal, match="Nothing here starts it"):
            w.jenkins.call("service_plan", "install", "jenkins/ci", spec(), "docker_engine", {})
        assert w.fake.calls == [], kind
    w = World(tmp_path, windows=FakeWindows(nerdctl=True))
    assert {t.id: t.state for t in w.plugin.runtime_targets()}["containerd"] == "not offered"
    twice = World(tmp_path, windows=FakeWindows(engine="twice"))
    assert [t.id for t in twice.plugin.runtime_targets()] == ["docker_engine"]  # one engine at two pipes, once


def test_its_own_remove_refuses_a_services_container(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    world.windows.containers.append({"id": "3d" * 32, "name": "liminal-jenkins-ci-controller", "image": "jenkins",
                                     "state": "running", "status": "Up 1 minute", "isolation": "process", "ports": ""})
    world.plugin.forget()
    with pytest.raises(PluginRefusal, match="remove it on jenkins's page"):
        world.plugin.remove_container("liminal-jenkins-ci-controller", "docker_engine", None, True)
    assert not any(argv[1:2] == ["rm"] for _, argv in world.windows.ran)
    assert "liminal-jenkins-ci-controller" in world.fake.containers


def test_its_own_changes_are_its_pages_alone(world):
    for hook, args in (("start_container", ("iis",)), ("stop_container", ("pinger",)), ("remove_container", ("build",)),
                       ("launch_sandbox", ()), ("stop_sandbox", ("x",))):
        with pytest.raises(AskRefused):
            world.jenkins.call(hook, *args)
    assert world.windows.ran == []


def test_turning_it_off_stops_its_page_services(world):
    world.grant()
    world.carry("install", spec(), target="docker_engine")
    world.app.off.add("windows-containers")
    world.app.detach("windows-containers")
    assert world.fake.containers["liminal-jenkins-ci-controller"]["state"] == "exited"
    assert world.fake.argv_of("rm") == [] and world.fake.argv_of("volume rm") == []


def test_the_page_lists_services_and_asks_the_engine_nothing_more_until_a_service_is_there(world):
    s = world.page("windows-containers", "status")
    titles = [t["title"] for t in s["tables"]]
    assert titles[-4:] == ["Liminal's services", "Waiting for your answer", "Service plugins", "Kept data"]
    assert {"approve", "decline", "grant", "revoke", "forget"} <= {f["id"] for f in s["forms"]}
    assert world.fake.calls == []  # nothing Liminal's there yet: its page reads no service
    world.grant()
    world.page("windows-containers", "status")
    assert world.fake.calls  # once a grant is made, its services are read


def test_the_conformance_sequence_runs_on_windows_containers(world):
    world.grant()
    done = standins.conformance(world.jenkins, world.page, spec(), "docker_engine", lambda work: world.wait(work))
    assert done[-1] == "conformance"
    assert world.fake.containers == {} and world.fake.volumes == {} and set(world.fake.networks) == {"nat"}
    assert all(c["argv"][:3] == [DOCKER, "-H", PIPE] for c in world.fake.calls)


def test_what_it_says_of_its_interface_is_sound():
    from liminal_libs import internal
    import plugin_platform_windows_containers as wc

    assert internal.problems(wc.MACHINE) == []
    assert wc.MACHINE.RUNTIME == "windows-containers" and "segments" in wc.MACHINE.HOOKS


def test_a_runtime_is_reached_at_a_pipe_alone():
    with pytest.raises(Refusal, match="own pipe"):
        services.WindowsRuntime(DOCKER, "tcp://127.0.0.1:2375", lambda *a, **k: (0, "", ""))
    with pytest.raises(Refusal, match="own pipe"):
        services.WindowsRuntime("", PIPE, lambda *a, **k: (0, "", ""))


def test_the_runner_runs_docker_exe_windowless_with_the_secret_in_its_environment_alone(monkeypatch):
    seen = {}

    def run(args, **kw):
        seen.update(args=args, **kw)
        return subprocess.CompletedProcess(args, 0, b"ok", b"")
    monkeypatch.setattr(subprocess, "run", run)
    monkeypatch.setenv("LIMINAL_PLATFORM_DIR", "C:\\liminal")
    code, out, _ = services.service_run([DOCKER, "-H", PIPE, "create", "-e", "ADMIN_PASSWORD", "x"], 5,
                                        env={"ADMIN_PASSWORD": SECRET})
    assert (code, out) == (0, "ok") and seen["args"][0] == DOCKER and SECRET not in " ".join(seen["args"])
    assert seen["env"]["ADMIN_PASSWORD"] == SECRET and "LIMINAL_PLATFORM_DIR" not in seen["env"]
    assert seen["stdin"] == subprocess.DEVNULL and seen.get("shell") is None
    import os
    if os.name == "nt":
        assert seen["creationflags"] == 0x08000000  # CREATE_NO_WINDOW


def service_flow(tmp_path) -> FakeWindowsDocker:
    """Every service command the plugin runs (for its API card's test): the conformance sequence, a file, its logs, a
    rollback that puts a backup back."""
    w = World(tmp_path)
    w.grant()
    w.carry("install", spec(), target="docker_engine")
    w.fake.volumes["liminal-jenkins-ci-home"]["files"]["secrets/initialAdminPassword"] = b"x"
    w.jenkins.call("hosted_file", "jenkins/ci", "controller", "unlock")
    w.carry("stop")
    w.jenkins.call("hosted_file", "jenkins/ci", "controller", "unlock")
    w.jenkins.call("hosted_logs", "jenkins/ci")
    w.carry("start")
    newer = copy.deepcopy(spec())
    newer["parts"][0]["image"]["digest"] = "sha256:" + "b" * 64
    w.carry("update", newer)
    w.carry("rollback", options={"choice": "backup"})
    w.carry("remove")
    w.carry("delete_data", options={"backups": "delete"})
    w.jenkins.call("segments")
    return w.fake
