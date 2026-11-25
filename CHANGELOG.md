# Changelog

## 0.3.0 (2026-11-25)

Windows containers host Liminal's services: liminal-libs 1.93.0's one "run a service" interface (`ContainerHost`) on each
Docker engine for Windows containers at its own pipe, through the library's `DockerRuntime` (services.py:
`WindowsRuntime`). Monday list items 34 and 35's foundation; service-containers-design §4.2 and the networking design's
§5.2. Needs liminal-libs>=1.93.0.
- **Its targets**: each Docker engine for Windows containers at its pipe (Docker Engine, Docker Desktop switched to
  Windows containers), ready while it answers; one engine at two pipes once. A denied pipe ("denied": docker-users),
  one not answering, and Docker Desktop running Linux containers ("other kind": the Docker plugin hosts those, and no
  plugin switches its kind) are not ready and are asked nothing; containerd through nerdctl is listed, "not offered"
  until its port mappings and restart choices are checked.
- **docker.exe, run directly** (`docker.exe -H npipe:////./pipe/<pipe> ...`), windowless, never inside a PowerShell
  script; no UAC path for a service's commands, so a secret given by environment (`-e NAME`, its value in docker.exe's
  environment alone) is never handed to an elevation. The runner leaves Liminal's variables and every plugin's declared
  pairs out of docker.exe's environment.
- **Windows images alone, each part's isolation from its pin's `os_build`** against this Windows' build (`runs_here`,
  Microsoft's version compatibility): process isolation where that build runs that way here, Hyper-V isolation
  otherwise (it needs Hyper-V: "cannot" while it is off); an image newer than this Windows, or with no build pinned,
  cannot; a Linux image cannot. `choose_pin` picks, of a service's Windows pins, the one this Windows runs best. The
  fit says each part's isolation and its size (Server Core images are several GB).
- **GoCD and Buildbot "not yet"** (decision 14 a: their makers publish Linux images alone): their fit on every target
  says so, for the Linux spec they hand and for any Windows spec made for them.
- **The engine's one NAT network** (N26): Windows holds one per host, so Liminal makes none and removes none. Every
  service joins the engine's own `nat` (read at each plan: "cannot" while it is not there), and the fit says "differs"
  (one service can reach another's ports there), which asks accept_differs; the firewall's plan carries no route (the
  Windows firewall's own stack). HNS hands out the addresses (no `--ip` until it is checked on the engine's own NAT
  network) and Docker's own names find a container by its name (no network aliases). Its segments are that one shared
  `hns-nat` segment, its members by their containers' labels.
- **Ports**: WinNAT's mappings on this PC's IPv4 addresses; a port meant for this PC alone "differs" (Windows' NAT takes
  no host address, so it is published on every address too, and Windows Firewall decides who reaches it).
- **Data and files**: named volumes at the image's `C:\` paths; seeds as one tar at `C:\`; a readable file by
  `cmd /S /C type` while it runs, `docker cp` when stopped; an update's backup through the image's own tar.exe (`run
  --rm --network none --isolation ...`), a rollback's put back after the image's PowerShell empties the volume.
- **Its page** gains Liminal's services, Waiting for your answer, Service plugins and Kept data (the base's), read only
  once a service plugin asked, a grant, a plan or a work is held, or an engine lists a container named as a service's.
- **Its own changes guarded**: Remove… of a service's container is refused, pointing at its owner's page; its own change
  hooks (start_container, stop_container, remove_container, launch_sandbox, stop_sandbox) are its page's alone
  (PAGE_ONLY_HOOKS, N1 a); its reads are declared (READ_HOOKS: engines, containers, images, sandboxes).
- Its API card names every command a service's plans run (create, cp, rename, run, exec, logs, inspect, volume ls,
  inspect, create and rm, network inspect nat, image inspect, pull), each with what it is used for.
- Tests: `test_services.py` (a Windows engine on the library's FakeDocker taught docker.exe's pipe and Windows' paths,
  beside the stand-in firewall and service plugins on a real apps.App: the exact argv at the pipe, the canary secret,
  the isolation from recorded builds, a Linux image refused, GoCD and Buildbot "not yet", the nat network never made or
  removed, the engines not ready, the guards, the conformance sequence); each of its 24 gates taken out once made a
  test fail.

## 0.2.1 (2026-11-15)

Drawn under the platform's Virtualization plugins section, in the list on the left (the user: "platform needs a virtualization plugins section"; "just like cloud plugins"; "docker, libvirt, kubernetes, lxc should be in virtualization"): `SECTION = "virtualization"`, liminal-libs 1.51.0's machine-plugin attribute. liminal-platform 0.26.0 draws it; an older platform keeps the plugin under Machine plugins. Nothing else changes.

## 0.2.0 (2026-11-11)

Its API on its page (plugin API 2.2, liminal-libs 1.49.0; the user: "each plugin should reflect the the API its attached
to, and present links that provide documentation, the plugin interface should more or less contain what it already has,
BUT, it should also expose more of what the API is about"). Needs liminal-libs>=1.49.0.

- `apis` (apis.py): four cards, read on their makers' pages on 2026-11-11. **Windows containers (Host Compute
  Service)**: Microsoft's Windows containers documentation (isolation modes, version compatibility, base images, the
  container platform, requirements, troubleshooting, the HCS's own reference), 13 parts (features, the platform's
  services, isolation, version compatibility, base images and the compute systems used; networking, storage, gMSA, GPU,
  resource controls, Dockerfiles, Kubernetes not), the CIM classes, services and `hcsdiag list` it reads. **Docker Engine
  on Windows (named pipes)**: Microsoft's Configure Docker in Windows, dockerd's pipes, the CLI pages, Docker Desktop and
  its license; the pipes listed, `docker context ls`, and at each pipe `info`, `ps`, `container inspect`, `images`,
  `image inspect`, `start`, `stop`, `rm`, beside run, pull, exec and logs it does not. **nerdctl (containerd)**: its
  command reference, containerd's documentation; `info`, `ps`, `images`, `start`, `stop`, `rm`. **Windows Sandbox
  (wsb)**: its overview, its command line, the .wsb configuration and its samples; `wsb --raw list`, `start`,
  `connect`, `stop`, WindowsSandbox.exe with a .wsb, beside exec, share and ip.
- `api_facts()`: what the last read holds, asking nothing: Windows, the Containers feature, vmcompute and hns, the
  compute systems listed; each Docker engine at its pipe (its version, Windows or Linux containers, its default
  isolation and counts, or why it does not answer); containerd's version; Windows Sandbox's command and the sandboxes
  running; how long ago.
- Tests: the cards are sound; they name every program and command the plugin runs (read from the scripts the stand-in
  powershell.exe is given: the read's Invoke-Native calls and each change's) and every cmdlet the read runs, and no
  other; the facts ask nothing; with LIMINAL_VENDOR_PAGES=1, every address on the cards answers (all did on 2026-11-11).

## 0.1.0 (2026-11-08)

The first release: Windows containers for the platform (the user: "also if there is a windows container format, a plugin
for that"), on the library's MachinePlugin and machines.windows.PowerShell (liminal-libs 1.30.0):

- One read of the rights, Windows' build, the features (Containers, Windows Sandbox, Hyper-V), the services (`vmcompute`,
  `hns`, Docker's, containerd's), the engines at their pipes and contexts (Windows engines listed with their containers'
  isolation and their images' builds; Linux ones and denied pipes said), containerd through nerdctl, Windows Sandbox
  (`wsb` or its program, the sandboxes running, the `.wsb` files in the platform's folder) and, with the rights, the
  Host Compute Service's compute systems (`hcsdiag list`); every program started with no window, within 20 s.
- Which images this Windows runs with process or Hyper-V isolation (Microsoft's version compatibility).
- Present when Windows containers or Windows Sandbox is on; how to turn them on when off; not for Linux or macOS.
- The page's tables (Engines, Containers, Images, Windows Sandbox, Sandboxes running, Compute systems) and forms: a
  container started, stopped or removed (a running one confirmed twice), Windows Sandbox launched with a `.wsb` (its
  settings said first) or its defaults, a sandbox closed.
- A denied change asked again through UAC with `LIMINAL_ELEVATE=prompt`.
- `python -m plugin_platform_windows_containers status | engines | containers | images | sandboxes | start | stop |
  remove | sandbox | close-sandbox`.
