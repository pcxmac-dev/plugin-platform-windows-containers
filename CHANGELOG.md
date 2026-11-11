# Changelog

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
