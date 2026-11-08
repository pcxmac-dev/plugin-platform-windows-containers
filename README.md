# plugin-platform-windows-containers

Windows containers for Liminal: the Containers and Windows Sandbox features, the engines that run Windows containers
with their containers (process or Hyper-V isolation) and images, Windows Sandbox and its `.wsb` files; a container
started, stopped or removed, a sandbox launched or closed, each change confirmed.

The user's words (2026-11-08): "also if there is a windows container format, a plugin for that, ... and a plugin for
windows virtualization too"; earlier: "basically the platform is the interface for the software/hardware which
facilitates the liminal framework".

## Windows' container formats

Windows has two of its own, and this plugin covers both:

- **Windows Server containers**: OCI images made from Windows Server Core or Nano Server (`mcr.microsoft.com/windows/...`),
  run by an engine (Docker Engine as the `docker` service, Docker Desktop switched to Windows containers, Mirantis
  Container Runtime, or containerd with nerdctl) through Windows' Host Compute Service (`vmcompute`) and Host Network
  Service (`hns`), on the Containers feature. Each runs with **process isolation** (sharing this Windows' kernel: the
  image's build must be this host's, but Windows Server 2022 images run so on Windows 11 and Windows Server 2025, and
  Windows Server 2025 images on Windows 11 24H2 and later) or **Hyper-V isolation** (a utility VM of its own, running
  older images too; Windows 10 and 11 default to it, so it needs Hyper-V).
- **Windows Sandbox**: a clean, throwaway Windows in a window, Hyper-V isolated (the Containers-DisposableClientVM
  feature), configured by a `.wsb` file (XML: networking, the GPU, the microphone, the camera, the printers, the
  clipboard, folders of this PC mapped in read-only or writable, a command at logon, its memory). Windows 11 24H2 added
  its command, `wsb` (start, list, connect, stop).

Linux containers (Docker Desktop's default, Docker in WSL) are not Windows containers: the Docker and WSL plugins have
them, and this plugin offers no Docker instance of its own (the framework's services are Linux images).

## What it reads

One PowerShell read (the library's `machines.windows.PowerShell`, windowless) gives everything the page shows; every
program it asks is started with no window (`CreateNoWindow`), its output and errors apart, within 20 seconds:

- The rights (elevated; Hyper-V Administrators), Windows' build, whether the hypervisor runs.
- The features (`Win32_OptionalFeature`, readable by anyone): Containers, Windows Sandbox, Hyper-V, the Virtual Machine
  Platform; the services: `vmcompute`, `hns`, `docker`, `com.docker.service`, `containerd`.
- The engines: the docker command asked at each Docker engine pipe there is (`docker_engine`, `docker_engine_windows`,
  `dockerDesktopWindowsEngine`) and at each docker context's pipe (`docker info`): one saying `OSType: windows` is
  listed with its containers (`docker ps -a`, each one's isolation from `docker container inspect`) and its images
  (`docker images`, each one's Windows build from `docker image inspect`); one engine reached at two pipes once; Docker
  Desktop running Linux containers said so (switch it to Windows containers); a pipe denied said so (join
  docker-users). containerd through `nerdctl` (its default namespace).
- Which images this Windows runs, and with which isolation (Microsoft's version compatibility).
- Windows Sandbox: `wsb --raw list` (the sandboxes running), or its program (`WindowsSandbox.exe`); the `.wsb` files
  in the platform's folder's `windows-containers/sandboxes` (`LIMINAL_PLATFORM_DIR`, else the data folder's
  `platform/`), each read and said in words (a file declaring a DOCTYPE or an ENTITY, or over 64 KB, is not read; a
  mapped folder missing on this PC is said, since Windows Sandbox would not start).
- The compute systems the Host Compute Service runs (`hcsdiag list`: Windows containers, Windows Sandbox, WSL 2's VM),
  only when the platform is elevated or in Hyper-V Administrators.

What is read is kept 10 s; a change reads again. Nothing runs between asks.

Present when Windows containers or Windows Sandbox is turned on; otherwise not present, saying how to turn them on
(`Enable-WindowsOptionalFeature -Online -FeatureName Containers, Containers-DisposableClientVM -All`, as administrator,
then a restart), or that the edition has neither (Windows Home). On Linux or macOS it is not for this machine at all.

## The changes, each confirmed on the page

| Button | Hook | What runs |
| --- | --- | --- |
| Start | `start_container(name, engine, container_id)` | `docker -H <pipe> start <id>` (or `nerdctl start`) |
| Stop | `stop_container(name, engine, container_id)` | `docker stop`: asked to shut down, ended after 10 s |
| Remove… | `remove_container(name, engine, container_id, accept_force)` | `docker rm` (its image and named volumes kept); a running one confirmed again, then `rm -f` |
| Launch… (a `.wsb`'s row) | `launch_sandbox(path, accept_settings, seen)` | its settings are the confirmation; `wsb --raw start --config <its XML>`, then `wsb connect` for its window (or `WindowsSandbox.exe <file>`) |
| Launch Windows Sandbox… | `launch_sandbox(path, accept_settings)` | any `.wsb` by its path (its settings said and confirmed again), or Windows Sandbox's own defaults |
| Close… | `stop_sandbox(sandbox_id)` | `wsb stop --id <id>` |

A container is always named to its engine by its Id, and the name the page showed must still be its name; the engine is
one the read found, never one typed. A second confirmation is a refusal naming the argument that accepts it
(`Refusal.accept`), which the platform's page (0.6.0) asks as its own step. A change runs as the platform does; denied
(the engine's pipe is for administrators and its group), it is asked again through Windows' prompt (UAC) when
`LIMINAL_ELEVATE=prompt`, else it fails saying how to give it the rights.

The read hooks `engines`, `containers`, `images` and `sandboxes` give the same as lists, for the platform's other clients.

## From the command line

```
python -m plugin_platform_windows_containers status
python -m plugin_platform_windows_containers engines | containers | images | sandboxes
python -m plugin_platform_windows_containers start iis [--engine docker_engine]
python -m plugin_platform_windows_containers stop iis
python -m plugin_platform_windows_containers remove iis [--force]
python -m plugin_platform_windows_containers sandbox C:\Users\you\Desktop\tools.wsb [--accept]
python -m plugin_platform_windows_containers sandbox                  # Windows Sandbox's own defaults
python -m plugin_platform_windows_containers close-sandbox <id>
```

## Tests

```
python -m pytest -q
```

Over a stand-in for `powershell.exe` only (recorded JSON: this PC's own read, and the same read's shape with the
commands' outputs as docker, nerdctl, wsb and hcsdiag print them); no test starts a process or reaches the network.
