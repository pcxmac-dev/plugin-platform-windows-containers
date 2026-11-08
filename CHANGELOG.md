# Changelog

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
