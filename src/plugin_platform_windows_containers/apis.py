"""What the Windows containers plugin attaches to (plugin API 2.2; the user, 2026-11-11: "each plugin should reflect the
the API its attached to, and present links that provide documentation ... it should also expose more of what the API is
about"): Windows' container platform (its features, its services, the Host Compute Service and hcsdiag), the Docker
engine on Windows over its named pipes, containerd through nerdctl, and Windows Sandbox (wsb, WindowsSandbox.exe, .wsb
files). Each part is named with what the plugin does with it, each command with what for, and the notable others; every
address was read on its maker's pages on 2026-11-11."""
from __future__ import annotations

from liminal_libs.sources.apis import Api, Area, Call, Link

VERIFIED = "2026-11-11"
PLATFORM = "Windows containers (Host Compute Service)"
DOCKER = "Docker Engine on Windows (named pipes)"
NERDCTL = "nerdctl (containerd)"
SANDBOX = "Windows Sandbox (wsb)"

_WC = "https://learn.microsoft.com/en-us/virtualization/windowscontainers/"
_LEARN = "https://learn.microsoft.com/en-us"
_WSB = "https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/"
_CLI = "https://docs.docker.com/reference/cli/docker/"
_NERDCTL_REF = "https://github.com/containerd/nerdctl/blob/main/docs/command-reference.md"
_PS51 = "?view=powershell-5.1"
_HCSDIAG = f"{_LEARN}/training/modules/troubleshoot-windows-containers/3-troubleshooting-containers-windows-host"

WINDOWS_CONTAINERS = Api(
    name=PLATFORM, maker="Microsoft", kind="system",
    about=("Windows' own containers: Windows Server containers run by an engine through the Host Compute Service (HCS), "
           "each with process isolation (sharing this Windows' kernel) or Hyper-V isolation (a utility VM of its own), from "
           "images whose Windows build must suit this one's. The plugin reads the features and services under them, says "
           "which images this Windows runs and with which isolation, and, given the rights, what the HCS runs (hcsdiag)."),
    base="Windows' features and services (Get-CimInstance, Get-Service); hcsdiag.exe in System32",
    version="Windows 10 and 11 (Hyper-V isolation by default), Windows Server 2016 to 2025",
    auth="the features and services are read by anyone; hcsdiag answers administrators and Hyper-V Administrators",
    limits="none (this PC's own services)",
    costs="",
    links=(
        Link("Containers on Windows documentation", _WC, "docs"),
        Link("About Windows containers", _WC + "about/", "guide"),
        Link("Isolation modes", _WC + "manage-containers/hyperv-container", "guide"),
        Link("Version compatibility", _WC + "deploy-containers/version-compatibility", "guide"),
        Link("Base images", _WC + "manage-containers/container-base-images", "guide"),
        Link("Windows container platform (HCS, containerd, Docker)", _WC + "deploy-containers/containerd", "guide"),
        Link("Windows container requirements", _WC + "deploy-containers/system-requirements", "guide"),
        Link("Troubleshoot Windows containers", _WC + "troubleshooting", "guide"),
        Link("Windows Containers FAQ", _WC + "about/faq", "guide"),
        Link("Host Compute System overview", f"{_LEARN}/virtualization/api/hcs/overview", "reference"),
        Link("HCS error codes", f"{_LEARN}/virtualization/api/hcs/reference/hcshresult", "reference"),
        Link("hcsdiag (Troubleshooting Windows Containers)", _HCSDIAG, "tool"),
        Link("microsoft/hcsshim", "https://github.com/microsoft/hcsshim", "source"),
    ),
    areas=(
        Area("Windows features", "Containers, Windows Sandbox, Hyper-V, the Virtual Machine Platform",
             f"{_LEARN}/windows/win32/cimwin32prov/win32-optionalfeature",
             covered="each on, off, or not in this edition of Windows"),
        Area("The container platform", "the Host Compute Service (vmcompute), the Host Network Service (hns), containerd, "
                                       "Docker", _WC + "deploy-containers/containerd",
             covered="their services read: state and how each starts"),
        Area("Isolation modes", "process isolation or Hyper-V isolation, per container", _WC + "manage-containers/hyperv-container",
             covered="each container's isolation and each engine's default"),
        Area("Version compatibility", "which image builds this Windows runs, with which isolation",
             _WC + "deploy-containers/version-compatibility", covered="whether this Windows runs each image, and how"),
        Area("Base images", "Nano Server, Server Core, Windows, Windows Server", _WC + "manage-containers/container-base-images",
             covered="each image's Windows build named (Windows Server 2016 to 2025)"),
        Area("Compute systems (hcsdiag)", "what the HCS runs: containers, utility VMs, Windows Sandbox, WSL 2's VM", _HCSDIAG,
             covered="listed when the platform has the rights (hcsdiag list)"),
        Area("Networking", "container networks and their drivers (nat, transparent, l2bridge, overlay)",
             _WC + "container-networking/architecture"),
        Area("Persistent storage", "bind mounts and named volumes", _WC + "manage-containers/persistent-storage"),
        Area("Group Managed Service Accounts", "a container's Active Directory identity", _WC + "manage-containers/manage-serviceaccounts"),
        Area("GPU acceleration", "a host GPU given to process-isolated containers", _WC + "deploy-containers/gpu-acceleration"),
        Area("Resource controls", "a container's processor, memory and storage limits", _WC + "manage-containers/resource-controls"),
        Area("Dockerfiles", "Windows images built", _WC + "manage-docker/manage-windows-dockerfile"),
        Area("Kubernetes on Windows", "Windows nodes in a Kubernetes cluster", _WC + "kubernetes/getting-started-kubernetes-windows"),
    ),
    calls=(
        Call("Get-CimInstance -ClassName Win32_OptionalFeature", "the container and virtualization features", "Windows features",
             used="present only when Windows containers or Windows Sandbox is on",
             docs=f"{_LEARN}/windows/win32/cimwin32prov/win32-optionalfeature"),
        Call("Get-CimInstance -ClassName Win32_ComputerSystem", "whether the hypervisor runs", "Windows features",
             used="the hypervisor fact", docs=f"{_LEARN}/windows/win32/cimwin32prov/win32-computersystem"),
        Call("Get-CimInstance -ClassName Win32_OperatingSystem", "this Windows' edition and build", "Version compatibility",
             used="which images run here, and with which isolation", docs=f"{_LEARN}/windows/win32/cimwin32prov/win32-operatingsystem"),
        Call("Get-ItemProperty", "the registry's CurrentVersion: release, revision and whether a client or a server",
             "Version compatibility", used="the windows fact; Windows 11's own compatibility rules",
             docs=f"{_LEARN}/powershell/module/microsoft.powershell.management/get-itemproperty{_PS51}"),
        Call("Get-Service", "vmcompute, hns, docker, com.docker.service, containerd, CmService", "The container platform",
             used="the services' facts", docs=f"{_LEARN}/powershell/module/microsoft.powershell.management/get-service{_PS51}"),
        Call("hcsdiag list", "the compute systems the HCS runs", "Compute systems (hcsdiag)",
             used="the Compute systems table (with the rights)", docs=_HCSDIAG),
        Call("hcsdiag console -uvm ID", "a console inside a container's utility VM", "Compute systems (hcsdiag)", docs=_HCSDIAG,
             writes=True),
        Call("Enable-WindowsOptionalFeature -Online -FeatureName Containers", "the Containers feature turned on (then a "
             "restart)", "Windows features", docs=f"{_LEARN}/powershell/module/dism/enable-windowsoptionalfeature", writes=True),
    ),
    verified=VERIFIED)

DOCKER_ON_WINDOWS = Api(
    name=DOCKER, maker="Docker, Inc.", kind="command",
    about=("The docker command asked at each Docker engine's named pipe (docker -H npipe:////./pipe/docker_engine …): Docker "
           "Engine on Windows (Microsoft's install script installs Docker CE as the docker service), or Docker Desktop "
           "switched to Windows containers. Each engine saying OSType windows is read: its containers with their isolation, "
           "its images with the Windows build each was made from; a container started, stopped or removed once confirmed."),
    base="docker -H npipe:////./pipe/<docker_engine | docker_engine_windows | dockerDesktopWindowsEngine>",
    version="any Docker engine answering on Windows' named pipes (its info's OSType windows); the CLI's JSON listings",
    auth=("the pipe's access: administrators and the group daemon.json names (docker-users for Docker Desktop); a change "
          "denied is asked again through Windows' prompt (UAC) when LIMINAL_ELEVATE=prompt"),
    limits="none on the engine (it is local)",
    costs=("Docker Engine is free; Docker Desktop is free for personal use, education, non-commercial open source and small "
           "businesses (fewer than 250 employees and less than $10 million a year), a paid subscription otherwise"),
    links=(
        Link("Configure Docker in Windows", _WC + "manage-docker/configure-docker-daemon", "docs"),
        Link("Prepare Windows (Docker Engine's install)", _WC + "quick-start/set-up-environment", "guide"),
        Link("dockerd (its -H npipe and daemon.json)", "https://docs.docker.com/reference/cli/dockerd/", "reference"),
        Link("docker CLI reference", _CLI, "reference"),
        Link("Engine API reference (v1.56)", "https://docs.docker.com/reference/api/engine/version/v1.56/", "spec"),
        Link("Docker Desktop", "https://docs.docker.com/desktop/", "tool"),
        Link("Docker Desktop license agreement", "https://docs.docker.com/subscription-billing/desktop-license/", "pricing"),
        Link("Docker Engine release notes", "https://docs.docker.com/engine/release-notes/", "changelog"),
        Link("moby/moby (the engine)", "https://github.com/moby/moby", "source"),
    ),
    areas=(
        Area("Pipes and contexts", "the engines' named pipes, and the docker contexts naming them", _CLI + "context/",
             covered="every Docker engine pipe there is, and each context's, asked once (one engine at two pipes listed once)"),
        Area("System info", "an engine's version, OS type, default isolation and counts", _CLI + "system/info/",
             covered="each engine: Windows or Linux containers, its version, its default isolation"),
        Area("Containers", "containers made, run, started, stopped, inspected, removed", _CLI + "container/",
             covered="listed with their isolation and platform (inspect); started, stopped, removed once confirmed"),
        Area("Images", "images pulled, built, inspected, removed", _CLI + "image/",
             covered="listed with the Windows build each was made from (inspect)"),
        Area("Exec", "a command run in a container", _CLI + "container/exec/"),
        Area("Building", "images built from a Dockerfile", _CLI + "buildx/"),
        Area("Networks", "the engine's networks (nat on Windows)", _CLI + "network/"),
        Area("Volumes", "named volumes", _CLI + "volume/"),
    ),
    calls=(
        Call("GetFiles('\\\\.\\pipe\\')", "the named pipes there are (.NET's Directory.GetFiles), docker's and containerd's",
             "Pipes and contexts", used="which Docker engine pipes exist", docs="https://docs.docker.com/reference/cli/dockerd/"),
        Call("docker context ls", "the CLI's contexts and their endpoints", "Pipes and contexts",
             used="a context's pipe asked too", docs=_CLI + "context/ls/"),
        Call("docker -H PIPE info", "the engine: version, OSType, isolation, counts (GET /info)", "System info",
             used="the Engines table", docs=_CLI + "system/info/"),
        Call("docker -H PIPE ps -a --no-trunc", "every container (GET /containers/json)", "Containers",
             used="the Containers table", docs=_CLI + "container/ls/"),
        Call("docker -H PIPE container inspect ID...", "each container's isolation, platform and start", "Containers",
             used="the Isolation column", docs=_CLI + "container/inspect/"),
        Call("docker -H PIPE images --no-trunc", "the images (GET /images/json)", "Images", used="the Images table",
             docs=_CLI + "image/ls/"),
        Call("docker -H PIPE image inspect ID...", "each image's OS, OS version and architecture", "Images",
             used="each image's Windows build, and whether it runs here", docs=_CLI + "image/inspect/"),
        Call("docker -H PIPE start ID", "a container started", "Containers", used="Start… a container",
             docs=_CLI + "container/start/", writes=True),
        Call("docker -H PIPE stop ID", "a container stopped (ended after 10 s)", "Containers", used="Stop… a container",
             docs=_CLI + "container/stop/", writes=True),
        Call("docker -H PIPE rm ID", "a container removed (-f: a running one ended first)", "Containers",
             used="Remove… a container (a running one only once accepted again)", docs=_CLI + "container/rm/", writes=True),
        Call("docker -H PIPE run --isolation process IMAGE", "a container made and started with process isolation",
             "Containers", docs=_CLI + "container/run/", writes=True),
        Call("docker -H PIPE pull IMAGE", "an image pulled", "Images", docs=_CLI + "image/pull/", writes=True),
        Call("docker -H PIPE exec ID COMMAND", "a command run in a container", "Exec", docs=_CLI + "container/exec/",
             writes=True),
        Call("docker -H PIPE logs ID", "a container's output", "Containers", docs=_CLI + "container/logs/"),
    ),
    verified=VERIFIED)

NERDCTL_CONTAINERD = Api(
    name=NERDCTL, maker="containerd (CNCF)", kind="command",
    about=("containerd's Docker-compatible command line. Windows containers run by containerd (through runhcs and the HCS) "
           "are read with it in containerd's default namespace: containerd's own info, its containers and its images; a "
           "container started, stopped or removed once confirmed."),
    base="nerdctl.exe (Program Files\\nerdctl, or containerd's bin)",
    version="nerdctl 2 (its command reference's main branch)",
    auth="containerd's pipe: administrators",
    limits="none (local)",
    costs="",
    links=(
        Link("nerdctl", "https://github.com/containerd/nerdctl", "docs"),
        Link("nerdctl command reference", _NERDCTL_REF, "reference"),
        Link("containerd documentation", "https://containerd.io/docs/", "guide"),
        Link("Windows container platform (containerd on Windows)", _WC + "deploy-containers/containerd", "guide"),
        Link("nerdctl releases", "https://github.com/containerd/nerdctl/releases", "changelog"),
        Link("containerd/containerd", "https://github.com/containerd/containerd", "source"),
    ),
    areas=(
        Area("System info", "containerd's version and OS", _NERDCTL_REF, covered="containerd's version, and that it runs "
                                                                               "Windows containers"),
        Area("Containers", "containers run, started, stopped, removed", _NERDCTL_REF,
             covered="listed; started, stopped, removed once confirmed"),
        Area("Images", "images pulled, built, removed", _NERDCTL_REF, covered="listed with their platform"),
        Area("Namespaces", "containerd's namespaces", _NERDCTL_REF),
        Area("Compose", "several containers from a compose file", _NERDCTL_REF),
        Area("Networks and volumes", "CNI networks and volumes", _NERDCTL_REF),
        Area("Registry sign-in", "a registry's account", _NERDCTL_REF),
    ),
    calls=(
        Call("nerdctl info", "containerd's version and OS type", "System info", used="the Engines table's containerd row",
             docs=_NERDCTL_REF),
        Call("nerdctl ps -a --no-trunc", "every container of the default namespace", "Containers",
             used="the Containers table", docs=_NERDCTL_REF),
        Call("nerdctl images --no-trunc", "the images", "Images", used="the Images table", docs=_NERDCTL_REF),
        Call("nerdctl start ID", "a container started", "Containers", used="Start…", docs=_NERDCTL_REF, writes=True),
        Call("nerdctl stop ID", "a container stopped", "Containers", used="Stop…", docs=_NERDCTL_REF, writes=True),
        Call("nerdctl rm ID", "a container removed (-f: a running one first ended)", "Containers", used="Remove…",
             docs=_NERDCTL_REF, writes=True),
        Call("nerdctl run IMAGE", "a container made and started", "Containers", docs=_NERDCTL_REF, writes=True),
        Call("nerdctl pull IMAGE", "an image pulled", "Images", docs=_NERDCTL_REF, writes=True),
        Call("nerdctl namespace ls", "containerd's namespaces", "Namespaces", docs=_NERDCTL_REF),
        Call("nerdctl compose up", "a compose file's containers run", "Compose", docs=_NERDCTL_REF, writes=True),
    ),
    verified=VERIFIED)

WINDOWS_SANDBOX = Api(
    name=SANDBOX, maker="Microsoft", kind="command",
    about=("Windows Sandbox: a throwaway Windows in a window, Hyper-V isolated, configured by a .wsb file (the network, "
           "mapped folders, a logon command, memory, the GPU, the microphone, the camera, printers, the clipboard). Windows "
           "11 24H2's wsb command starts, lists, connects to and stops sandboxes; without it, WindowsSandbox.exe opens one "
           "with a .wsb. The plugin lists its folder's .wsb files with what each gives a sandbox, launches one once its "
           "settings are said and accepted, and closes one."),
    base="wsb.exe (Windows 11 24H2 and later; --raw: JSON), else C:\\Windows\\System32\\WindowsSandbox.exe",
    version="Windows 11 24H2's wsb; the .wsb configuration as Microsoft documents it",
    auth="the signed-in user's (Windows 10 and 11 Pro, Enterprise and Education; not Home)",
    limits="none (local)",
    costs="",
    links=(
        Link("Windows Sandbox", _WSB, "docs"),
        Link("Windows Sandbox command line", _WSB + "windows-sandbox-cli", "reference"),
        Link("Use and configure Windows Sandbox (.wsb)", _WSB + "windows-sandbox-configure-using-wsb-file", "reference"),
        Link("Sample configuration files", _WSB + "windows-sandbox-sample-configuration", "guide"),
    ),
    areas=(
        Area("Start", "a sandbox started, with a configuration or Windows Sandbox's defaults", _WSB + "windows-sandbox-cli",
             covered="a sandbox launched with a .wsb (its settings said and accepted first) or the defaults"),
        Area("List", "the sandboxes running, their Id, status and uptime", _WSB + "windows-sandbox-cli",
             covered="the Sandboxes running table"),
        Area("Connect", "a running sandbox's window (a remote desktop session)", _WSB + "windows-sandbox-cli",
             covered="its window opened once it starts"),
        Area("Stop", "a sandbox closed and its resources released", _WSB + "windows-sandbox-cli",
             covered="a sandbox closed by its Id"),
        Area("Configuration (.wsb)", "networking, mapped folders, logon command, memory, vGPU, audio and video input, "
                                     "printers, clipboard, protected client", _WSB + "windows-sandbox-configure-using-wsb-file",
             covered="each file's settings said in words, a file declaring a DOCTYPE or an ENTITY refused unread"),
        Area("The classic program", "WindowsSandbox.exe, opened with a .wsb", _WSB,
             covered="launched with a .wsb where wsb is not there"),
        Area("Exec", "a command run in a sandbox, as the user or System", _WSB + "windows-sandbox-cli"),
        Area("Share", "a host folder shared with a running sandbox", _WSB + "windows-sandbox-cli"),
        Area("IP", "a sandbox's IP address", _WSB + "windows-sandbox-cli"),
    ),
    calls=(
        Call("wsb --raw list", "the sandboxes running, as JSON", "List", used="the Sandboxes running table",
             docs=_WSB + "windows-sandbox-cli"),
        Call("wsb --raw start --config XML", "a sandbox started (its Id given back), with a configuration's XML",
             "Start", used="Launch Windows Sandbox…", docs=_WSB + "windows-sandbox-cli", writes=True),
        Call("wsb connect --id ID", "its window opened", "Connect", used="the window of a sandbox just started",
             docs=_WSB + "windows-sandbox-cli"),
        Call("wsb stop --id ID", "a sandbox closed: everything in it gone", "Stop", used="Close…", docs=_WSB + "windows-sandbox-cli",
             writes=True),
        Call("WindowsSandbox.exe FILE.wsb", "Windows Sandbox's own program, opened with a .wsb", "The classic program",
             used="Launch… where wsb is not there", docs=_WSB, writes=True),
        Call("Get-Process -Name WindowsSandbox*", "Windows Sandbox's processes", "List", used="whether a sandbox runs",
             docs=f"{_LEARN}/powershell/module/microsoft.powershell.management/get-process{_PS51}"),
        Call("wsb exec --id ID -c COMMAND -r System", "a command run in a sandbox", "Exec", docs=_WSB + "windows-sandbox-cli",
             writes=True),
        Call("wsb share --id ID -f HOST -s SANDBOX", "a host folder shared with it (--allow-write: writable)", "Share",
             docs=_WSB + "windows-sandbox-cli", writes=True),
        Call("wsb ip --id ID", "its IP address", "IP", docs=_WSB + "windows-sandbox-cli"),
    ),
    verified=VERIFIED)

APIS = (WINDOWS_CONTAINERS, DOCKER_ON_WINDOWS, NERDCTL_CONTAINERD, WINDOWS_SANDBOX)
