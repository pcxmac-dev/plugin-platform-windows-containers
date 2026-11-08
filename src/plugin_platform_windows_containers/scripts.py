"""The PowerShell the Windows containers plugin runs, through the library's machines.windows.PowerShell (windowless, given
as -EncodedCommand, a failure coming back as one line of its own words): one read of everything the platform's page shows,
and each change. Every program it starts (docker, nerdctl, wsb, hcsdiag) is started by Invoke-Native: no window
(CreateNoWindow), its output and errors kept apart, its exit code, and a time limit (an engine that does not answer
cannot hold the read). The read gives each command's raw output ({Code, Out, Err}); the plugin parses it.

What is asked, and of whom:
- the rights (elevated, a member of Hyper-V Administrators: S-1-5-32-578), Windows' build, whether the hypervisor runs;
- the Windows features (Win32_OptionalFeature, readable by anyone): Containers, Windows Sandbox
  (Containers-DisposableClientVM), Hyper-V, the Virtual Machine Platform;
- the services under Windows containers: the Host Compute Service (vmcompute), the Host Network Service (hns), Docker
  Engine (docker), Docker Desktop's (com.docker.service), containerd;
- the Windows engines: the docker command asked at each Docker engine pipe there is (docker_engine,
  docker_engine_windows, dockerDesktopWindowsEngine) and at each docker context's pipe; an engine saying OSType windows
  is listed with its containers (and their isolation) and images (and their Windows build); nerdctl asked of containerd;
- Windows Sandbox: its command (wsb, Windows 11 24H2's) and the sandboxes it runs, or its program (WindowsSandbox.exe);
- the compute systems the Host Compute Service runs (hcsdiag list), only when the platform has the rights to ask.

Windows PowerShell 5.1's ConvertTo-Json gives an enum as a number: every value is a string, a number or a bool here, and
nothing is nested deeper than the library's json() reads (-Depth 5)."""
from __future__ import annotations

from liminal_libs.machines.windows import quote

READ_MARK = "# liminal-windows-containers: read"
RESULT = "LIMINAL-RESULT: "  # a change's line: the command's {Code, Out, Err}, as JSON
GROUP_SID = "S-1-5-32-578"  # Hyper-V Administrators, in every language
ENGINE_PIPES = ("docker_engine", "docker_engine_windows", "dockerDesktopWindowsEngine")  # the Docker engines' own pipes
NATIVE_S = 20  # a command's time limit in a read, in seconds
FEATURES = ("Containers", "Containers-DisposableClientVM", "Microsoft-Hyper-V", "Microsoft-Hyper-V-Management-PowerShell",
            "VirtualMachinePlatform", "HypervisorPlatform")
SERVICES = ("vmcompute", "hns", "docker", "com.docker.service", "containerd", "CmService")

# a program run with no window, its output and errors apart, within a time limit; its arguments quoted as Windows'
# command line parses them (CommandLineToArgvW: a quote escaped, the backslashes before it doubled)
NATIVE = r"""
function Invoke-Native([string]$exe, [string[]]$arguments, [int]$seconds) {
    $quoted = foreach ($a in $arguments) {
        if ($a -ne '' -and $a -notmatch '[\s"]') { $a } else { '"' + (($a -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"' }
    }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $exe
    $psi.Arguments = (@($quoted) -join ' ')
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
    $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
    try { $p = [System.Diagnostics.Process]::Start($psi) } catch { return [pscustomobject]@{ Code = -1; Out = ''; Err = $_.Exception.Message } }
    $o = $p.StandardOutput.ReadToEndAsync()
    $e = $p.StandardError.ReadToEndAsync()
    if (-not $p.WaitForExit($seconds * 1000)) {
        try { $p.Kill() } catch { }
        return [pscustomobject]@{ Code = -1; Out = ''; Err = "no answer in $seconds s" }
    }
    $p.WaitForExit()
    [pscustomobject]@{ Code = [int]$p.ExitCode; Out = [string]$o.Result; Err = [string]$e.Result }
}
function Find-Program([string]$name, [string[]]$places) {
    $c = Get-Command -Name $name -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($c) { return [string]$c.Source }
    foreach ($p in $places) { $x = [Environment]::ExpandEnvironmentVariables($p); if (Test-Path -LiteralPath $x) { return $x } }
    return $null
}
"""

READ = READ_MARK + NATIVE + r"""
$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
$cv = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction SilentlyContinue
$out = [ordered]@{
    Elevated = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    Group = $principal.IsInRole([Security.Principal.SecurityIdentifier]'""" + GROUP_SID + r"""')
    Windows = $null
    Hypervisor = $null
    Features = @()
    FeaturesRead = $false
    Services = @()
    Docker = $null
    Nerdctl = $null
    Hcsdiag = $null
    Pipes = @()
    Contexts = $null
    Engines = @()
    Containerd = $null
    Sandbox = $null
    Hcs = $null
}
try {
    $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
    $out.Windows = [pscustomobject]@{ Caption = [string]$os.Caption; Build = [string]$os.BuildNumber
        Release = [string]$cv.DisplayVersion; Revision = [string]$cv.UBR; Kind = [string]$cv.InstallationType }
} catch { }
try { $out.Hypervisor = [bool](Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).HypervisorPresent } catch { }
try {
    $filter = (@('""" + "', '".join(FEATURES) + r"""') | ForEach-Object { "Name='$_'" }) -join ' OR '
    $out.Features = @(Get-CimInstance -ClassName Win32_OptionalFeature -Filter $filter -ErrorAction Stop |
        ForEach-Object { [pscustomobject]@{ Name = [string]$_.Name; State = [int]$_.InstallState; Title = [string]$_.Caption } })
    $out.FeaturesRead = $true
} catch { }
$out.Services = @(Get-Service -Name @('""" + "', '".join(SERVICES) + r"""') -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{ Name = [string]$_.Name; Status = $_.Status.ToString(); StartType = $_.StartType.ToString(); Title = [string]$_.DisplayName } })
$out.Docker = Find-Program 'docker.exe' @('%ProgramFiles%\Docker\Docker\resources\bin\docker.exe', '%ProgramFiles%\docker\docker.exe')
$out.Nerdctl = Find-Program 'nerdctl.exe' @('%ProgramFiles%\nerdctl\nerdctl.exe', '%ProgramFiles%\containerd\bin\nerdctl.exe')
$out.Hcsdiag = Find-Program 'hcsdiag.exe' @('%SystemRoot%\System32\hcsdiag.exe')
try { $out.Pipes = @([System.IO.Directory]::GetFiles('\\.\pipe\') | ForEach-Object { [System.IO.Path]::GetFileName($_) } | Where-Object { $_ -match '^(docker|containerd)' }) } catch { }
if ($out.Docker) {
    $endpoints = [ordered]@{}
    foreach ($name in @('""" + "', '".join(ENGINE_PIPES) + r"""')) { if ($out.Pipes -contains $name) { $endpoints["npipe:////./pipe/$name"] = "the pipe $name" } }
    $out.Contexts = Invoke-Native $out.Docker @('context', 'ls', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
    if ($out.Contexts.Code -eq 0) {
        foreach ($line in ($out.Contexts.Out -split "`r?`n")) {
            if ($line -notmatch '^\s*\{') { continue }
            try { $row = $line | ConvertFrom-Json } catch { continue }
            $ep = [string]$row.DockerEndpoint
            if ($ep -match '^npipe:////\./pipe/(.+)$' -and ($out.Pipes -contains $Matches[1]) -and -not $endpoints.Contains($ep)) {
                $endpoints[$ep] = 'the context ' + [string]$row.Name
            }
        }
    }
    $seen = @{}
    foreach ($ep in @($endpoints.Keys)) {
        $engine = [ordered]@{ Endpoint = $ep; From = $endpoints[$ep]; Same = $null; Info = $null; Ps = $null; Inspect = $null; Images = $null; ImageInspect = $null }
        $engine.Info = Invoke-Native $out.Docker @('-H', $ep, 'info', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
        $id = ''
        if ($engine.Info.Out -match '"ID"\s*:\s*"([^"]+)"') { $id = $Matches[1] }
        $windows = $engine.Info.Out -match '"OSType"\s*:\s*"windows"'
        if ($windows -and $id -and $seen.ContainsKey($id)) { $engine.Same = $seen[$id] } elseif ($windows) {
            if ($id) { $seen[$id] = $ep }
            $engine.Ps = Invoke-Native $out.Docker @('-H', $ep, 'ps', '-a', '--no-trunc', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
            $ids = @([regex]::Matches([string]$engine.Ps.Out, '"ID"\s*:\s*"([0-9a-f]{12,64})"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
            if ($ids.Count) {
                $engine.Inspect = Invoke-Native $out.Docker (@('-H', $ep, 'container', 'inspect', '--format', '{{.Id}}|{{.HostConfig.Isolation}}|{{.Platform}}|{{.State.StartedAt}}') + $ids) """ + str(NATIVE_S) + r"""
            }
            $engine.Images = Invoke-Native $out.Docker @('-H', $ep, 'images', '--no-trunc', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
            $images = @([regex]::Matches([string]$engine.Images.Out, '"ID"\s*:\s*"(sha256:[0-9a-f]{64})"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique)
            if ($images.Count) {
                $engine.ImageInspect = Invoke-Native $out.Docker (@('-H', $ep, 'image', 'inspect', '--format', '{{.Id}}|{{.Os}}|{{.OsVersion}}|{{.Architecture}}') + $images) """ + str(NATIVE_S) + r"""
            }
        }
        $out.Engines += [pscustomobject]$engine
    }
}
if ($out.Nerdctl) {
    $c = [ordered]@{ Info = $null; Ps = $null; Images = $null }
    $c.Info = Invoke-Native $out.Nerdctl @('info', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
    if ($c.Info.Code -eq 0) {
        $c.Ps = Invoke-Native $out.Nerdctl @('ps', '-a', '--no-trunc', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
        $c.Images = Invoke-Native $out.Nerdctl @('images', '--no-trunc', '--format', '{{json .}}') """ + str(NATIVE_S) + r"""
    }
    $out.Containerd = [pscustomobject]$c
}
$wsb = Find-Program 'wsb.exe' @('%LOCALAPPDATA%\Microsoft\WindowsApps\wsb.exe')
$sandbox = [ordered]@{ Cli = $wsb; Classic = $null; Running = @(); List = $null }
$classic = Join-Path $env:SystemRoot 'System32\WindowsSandbox.exe'
if (Test-Path -LiteralPath $classic) { $sandbox.Classic = $classic }
$sandbox.Running = @(Get-Process -Name WindowsSandbox, WindowsSandboxClient, WindowsSandboxServer, WindowsSandboxRemoteSession -ErrorAction SilentlyContinue |
    ForEach-Object { [string]$_.ProcessName } | Select-Object -Unique)
if ($wsb) { $sandbox.List = Invoke-Native $wsb @('--raw', 'list') """ + str(NATIVE_S) + r""" }
$out.Sandbox = [pscustomobject]$sandbox
if ($out.Hcsdiag -and ($out.Elevated -or $out.Group)) { $out.Hcs = Invoke-Native $out.Hcsdiag @('list') """ + str(NATIVE_S) + r""" }
[pscustomobject]$out
"""


def _run(exe: str, args: list[str], seconds: int) -> str:
    """A change: one program run (Invoke-Native), what it said given back on the RESULT line (Write-Output: an elevated
    run's file holds it too)."""
    listed = ", ".join(quote(a) for a in args)
    return (NATIVE + f"$r = Invoke-Native {quote(exe)} @({listed}) {int(seconds)}\n"
            f"Write-Output ('{RESULT}' + ($r | ConvertTo-Json -Compress))")


def container(exe: str, endpoint: str | None, verb: str, container_id: str, force: bool = False) -> str:
    """A container started, stopped or removed on its engine: docker at the engine's pipe, or nerdctl (endpoint None)."""
    args = (["-H", endpoint] if endpoint else []) + [verb] + (["-f"] if force else []) + [container_id]
    return _run(exe, args, 120)


def sandbox_start(wsb: str, config: str | None) -> str:
    """A sandbox started through wsb (Windows 11 24H2's command: `wsb --raw start [--config XML]`, which gives its Id),
    then its window opened (`wsb connect`, started apart: it lasts as long as the window)."""
    args = ["--raw", "start"] + (["--config", config] if config else [])
    listed = ", ".join(quote(a) for a in args)
    return (NATIVE + f"$r = Invoke-Native {quote(wsb)} @({listed}) 180\n"
            f"Write-Output ('{RESULT}' + ($r | ConvertTo-Json -Compress))\n"
            "if ($r.Code -eq 0 -and ([string]$r.Out) -match '([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})') {\n"
            "    $psi = New-Object System.Diagnostics.ProcessStartInfo\n"
            f"    $psi.FileName = {quote(wsb)}\n"
            "    $psi.Arguments = 'connect --id ' + $Matches[1]\n"
            "    $psi.UseShellExecute = $false\n"
            "    $psi.CreateNoWindow = $true\n"
            "    [void][System.Diagnostics.Process]::Start($psi)\n"
            "}")


def sandbox_classic(exe: str, path: str | None) -> str:
    """Windows Sandbox's own program started with a .wsb (its window is the sandbox), not waited for."""
    return ("$psi = New-Object System.Diagnostics.ProcessStartInfo\n"
            f"$psi.FileName = {quote(exe)}\n"
            + (f"$psi.Arguments = '\"' + {quote(path)} + '\"'\n" if path else "")
            + "$psi.UseShellExecute = $false\n"
            "$p = [System.Diagnostics.Process]::Start($psi)\n"
            f"Write-Output ('{RESULT}' + (@{{ Code = 0; Out = [string]$p.Id; Err = '' }} | ConvertTo-Json -Compress))")


def sandbox_stop(wsb: str, sandbox_id: str) -> str:
    return _run(wsb, ["stop", "--id", sandbox_id], 120)
