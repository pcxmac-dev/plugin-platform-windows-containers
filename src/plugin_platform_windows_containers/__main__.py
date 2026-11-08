"""`python -m plugin_platform_windows_containers ...`: the plugin from the command line, through the same hooks as the
platform's page and with the same refusals (--force gives the second confirmation removing a running container asks for,
--accept the one a .wsb's settings ask for). CONTAINER: its name, or its Id; --engine KEY when two engines have it.

    status                                     the plugin's status (JSON)
    engines | containers | images | sandboxes  what is there (JSON)
    start CONTAINER [--engine KEY]             a container started
    stop CONTAINER [--engine KEY]              a running container stopped
    remove CONTAINER [--engine KEY] [--force]  a container removed (--force: a running one too)
    sandbox [FILE.wsb] [--accept]              Windows Sandbox launched, with the file's settings (said unless --accept)
    close-sandbox ID                           a sandbox wsb runs closed
"""
from __future__ import annotations

import argparse
import json
import sys

from liminal_libs.machines.plugin import CommandError

from . import MACHINE


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="python -m plugin_platform_windows_containers",
                                description="Windows containers for Liminal: engines, containers, images, Windows Sandbox")
    sub = p.add_subparsers(dest="what")
    sub.add_parser("status", help="the plugin's status (JSON)")
    for what in ("engines", "containers", "images", "sandboxes"):
        sub.add_parser(what, help=f"the {what} there are (JSON)")
    for what, words in (("start", "a container started"), ("stop", "a running container stopped"), ("remove", "a container removed")):
        s = sub.add_parser(what, help=words)
        s.add_argument("container", help="the container's name, or its Id")
        s.add_argument("--engine", help="the engine's key (engines lists them) when two have it")
        if what == "remove":
            s.add_argument("--force", action="store_true", help="the second confirmation: a running container ended at once")
    b = sub.add_parser("sandbox", help="Windows Sandbox launched")
    b.add_argument("file", nargs="?", help="a .wsb file (its whole path); none: Windows Sandbox's own defaults")
    b.add_argument("--accept", action="store_true", help="the second confirmation: launched with the file's settings")
    c = sub.add_parser("close-sandbox", help="a sandbox wsb runs closed")
    c.add_argument("id", help="its Id (sandboxes lists them)")
    return p


def main(argv: list[str] | None = None, plugin=None, out=None, err=None) -> int:
    p = plugin if plugin is not None else MACHINE
    say = out or print
    tell = err or (lambda s: print(s, file=sys.stderr))
    try:
        args = parser().parse_args(sys.argv[1:] if argv is None else argv)
    except SystemExit as e:  # argparse's usage, said already
        return int(e.code or 0)
    what = args.what or "status"
    try:
        if what == "status":
            say(json.dumps(p.status(), indent=1))
            return 0 if p.present() else 1
        if what in ("engines", "containers", "images", "sandboxes"):
            say(json.dumps(getattr(p, what)(), indent=1))
            return 0
        if what == "start":
            answer = p.start_container(args.container, args.engine)
        elif what == "stop":
            answer = p.stop_container(args.container, args.engine)
        elif what == "remove":
            answer = p.remove_container(args.container, args.engine, accept_force=args.force)
        elif what == "sandbox":
            answer = p.launch_sandbox(args.file, accept_settings=args.accept)
        else:
            answer = p.stop_sandbox(args.id)
    except ValueError as e:  # a refusal: nothing was changed
        hint = {"accept_force": " (--force removes it)", "accept_settings": " (--accept launches it with them)"}.get(
            getattr(e, "accept", None) or "", "")
        tell(f"refused: {e}{hint}")
        return 1
    except CommandError as e:
        tell(f"failed: {e}")
        return 1
    say(answer["said"])
    for line in answer.get("lines") or []:
        say(f"  {line}")
    return 0 if answer.get("ok", True) else 1


if __name__ == "__main__":
    sys.exit(main())
