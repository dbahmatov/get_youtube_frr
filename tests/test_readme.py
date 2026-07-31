"""README не должен обещать команды и флаги, которых нет в argparse."""

import shlex
from pathlib import Path

import pytest

from bgpfeed.cli import build_parser


README = Path(__file__).parents[1] / "README.md"
CONTRIB = Path(__file__).parents[1] / "contrib"


def documented_commands():
    prefix = "python3 -m bgpfeed "
    return [
        shlex.split(line.strip()[len(prefix):])
        for line in README.read_text(encoding="utf-8").splitlines()
        if line.strip().startswith(prefix)
    ]


def test_readme_contains_new_cli_examples():
    assert documented_commands()


@pytest.mark.parametrize("argv", documented_commands())
def test_every_readme_command_parses(argv):
    build_parser().parse_args(argv)


@pytest.mark.parametrize("unit", sorted(CONTRIB.glob("*.service")))
def test_systemd_execstart_uses_existing_cli(unit):
    line = next(
        line for line in unit.read_text(encoding="utf-8").splitlines()
        if line.startswith("ExecStart=")
    )
    command = shlex.split(line.removeprefix("ExecStart="))
    module = command.index("bgpfeed")
    build_parser().parse_args(command[module + 1:])
