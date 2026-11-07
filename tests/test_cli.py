"""Tests for DeadDrop Command Line Interface."""

import secrets
import sys
import pytest
from deaddrop.client.cli import main


def test_cli_help(capsys):
    test_args = ["deaddrop", "--help"]
    sys.argv = test_args
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "DeadDrop" in captured.out
    assert "send" in captured.out
    assert "receive" in captured.out
    assert "list" in captured.out
    assert "burn" in captured.out
    assert "audit" in captured.out
    assert "server" in captured.out
    assert "gui" in captured.out
    assert "lab" in captured.out


def test_cli_subcommand_help(capsys):
    for subcmd in ["send", "receive", "list", "burn", "audit", "server", "gui", "lab"]:
        test_args = ["deaddrop", subcmd, "--help"]
        sys.argv = test_args
        with pytest.raises(SystemExit) as exc:
            main()
        assert exc.value.code == 0
        captured = capsys.readouterr()
        assert f"usage: deaddrop {subcmd}" in captured.out.lower()


def test_cli_missing_command(capsys):
    test_args = ["deaddrop"]
    sys.argv = test_args
    main()
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "help" in captured.out.lower()
