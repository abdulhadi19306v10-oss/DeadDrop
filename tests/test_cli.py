"""Tests for DeadDrop Command Line Interface."""

import secrets
import pytest
from deaddrop.client.cli import main
import sys


def test_cli_help(capsys):
    test_args = ["deaddrop", "--help"]
    sys.argv = test_args
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert "DeadDrop Secure File Exchange CLI" in captured.out


def test_cli_missing_command(capsys):
    test_args = ["deaddrop"]
    sys.argv = test_args
    main()
    captured = capsys.readouterr()
    assert "usage:" in captured.out.lower() or "help" in captured.out.lower()
