"""ANSI color helpers - matches ADPwn's executor.py:C/_color/_bold pattern."""

from __future__ import annotations

import sys


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"


_NO_COLOR = False


def disable_color() -> None:
    global _NO_COLOR
    _NO_COLOR = True


def _color(text: str, color: str) -> str:
    if _NO_COLOR or not sys.stdout.isatty():
        return text
    return f"{color}{text}{C.RESET}"


def _bold(text: str) -> str:
    return _color(text, C.BOLD)


def _dim(text: str) -> str:
    return _color(text, C.DIM)


def banner() -> str:
    art = r"""
    _    _    _  ___ ___
   /_\  | |  | |/ __| _ \_ __ ___ _ _
  / _ \ | |/\| |\__ \  _/ V V / ' \
 /_/ \_\|__/\__||___/_|  \_/\_/|_||_|
"""
    return _color(art, C.YELLOW)


def separator(char: str = "─", width: int = 78) -> str:
    return _color(char * width, C.DIM)
