"""Flat entry point for PyInstaller's standalone binary build.

unwindy normally launches via the ``unwindy`` console script or
``python -m unwindy``; PyInstaller wants a plain script as the freeze root.
The package (and the optional ``iced-x86`` extra) must be installed first.
"""

import sys

from unwindy.cli import main

if __name__ == "__main__":
    sys.exit(main())
