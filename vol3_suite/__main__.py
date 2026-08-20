"""
Entrypoint for `python -m vol3_suite`.
"""

import sys
from .cli import main

if __name__ == "__main__":
    sys.exit(main())
