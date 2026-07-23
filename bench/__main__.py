"""`python -m bench` == `python -m bench.run`."""

import sys

from bench.run import main

if __name__ == "__main__":
    sys.exit(main())
