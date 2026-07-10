#!/usr/bin/env python3
"""TOP RECON launcher. Run:  python run.py"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

if __name__ == "__main__":
    from gui.app import main
    sys.exit(main())
