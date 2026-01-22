#!/usr/bin/env python3
"""
Convenience wrapper to run Malachi Stack.

Usage: sudo python3 run.py --iface <interface>

Or use the module directly:
    sudo python3 -m malachi --iface <interface>
"""

from malachi.__main__ import main

if __name__ == "__main__":
    main()
