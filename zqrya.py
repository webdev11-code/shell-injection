#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Shim backward-compat: `python zqrya.py ...` == `zqrya ...`."""
from zqrya_exploit import main

if __name__ == "__main__":
    main()
