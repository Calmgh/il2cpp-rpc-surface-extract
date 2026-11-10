#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Shared bootstrap: make ``il2cpprpc`` importable when running a script
directly out of ``tools/`` without installing the package.
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)
