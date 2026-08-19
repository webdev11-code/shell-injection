#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Zqrya-Exploit — All-in-One Web Exploitation Suite.

Install:
    pip install .
    # atau mode editable (dev):
    pip install -e .

Setelah terpasang, gunakan launcher:
    zqrya --cli https://target.com --crawler -o report.html
"""

import os

from setuptools import find_packages, setup

HERE = os.path.abspath(os.path.dirname(__file__))


def read(fname):
    with open(os.path.join(HERE, fname), encoding="utf-8") as f:
        return f.read()


setup(
    name="zqrya-exploit",
    version="1.0.0",
    description=("Zqrya-Exploit — All-in-One Web Exploitation Suite "
                 "(scanner + exploiter: RCE, SQLi, XSS, SSTI, SSRF, LFI, XXE, "
                 "OOB, recon, fuzz)"),
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="Zqrya",
    url="https://github.com/zqrya/zqrya-exploit",
    license="MIT",
    # Satu package Python berisi core + vendored engines (tools/) + wordlist.
    packages=find_packages(exclude=("tests", "tests.*")),
    include_package_data=True,
    package_data={
        "zqrya_exploit": [
            "wordlist.txt",
            "tools/bin/*",
            "tools/dbstrike/*.py",
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
    ],
    entry_points={
        "console_scripts": [
            "zqrya=zqrya_exploit:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
    ],
)
