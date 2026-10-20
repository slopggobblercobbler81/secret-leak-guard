#!/usr/bin/env python
import os
from setuptools import setup, find_packages

setup(
    name="secret-leak-guard",
    version="1.0.0",
    description="High-performance CLI regex & entropy scanner for accidental tokens/secrets in git diffs and codebases.",
    long_description=open("README.md", encoding="utf-8").read() if os.path.exists("README.md") else "",
    long_description_content_type="text/markdown",
    author="slopggobblercobbler81",
    author_email="336610228+slopggobblercobbler81@users.noreply.github.com",
    url="https://github.com/slopggobblercobbler81/secret-leak-guard",
    packages=find_packages(include=["secret_leak_guard", "secret_leak_guard.*"]),
    python_requires=">=3.8",
    entry_points={
        "console_scripts": [
            "secret-leak-guard=secret_leak_guard.cli:main",
        ],
    },
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
