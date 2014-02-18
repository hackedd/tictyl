#!/usr/bin/env python
from setuptools import setup


def get_version():
    with open("tictyl.py", "r") as fp:
        for line in fp:
            if line.startswith("__version__"):
                return eval(line.split("=")[-1])


def read(filename):
    with open(filename, "r") as fp:
        return fp.read()


setup(
    name="tictyl",
    version=get_version(),
    description="Tictyl manages your SSH port forwardings.",
    long_description="",
    author="Paul Hooijenga",
    author_email="paulhooijenga@gmail.com",
    url="https://github.com/hackedd/tictyl",
    license="MIT",
    install_requires=["pyyaml"],
    py_modules=["tictyl"],
    entry_points={
        "console_scripts": [
            "tictyl = tictyl:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2",
    ],
)
