#!/usr/bin/env python3

import platform
from distutils.core import setup, Extension

source_files = [
    "aesmodule.c",
    "aes_compat.c",
    "../aes/aeskey.c",
    "../aes/aes_modes.c",
    "../aes/aestab.c",
    "../aes/aescrypt.c",
]

cflags = []
if platform.system() == "Linux":
    cflags.append("-Wno-sequence-point")

if platform.machine() == "x86_64":
    source_files.append("../aes/aes_ni.c")

setup(
    name="aes",
    version="1.0",
    ext_modules=[
        Extension(
            "aes", source_files, include_dirs=["../aes"], extra_compile_args=cflags
        )
    ],
)
