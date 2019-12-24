#!/usr/bin/env python3

import platform
import subprocess
import distutils
from distutils.cmd import Command
from distutils.core import setup, Extension
from distutils.command.build_ext import build_ext

# https://jichu4n.com/posts/how-to-add-custom-build-steps-and-commands-to-setuppy/
class YasmCommand(Command):
    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        command = ["yasm", "-D__GNUC__", "-g", "dwarf2", "-f", "elf64", "../aes/aes_amd64.asm"]
        self.announce("Running command: {}".format(" ".join(command)))
        subprocess.check_call(command)


class BuildExtCommand(build_ext):
  def run(self):
    self.run_command("yasm")
    super().run()

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
    define_macros = [("ASM_AMD64_C", None)]
    cmdclass = {
        "yasm": YasmCommand,
        "build_ext": BuildExtCommand,
    }
    extra_objects = ["aes_amd64.o"]
else:
    cmdclass = {}
    extra_objects = []
    define_macros = []

setup(
    cmdclass=cmdclass,
    name="aes",
    version="1.0",
    ext_modules=[
        Extension(
            name="aes",
            sources=source_files,
            include_dirs=["../aes"],
            define_macros=define_macros,
            extra_compile_args=cflags,
            extra_objects=extra_objects,
        )
    ],
)
