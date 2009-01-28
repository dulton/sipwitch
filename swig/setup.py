#!/usr/bin/env python

"""
setup.py file for SWIG example
"""

from distutils.core import setup, Extension

sipwitch_module = Extension('_sipwitch', sources=['wrapper.cpp'],)

setup (name = 'sipwitch',
       version = '0.1',
       author      = "SWIG Docs",
       description = """Interface to control local instance of GNU SIP Witch""",
       ext_modules = [sipwitch_module],
       py_modules = ["sipwitch"],
       )

