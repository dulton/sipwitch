#!/usr/bin/env python
# Copyright (C) 2009 David Sugar, Tycho Softworks.
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

"""
setup.py file for SWIG example
"""

from distutils.core import setup, Extension

setup (
	name = 'GNU SIP Witch',
	version = '0.1',
	author      = "David Sugar",
	author_email = 'dyfet@gnutelephony.org',
	url = 'http://www.gnutelephony.org',
	description = """Interface to control local instance of GNU SIP Witch""",
	ext_modules = [Extension('sipwitch._server', ['wrapper.cpp'])],
	py_modules = ["server"],
	packages = ['sipwitch']
)

