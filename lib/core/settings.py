#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

# The name of the operating system dependent module imported.
# The following names have currently been registered: 'posix', 'nt', 'mac', 'os2', 'ce', 'java', 'riscos'
PLATFORM = os.name
IS_WIN = PLATFORM == "nt"
ROOT_DIR = os.path.dirname(sys.argv[0])
LOG_DIR = os.path.join(ROOT_DIR, 'logs')
FRIDA_SERVER_DEFAULT_PORT = 27042
