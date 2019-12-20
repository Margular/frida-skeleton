#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os

# The name of the operating system dependent module imported.
# The following names have currently been registered: 'posix', 'nt', 'mac', 'os2', 'ce', 'java', 'riscos'
PLATFORM = os.name
IS_WIN = PLATFORM == "nt"
