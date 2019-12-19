#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import sys

from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

LOGGER = logging.getLogger("fridaSkeletonLog")

LOGGER_HANDLER = ColorizingStreamHandler(sys.stdout)

FORMATTER = logging.Formatter("\r[%(asctime)s] [%(levelname)s] %(message)s", "%H:%M:%S")

LOGGER_HANDLER.setFormatter(FORMATTER)
LOGGER.addHandler(LOGGER_HANDLER)
LOGGER.setLevel(logging.INFO)
