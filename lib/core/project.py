#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import os
import re
import threading

import yaml
from attrdict import AttrDict

from lib.core.settings import ROOT_DIR, PROJECT_CONFIG_FILENAME

__lock__ = threading.Lock()


class Project:

    def __init__(self, path: str, enable:bool, name: str, regexp: str, spawn: bool, priority: int):
        self.log = logging.getLogger(self.__class__.__name__ + '|' + name)

        self.path = path
        self.enable = enable
        self.name = name
        self.regexp = regexp
        self.spawn = spawn
        self.priority = priority

    @classmethod
    def logger(cls):
        with __lock__:
            if hasattr(cls, 'log'):
                return cls.log
            else:
                return logging.getLogger(cls.__name__)

    @classmethod
    def preload(cls) -> str:
        js = 'Java.perform(function() {\n'

        # recursively load js files in the script directory
        for (dirpath, dirnames, filenames) in os.walk(os.path.join(ROOT_DIR, 'scripts')):
            for filename in filenames:
                js += open(os.path.join(dirpath, filename), encoding="utf-8").read() + '\n'

        return js

    @classmethod
    def postload(cls) -> str:
        return '});'

    @classmethod
    def scan(cls, path: str):
        for entry in os.scandir(path):
            if entry.is_dir():
                try:
                    config = AttrDict(yaml.safe_load(open(os.path.join(entry.path, PROJECT_CONFIG_FILENAME))))
                    if config.regexp:
                        yield Project(entry.path,
                                      config.enable if 'enable' in config.keys() else True,
                                      os.path.basename(entry.path),
                                      config.regexp,
                                      config.spawn if 'spawn' in config.keys() else False,
                                      config.priority if 'priority' in config.keys() else 0)
                except yaml.YAMLError as e:
                    cls.logger().error('error in configuration file: {}'.format(e))

    def load(self, app: str) -> str:
        # if app match regexp
        if not re.search(self.regexp, app):
            return ''

        self.log.debug('loading...')

        js = ''

        # recursively load js files
        for (dirpath, dirnames, filenames) in os.walk(self.path):
            for filename in filenames:
                if os.path.splitext(filename)[1] != '.js':
                    continue
                js += open(os.path.join(dirpath, filename), encoding="utf-8").read() + '\n'

        return js

