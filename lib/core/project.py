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

    def __init__(self, path: str, name: str, regexp: str):
        self.log = logging.getLogger(self.__class__.__name__ + '|' + name)

        self.path = path
        self.name = name
        self.regexp = regexp

    @classmethod
    def logger(cls):
        with __lock__:
            if hasattr(cls, 'log'):
                return cls.log
            else:
                return logging.getLogger(cls.__name__)

    @classmethod
    def preload(cls) -> str:
        js = 'Java.perform(function() {'

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
                    if config.name and config.enable and config.regexp:
                        yield Project(entry.path, config.name, config.regexp)
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
                if os.path.splitext(filename) != '.js':
                    continue
                js += open(os.path.join(dirpath, filename), encoding="utf-8").read() + '\n'

        return js
