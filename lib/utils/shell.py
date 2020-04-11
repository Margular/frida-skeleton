#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from subprocess import Popen, PIPE


class Shell:
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)

    def cmd_and_debug(self, cmd: str, debug=True) -> map:
        ret = {'out': '', 'err': ''}

        if debug:
            self.log.debug(cmd)

        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, close_fds=True)

        err = p.stderr.read().decode().strip()
        if err:
            if err != 'Unable to start: Error binding to address: Address already in use':
                self.log.error('shell error: ' + err)
                ret['err'] = err

        out = p.stdout.read().decode().strip()
        if out:
            if debug:
                self.log.debug('shell output: ' + out)
            ret['out'] = out

        return ret
