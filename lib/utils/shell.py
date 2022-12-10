#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
from subprocess import Popen, PIPE

from thirdparty.attrdict import AttrDict


class Shell:
    def __init__(self):
        self.log = logging.getLogger(self.__class__.__name__)

    def exec(self, cmd: str, quiet=False, supress_error=False) -> AttrDict:
        ret = AttrDict()

        if not quiet:
            self.log.debug(cmd)

        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, close_fds=True)

        # output processing
        out = p.stdout.read().decode().strip()
        ret.out = out
        err = p.stderr.read().decode().strip()
        ret.err = err

        output = '{} <output> {}'.format(cmd, out if out else 'Nothing')

        if err and not supress_error:
            output += ' <error> ' + err

        if not quiet:
            self.log.debug(output)

        return ret
