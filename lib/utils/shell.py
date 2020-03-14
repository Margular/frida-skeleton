#!/usr/bin/env python
# -*- coding: utf-8 -*-

from subprocess import Popen, PIPE

from lib.core.log import LOGGER


class Shell:

    @classmethod
    def cmd_and_debug(cls, cmd: str, debug=True) -> map:
        ret = {'out': '', 'err': ''}

        if debug:
            LOGGER.debug(cmd)

        p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE, close_fds=True)

        err = p.stderr.read().decode().strip()
        if err:
            if err != 'Unable to start: Error binding to address: Address already in use':
                LOGGER.error('shell error: ' + err)
                ret['err'] = err

        out = p.stdout.read().decode().strip()
        if out:
            if debug:
                LOGGER.debug('shell output: ' + out)
            ret['out'] = out

        return ret
