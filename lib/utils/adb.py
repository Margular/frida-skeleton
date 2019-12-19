#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.utils.shell import Shell


class Adb(Shell):
    def __init__(self, serial=""):
        self._serial = serial
        # if we are root shell
        self._root = False

    @classmethod
    def start_server(cls):
        return cls.cmd_and_debug('adb start-server')

    def root(self):
        ret = self.cmd_and_debug('adb -s "{}" root'.format(self._serial))
        if not 'cannot run as root' in ret['out']:
            self._root = True
        return ret

    def unsafe_shell(self, command, root=False):
        return self.cmd_and_debug(r'''adb -s "{}" shell "{}{}"'''.format(
            self._serial, 'su - -c ' if root and not self._root else '', command))

    def push(self, src, dst):
        return self.cmd_and_debug('adb push "{}" "{}"'.format(src, dst))

    def reverse(self, port):
        return self.cmd_and_debug('adb -s "{0}" reverse tcp:{1} tcp:{1}'.format(self._serial, port))
