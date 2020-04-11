#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.utils.shell import Shell


class Adb(Shell):
    def __init__(self, serial=""):
        super().__init__()

        self.serial = serial
        # if we are root shell
        self.is_root = False
        self.check_root()

    @staticmethod
    def start_server():
        return Shell().cmd_and_debug('adb start-server')

    def check_root(self):
        if self.unsafe_shell('whoami')['out'] == 'root':
            self.is_root = True

    def root(self):
        self.cmd_and_debug('adb -s "{}" root'.format(self.serial))
        self.check_root()

    def unsafe_shell(self, command, root=False, debug=True):
        return self.cmd_and_debug(r'''adb -s "{}" shell "{}{}"'''.format(
            self.serial, 'su - -c ' if root and not self.is_root else '', command), debug)

    def push(self, src, dst):
        return self.cmd_and_debug('adb -s "{}" push "{}" "{}"'.format(self.serial, src, dst))

    def reverse(self, port):
        return self.cmd_and_debug('adb -s "{0}" reverse tcp:{1} tcp:{1}'.format(self.serial, port))

    def clear_reverse(self, remote_port):
        return self.cmd_and_debug('adb -s "{}" reverse --remove tcp:{}'.format(self.serial, remote_port))

    def forward(self, local_port, remote_port):
        return self.cmd_and_debug('adb -s "{}" forward tcp:{} tcp:{}'.format(self.serial, local_port, remote_port))

    def clear_forward(self, local_port):
        return self.cmd_and_debug('adb -s "{}" forward --remove tcp:{}'.format(self.serial, local_port))
