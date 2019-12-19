#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Iptables:
    _commands = [
        ['iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports {}',
         'iptables -t nat -D OUTPUT -p tcp -j REDIRECT --to-ports {}'],
    ]

    def __init__(self, adb):
        self._adb = adb

    def uninstall(self, port):
        rets = []

        for install, uninstall in self._commands:
            rets.append(self._adb.unsafe_shell(uninstall.format(port), root=True))

        return rets

    def install(self, port):
        rets = []

        for install, uninstall in self._commands:
            rets.append(self._adb.unsafe_shell(install.format(port), root=True))

        return rets
