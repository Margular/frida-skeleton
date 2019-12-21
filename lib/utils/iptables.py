#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Iptables:
    install_cmd = 'iptables -t nat -A OUTPUT -p tcp -o lo -j RETURN'
    install_cmd2 = 'iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:{}'
    uninstall_cmd = 'iptables -t nat -F'

    def __init__(self, adb):
        self._adb = adb

    def uninstall(self):
        self._adb.unsafe_shell(self.uninstall_cmd, root=True)

    def install(self, port):
        self._adb.unsafe_shell(self.install_cmd, root=True)
        self._adb.unsafe_shell(self.install_cmd2.format(port), root=True)
