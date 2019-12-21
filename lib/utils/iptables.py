#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Iptables:
    install_cmd = 'iptables -t nat -A OUTPUT -p tcp -o wlan0 -j DNAT --to-destination 127.0.0.1:{}'
    uninstall_cmd = 'iptables -t nat -F'

    def __init__(self, adb):
        self._adb = adb

    def uninstall(self):
        return self._adb.unsafe_shell(self.uninstall_cmd, root=True)

    def install(self, port):
        return self._adb.unsafe_shell(self.install_cmd.format(port), root=True)
