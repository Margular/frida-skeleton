#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Iptables:

    def __init__(self, adb, port):
        self.adb = adb
        self.port = port
        self.install_cmd = 'iptables -t nat -A OUTPUT -p tcp -o lo -j RETURN'
        self.install_cmd2 = 'iptables -t nat -A OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:{}'.format(port)
        self.uninstall_cmd = 'iptables -t nat -D OUTPUT -p tcp -o lo -j RETURN'
        self.uninstall_cmd2 = 'iptables -t nat -D OUTPUT -p tcp -j DNAT --to-destination 127.0.0.1:{}'.format(port)

    def uninstall(self):
        rules = self.adb.unsafe_shell('iptables -t nat -S', root=True, debug=False)['out']

        for rule in rules:
            if 'iptables -t nat {}'.format(rule) == self.install_cmd:
                self.adb.unsafe_shell(self.uninstall_cmd)
                break

        for rule in rules:
            if 'iptables -t nat {}'.format(rule) == self.install_cmd2:
                self.adb.unsafe_shell(self.uninstall_cmd2)
                break

    def install(self):
        self.adb.unsafe_shell(self.install_cmd, root=True)
        self.adb.unsafe_shell(self.install_cmd2, root=True)
