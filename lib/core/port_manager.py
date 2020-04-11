#!/usr/bin/env python
# -*- coding: utf-8 -*-

import secrets
import threading

__lock__ = threading.Lock()


class PortManager:
    def __init__(self):
        self.port_map = {}

    @classmethod
    def secure_rand_port(cls):
        while True:
            port = secrets.randbits(16)
            if port < 1024:
                continue
            return port

    def acquire_port(self):
        with __lock__:
            while True:
                port = PortManager.secure_rand_port()

                if port in self.port_map.keys():
                    continue

                self.port_map[port] = True
                return port

    def release_port(self, port):
        with __lock__:
            assert port in self.port_map.keys()
            self.port_map.pop(port)


port_manager = PortManager()
