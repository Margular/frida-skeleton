#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time

import frida

from lib.core.frida_thread import FridaThread
from lib.core.log import LOGGER


class WatchThread(threading.Thread):

    def __init__(self, install: bool, port: int, regexps: list, daemon: bool):
        super().__init__(daemon=daemon)
        self.install = install
        self.port = port
        self.regexps = regexps

    def run(self) -> None:
        LOGGER.debug('{} start'.format(self.__class__.__name__))

        threads = []

        while True:
            devices = frida.enumerate_devices()

            for device in devices:
                if device.type != 'usb':
                    continue

                duplicated = False

                for t in threads:
                    if t.device.id == device.id:
                        if not t.is_alive():
                            threads.remove(t)
                            break

                        duplicated = True
                        break

                if duplicated:
                    continue
                try:
                    new_thread = FridaThread(device, self.install, self.port, self.regexps, True)
                    new_thread.start()
                    threads.append(new_thread)
                except Exception as e:
                    LOGGER.error(e)

            time.sleep(0.1)
