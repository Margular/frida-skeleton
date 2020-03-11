#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time

import frida

from lib.core.frida_thread import FridaThread
from lib.core.log import LOGGER


class WatchThread(threading.Thread):

    def __init__(self, install: bool, port: int, regexps: list):
        super().__init__()
        self.install = install
        self.port = port
        self.regexps = regexps
        self.frida_threads = []
        self.stop_flag = False

    def run(self) -> None:
        LOGGER.debug('{} start'.format(self.__class__.__name__))

        while True:
            if self.stop_flag:
                break

            devices = frida.enumerate_devices()

            for device in devices:
                if device.type != 'usb':
                    continue

                duplicated = False

                for t in self.frida_threads:
                    if t.device.id == device.id:
                        if not t.is_alive():
                            self.frida_threads.remove(t)
                            break

                        duplicated = True
                        break

                if duplicated:
                    continue

                frida_thread = FridaThread(device, self.install, self.port, self.regexps)
                frida_thread.start()
                self.frida_threads.append(frida_thread)

            time.sleep(0.1)

    def cancel(self):
        for frida_thread in self.frida_threads:
            frida_thread.cancel()

        self.stop_flag = True
