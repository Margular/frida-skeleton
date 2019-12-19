#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading
import time

import frida

from lib.core.frida_thread import FridaThread
from lib.core.log import LOGGER


class WatchThread(threading.Thread):

    def run(self) -> None:
        args = self._args[0]

        LOGGER.debug('{} start with args: {}'.format(self._name, args))

        threads = []

        while True:
            devices = frida.enumerate_devices()

            for device in devices:
                if device.type != 'usb':
                    continue

                duplicated = False

                for t in threads:
                    if t._args[0].id == device.id:
                        if not t.is_alive():
                            threads.remove(t)
                            break

                        duplicated = True
                        break

                if duplicated:
                    continue

                LOGGER.info("hook device: id={}, name={}, type={}".format(device.id, device.name, device.type))
                new_thread = FridaThread(name='FridaThread', args=(device, args))
                new_thread.start()
                threads.append(new_thread)

            time.sleep(1)
