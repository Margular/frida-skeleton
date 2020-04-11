#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import signal
import sys
import time

import coloredlogs
import urllib3

from lib.core.settings import LOG_DIR
from lib.core.thread_manager import thread_manager
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MainExit(Exception):
    pass


class FridaSkeleton:
    def __init__(self):
        parser = argparse.ArgumentParser(description='A tool that hook all apps you need')

        parser.add_argument('regexps', type=str, nargs='*',
                            help=r'Regexps for the apps you want to hook such as "^com\.baidu\.", '
                                 r'empty for hooking all apps')
        parser.add_argument('-i', '--install', action='store_true',
                            help='install frida server to /data/local/tmp automatically')
        parser.add_argument('-p', '--port', type=int,
                            help='reverse tcp port, if specified, manipulate iptables automatically')
        parser.add_argument('-v', action='store_true', help='verbose output')

        args = parser.parse_args()

        try:
            self.log = logging.getLogger(self.__class__.__name__)

            level = 'DEBUG' if args.v else 'INFO'
            coloredlogs.install(level=level)

            # set log
            os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
            log_filename = time.strftime('%Y-%m-%d_%H-%M-%S.log')
            log_file = open(os.path.join(LOG_DIR, log_filename), 'a', encoding='utf-8')
            coloredlogs.install(level=level, stream=log_file)

            # set handling interrupt exceptions
            signal.signal(signal.SIGTERM, self.shutdown)
            signal.signal(signal.SIGINT, self.shutdown)

            Adb.start_server()

            watch_thread = WatchThread(args.install, args.port, args.regexps)
        except (KeyboardInterrupt, InterruptedError) as e:
            self.log.info(e)
            sys.exit(-1)

        try:
            watch_thread.start()
            while True:
                time.sleep(1)
        except MainExit:
            while True:
                try:
                    self.log.info('shutdown command received, wait for clean up please...')
                    watch_thread.cancel()
                    break
                except MainExit:
                    pass

        # waiting for sub threads
        while True:
            try:
                while True:
                    self.should_we_exit()
                    time.sleep(1)
            except MainExit:
                try:
                    n = len(thread_manager.thread_map)
                    if n > 0:
                        self.log.info('running sub threads: {}, wait a second please'.format(n))
                except MainExit:
                    pass

    def shutdown(self, signum, frame):
        if signum == signal.SIGINT:
            self.log.debug('keyboard interrupt event detected')
        elif signum == signal.SIGTERM:
            self.log.debug('termination event detected')
        else:
            self.log.warning('unknown event detected')

        raise MainExit

    def should_we_exit(self):
        if thread_manager.is_empty():
            self.log.info('sub threads exit completely, bye!')
            sys.exit(0)


if __name__ == '__main__':
    FridaSkeleton()
