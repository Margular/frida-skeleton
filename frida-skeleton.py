#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import signal
import sys
import time

import urllib3

from lib.core.log import LOGGER, FORMATTER
from lib.core.settings import LOG_DIR
from lib.core.thread_manager import thread_manager
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb
from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MainExit(Exception):
    pass


def shutdown(signum, frame):
    if signum == signal.SIGINT:
        LOGGER.debug('keyboard interrupt event detected')
    elif signum == signal.SIGTERM:
        LOGGER.debug('termination event detected')
    else:
        LOGGER.warn('unknown event detected')

    raise MainExit


def should_we_exit():
    if thread_manager.is_empty():
        LOGGER.info('sub threads exit completely, bye!')
        sys.exit(0)


def main():
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
        if args.v:
            LOGGER.setLevel(logging.DEBUG)

        # set log
        os.makedirs(LOG_DIR, mode=0o700, exist_ok=True)
        log_filename = time.strftime('%Y-%m-%d_%H-%M-%S.log')
        log_file = open(os.path.join(LOG_DIR, log_filename), 'a', encoding='utf-8')
        logger_handler = ColorizingStreamHandler(log_file)
        logger_handler.setFormatter(FORMATTER)
        LOGGER.addHandler(logger_handler)

        # set handling interrupt exceptions
        signal.signal(signal.SIGTERM, shutdown)
        signal.signal(signal.SIGINT, shutdown)

        Adb.start_server()

        watch_thread = WatchThread(args.install, args.port, args.regexps)
    except (KeyboardInterrupt, InterruptedError) as e:
        LOGGER.info(e)
        sys.exit(-1)

    try:
        watch_thread.start()
        while True:
            time.sleep(1)
    except MainExit:
        while True:
            try:
                LOGGER.info('shutdown command received, wait for clean up please...')
                watch_thread.cancel()
                break
            except MainExit:
                pass

    # waiting for sub threads
    while True:
        try:
            while True:
                should_we_exit()
                time.sleep(1)
        except MainExit:
            try:
                n = len(thread_manager.thread_map)
                if n > 0:
                    LOGGER.info('running sub threads: {}, wait a second please'.format(n))
            except MainExit:
                pass


if __name__ == '__main__':
    main()
