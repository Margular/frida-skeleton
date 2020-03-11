#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import signal
import time

import urllib3

from lib.core.exception import MainExit
from lib.core.log import LOGGER, FORMATTER
from lib.core.settings import LOG_DIR
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb
from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def shutdown(signum, frame):
    if signum == signal.SIGINT:
        LOGGER.info('keyboard interrupt event detected')
    elif signum == signal.SIGTERM:
        LOGGER.info('termination event detected')
    else:
        LOGGER.error('unknown event detected')

    raise MainExit


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

    try:
        watch_thread.start()
        while True:
            time.sleep(1)
    except MainExit:
        LOGGER.info('shutdown, thank you for using frida skeleton')
        watch_thread.cancel()


if __name__ == '__main__':
    main()
