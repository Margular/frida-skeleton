#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import time

import urllib3

from lib.core.log import LOGGER, FORMATTER
from lib.core.settings import LOG_DIR
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb
from thirdparty.ansistrm.ansistrm import ColorizingStreamHandler

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


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

    Adb.start_server()

    try:
        t = WatchThread(args.install, args.port, args.regexps, True)
        t.start()
        t.join()
    except KeyboardInterrupt:
        LOGGER.info('shutdown, thank you for using frida skeleton')
    except Exception as e:
        LOGGER.error(e)


if __name__ == '__main__':
    main()
