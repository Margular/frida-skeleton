#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging

import urllib3

from lib.core.log import LOGGER
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb

# disable ssl warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def main():
    parser = argparse.ArgumentParser(description='A tool that hook all apps you need')

    parser.add_argument('regexps', type=str, nargs='*',
                        help=r'Regexps for the apps you want to hook such as "^com\.baidu\.", '
                             r'empty for hooking all apps')
    parser.add_argument('-i', '--install', action='store_true', help='install frida server to /data/local/tmp automatically')
    parser.add_argument('-p', '--port', type=int,
                        help='reverse tcp port, if specified, manipulate iptables automatically')
    parser.add_argument('-v', action='store_true', help='verbose output')

    args = parser.parse_args()

    if args.v:
        LOGGER.setLevel(logging.DEBUG)

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
