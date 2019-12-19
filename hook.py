#!/usr/bin/env python
# -*- coding: utf-8 -*-

# disable ssl warnings
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import argparse
import logging

from lib.core.log import LOGGER
from lib.core.watch_thread import WatchThread
from lib.utils.adb import Adb


def main():
    parser = argparse.ArgumentParser(description='A tool that hook all apps you need')

    parser.add_argument('regexps', type=str, nargs='*',
                        help=r'Regexps for the apps you want to hook such as "^com\.baidu\.", '
                             r'empty for hooking all apps')
    parser.add_argument('-i', action='store_true', help='install frida server to /data/local/tmp automatically')
    parser.add_argument('-p', '--port', type=int,
                        help='reverse tcp port, if specified, manipulate iptables automatically')
    parser.add_argument('-v', action='store_true', help='verbose output')

    args = parser.parse_args()

    if args.v:
        LOGGER.setLevel(logging.DEBUG)

    Adb.start_server()

    t = WatchThread(name="WatchThread", args=(args,))
    t.start()
    t.join()


if __name__ == '__main__':
    main()
