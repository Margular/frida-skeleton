#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


class Options:
    def __init__(self):
        parser = argparse.ArgumentParser(description='A tool that hook all apps you need')

        parser.add_argument('regexps', nargs='*', default=[r'^com\.'],
                            help=r'Regexps for the apps you want to hook such as "^com\.baidu\.", '
                                 r'empty for hooking all apps')
        parser.add_argument('-i', '--install', action='store_true',
                            help='install frida server to /data/local/tmp automatically')
        parser.add_argument('-p', '--port', type=int,
                            help='reverse tcp port, if specified, manipulate iptables automatically')
        parser.add_argument('-s', '--spawn', action='store_true',
                            help='spawn mode on, attach mode off')
        parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')

        args = parser.parse_args()

        self.regexps = args.regexps
        self.install = args.install
        self.port = args.port
        self.spawn = args.spawn
        self.verbose = args.verbose


options = Options()
