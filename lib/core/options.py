#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


class Options:
    def __init__(self):
        parser = argparse.ArgumentParser(description='a tool that helps you hook the program you want to hook '
                                                     'according to regular expressions, more details see: '
                                                     'https://github.com/Margular/frida-skeleton')

        parser.add_argument('regexps', nargs='*', default=[r'^com\.'],
                            help=r'regular expressions that specifies the application names you want to hook, for '
                                 r'example "^com\.baidu\.", if it is empty, hook all programs starting with com.')
        parser.add_argument('-i', '--install', action='store_true',
                            help='install frida server to /data/local/tmp automatically')
        parser.add_argument('-p', '--port', type=int,
                            help='reverse tcp port, if specified, manipulate iptables automatically, data flow: '
                                 'mobile | all tcp streams -> mobile | tcp 8080 -> your pc/laptop | tcp 8080, done '
                                 'by iptables and adb reverse')
        parser.add_argument('-s', '--spawn', action='store_true',
                            help='spawn mode on, attach mode off, same as native frida')
        parser.add_argument('-v', '--verbose', action='store_true', help='verbose output')

        args = parser.parse_args()

        self.regexps = args.regexps
        self.install = args.install
        self.port = args.port
        self.spawn = args.spawn
        self.verbose = args.verbose


options = Options()
