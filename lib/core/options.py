#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse


class Options:
    def __init__(self):
        parser = argparse.ArgumentParser(description='基于frida的安卓hook框架，提供了很多frida自身不支持的功能，'
                                                     '将hook安卓变成简单便捷，人人都会的事情，项目地址：'
                                                     'https://github.com/Margular/frida-skeleton')

        parser.add_argument('regexps', nargs='*', default=[r'^com\.'],
                            help=r'根据你指定的正则表达式去匹配包名hook对应的程序，支持多个正则表达式')
        parser.add_argument('-l', '--list', action='store_true', help='显示设备列表')
        parser.add_argument('-d', '--devices', type=str, help='指定hook的设备，多个设备逗号隔开')
        parser.add_argument('-i', '--install', action='store_true',
                            help='自动从github安装对应版本和架构的frida-server到assets目录下，支持断点续传，下载完后自动运行')
        parser.add_argument('-p', '--port', type=int,
                            help='自动利用iptables和adb将所有的TCP流量重定向到PC的指定端口，这样就可以在本机监听该端口来抓包了')
        parser.add_argument('-n', '--no-root', action='store_true', help='不尝试使用adb root获取root权限，默认尝试')
        parser.add_argument('-s', '--spawn', action='store_true',
                            help='开启frida的spawn模式并忽略项目配置文件中的spawn选项，开启此选项会导致被hook的进程自动重启')
        parser.add_argument('-v', '--verbose', action='store_true', help='输出调试信息')

        args = parser.parse_args()

        self.list = args.list
        self.devices = args.devices
        self.regexps = args.regexps
        self.install = args.install
        self.port = args.port
        self.no_root = args.no_root
        self.spawn = args.spawn
        self.verbose = args.verbose


options = Options()
