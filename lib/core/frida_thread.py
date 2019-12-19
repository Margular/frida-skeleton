#!/usr/bin/env python
# -*- coding: utf-8 -*-

import lzma
import os
import re
import threading
import time

import frida

from lib.core.common import download
from lib.core.log import LOGGER
from lib.utils.adb import Adb
from lib.utils.iptables import Iptables


class FridaThread(threading.Thread):

    def run(self) -> None:
        self._device = self._args[0]
        args = self._args[1]

        LOGGER.debug('{} start with args: device={}, args={}'.format(self._name, self._device, args))

        # hook by regexp
        self._regexps = args.regexps
        # whether install frida server automatically
        self._i = args.i
        # tcp reverse port
        self._port = args.port
        if self._port:
            self._port_enabled = False

        self._adb = Adb(self._device.id)
        self._iptables = Iptables(self._adb)

        self._arch = self._adb.unsafe_shell("getprop ro.product.cpu.abi")['out']
        # maybe get 'arm64-v8a'
        self._arch = 'arm64' if 'arm64' in self._arch else self._arch
        self._server_name = 'frida-server-{}-android-{}'.format(frida.__version__, self._arch)
        self._log = time.strftime('%Y-%m-%d_%H-%M-%S_') + self._device.id + '.log'

        self.prepare()
        self.hook_apps()

    # prepare for starting hook
    def prepare(self):
        # get root
        self._adb.root()

        self._iptables.uninstall(self._port)

        if self._i:
            self.install_frida_server()

        self.kill_frida_servers()
        self.run_frida_server()

    def kill_frida_servers(self):
        try:
            apps = self._device.enumerate_processes()
        except frida.ServerNotRunningError:
            # frida server has not been started, no need to start
            return

        for app in apps:
            if app.name == self._server_name:
                self._device.kill(app.pid)

    def run_frida_server(self):
        self._adb.unsafe_shell('chmod +x /data/local/tmp/' + self._server_name)
        threading.Thread(
            target=self._adb.unsafe_shell,
            args=('/data/local/tmp/{} -D'.format(self._server_name), True)
        ).start()

        # waiting for frida server
        time.sleep(1)

    def install_frida_server(self):
        server_path = os.path.join('assets', self._server_name)
        server_path_xz = server_path + '.xz'

        # if not exist frida server then install it
        if not self._adb.unsafe_shell("ls /data/local/tmp/" + self._server_name)['out']:
            LOGGER.info('download {} from github ...'.format(self._server_name))
            download('https://github.com/frida/frida/releases/download/{}/{}.xz'
                     .format(frida.__version__, self._server_name), server_path_xz)

            # extract frida server
            with open(server_path, 'wb') as f:
                with lzma.open(server_path_xz) as xz:
                    f.write(xz.read())

            # upload frida server
            self._adb.push(server_path, '/data/local/tmp/')

    def hook_apps(self):
        if not self._regexps:
            self._regexps = ['.*']

        # first hook started apps
        apps = set(p.name for p in self._device.enumerate_processes())

        LOGGER.info('hook apps that has been started by user')

        for app in apps:
            for regexp in self._regexps:
                if re.search(regexp, app):
                    try:
                        self.hook(app)
                    except Exception as e:
                        LOGGER.error(e)
                    finally:
                        break

        LOGGER.info('Initial hooking finished!')

        # monitor apps
        while True:
            time.sleep(1)

            new_apps = set(p.name for p in self._device.enumerate_processes())
            if len(new_apps) == 0:
                continue

            differ_apps = new_apps - apps
            for differ_app in differ_apps:
                for regexp in self._regexps:
                    if re.search(regexp, differ_app):
                        # Wait for app starting completely
                        time.sleep(1)

                        try:
                            self.hook(differ_app)
                        except Exception as e:
                            LOGGER.error(e)
                        finally:
                            break

            apps = new_apps

    def hook(self, app):
        LOGGER.info('hook app ' + app)
        process = self._device.attach(app)
        js = 'Java.perform(function() {'

        # Load all scripts under folder 'scripts'
        for (dirpath, dirnames, filenames) in os.walk('scripts'):
            for filename in filenames:
                _ = open(os.path.join(dirpath, filename), encoding="utf-8").read()
                if _.startswith(r'''/*Deprecated*/'''):
                    continue
                js += _
                js += '\n'

        js += '});'
        script = process.create_script(js)
        script.on('message', self.on_message)
        script.load()

        # install iptables and reverse tcp port
        if not self._port_enabled and self._port:
            # enable tcp connections between frida server and binding
            self._device.enumerate_processes()
            self._iptables.install(self._port)
            self._adb.reverse(self._port)
            self._port_enabled = True

    def on_message(self, message, data):
        if message['type'] == 'error':
            text = message['description'].strip()

            if not text:
                return

            LOGGER.error(text)
        else:
            text = message['payload'].strip() if message['type'] == 'send' else message.strip()

            if not text:
                return

            LOGGER.info(text)

        self.append_log(os.path.join("logs", self._log), text)

    def append_log(self, log_path, text):
        log_dir = os.path.split(log_path)[0]
        os.makedirs(log_dir, mode=0o700, exist_ok=True)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(text)
            f.write("\n")
