#!/usr/bin/env python
# -*- coding: utf-8 -*-

import logging
import lzma
import os
import re
import sys
import threading
import time

import frida
import requests

from lib.core.port_manager import port_manager
from lib.core.settings import ROOT_DIR, FRIDA_SERVER_DEFAULT_PORT
from lib.core.thread_manager import thread_manager
from lib.core.types import FakeDevice
from lib.utils.adb import Adb
from lib.utils.iptables import Iptables

__lock__ = threading.Lock()


class FridaThread(threading.Thread):

    def __init__(self, device, install: bool, port: int, regexps: list, spawn: bool):
        super().__init__()

        self.log = logging.getLogger(self.__class__.__name__ + '|' + device.id)

        if device.type == FakeDevice.type:
            # init remote device
            self.log.debug('device {} does not support get_usb_device, changing to get_remote_device'.format(device.id))
            self.forward_port = port_manager.acquire_port(excludes=[port])
            self.device = frida.get_device_manager().add_remote_device('127.0.0.1:{}'.format(self.forward_port))
            self.device.id = device.id
        else:
            self.device = device

        self.install = install
        self.port = port
        self.regexps = regexps if regexps else ['.*']
        self.spawn = spawn

        self.adb = Adb(self.device.id)

        if device.type == FakeDevice.type:
            result = self.adb.forward(self.forward_port, FRIDA_SERVER_DEFAULT_PORT)
            # port has been used
            if len(result['err'].strip()) > 0:
                port_manager.release_port(self.forward_port)
                raise RuntimeError('port {} has been used'.format(self.forward_port))

        if self.port:
            self.iptables = Iptables(self.adb, self.port)

        self.arch = self.adb.unsafe_shell("getprop ro.product.cpu.abi")['out']
        # maybe get 'arm64-v8a', 'arm-v7a' ...
        if 'arm64' in self.arch:
            self.arch = 'arm64'
        elif 'arm' in self.arch:
            self.arch = 'arm'
        elif 'x86_64' in self.arch:
            self.arch = 'x86_64'
        elif 'x86' in self.arch:
            self.arch = 'x86'
        else:
            raise RuntimeError('unknown arch: ' + self.arch)

        self.server_name = 'frida-server-{}-android-{}'.format(frida.__version__, self.arch)

        self.stop_flag = False

        thread_manager.add_thread(self)

    def run(self) -> None:
        self.log.info("{} start with hook device: id={}, name={}, type={}".format(
            self.__class__.__name__, self.device.id, self.device.name, self.device.type))

        try:
            self.prepare()
            self.hook_apps()
        except Exception as e:
            self.log.error('device {}: {}'.format(self.device.id, e))

        try:
            self.shutdown()
        except Exception as e:
            self.log.error('unexpected error occurred when shutdown device {}: {}'.format(self.device.id, e))

        self.log.debug('device {} exit'.format(self.device.id))
        thread_manager.del_thread(self)

    # prepare for starting hook
    def prepare(self):
        # get root
        self.adb.root()

        # close selinux
        self.adb.unsafe_shell('setenforce 0', root=True)

        # install iptables and reverse tcp port
        if self.port:
            # enable tcp connections between frida server and binding
            self.iptables.install()
            self.adb.reverse(self.port)

        if self.install:
            self.install_frida_server()

        self.kill_frida_servers()
        self.run_frida_server()

    def download(self, url, file_path):
        # get total size of file
        r1 = requests.get(url, stream=True, verify=False)
        total_size = int(r1.headers['Content-Length'])

        # check downloaded size
        if os.path.exists(file_path):
            temp_size = os.path.getsize(file_path)
        else:
            temp_size = 0

        if temp_size == total_size:
            self.log.info('{} has downloaded completely'.format(file_path))
            return

        if temp_size > total_size:
            self.log.error('{} has corrupted, download it again'.format(file_path))
            os.remove(file_path)
            return self.download(url, file_path)

        self.log.debug('{} of {} needs to be download'.format(total_size - temp_size, total_size))

        # download from temp size to end
        headers = {'Range': 'bytes={}-'.format(temp_size)}

        r = requests.get(url, stream=True, verify=False, headers=headers)

        with open(file_path, "ab") as f:
            for chunk in r.iter_content(chunk_size=1024):
                if self.stop_flag:
                    break

                if chunk:
                    temp_size += len(chunk)
                    f.write(chunk)
                    f.flush()

                    # download progress
                    done = int(50 * temp_size / total_size)
                    sys.stdout.write(
                        "\r[{}{}] {:.2f}%".format('█' * done, ' ' * (50 - done), 100 * temp_size / total_size))
                    sys.stdout.flush()

        sys.stdout.write(os.linesep)

    def install_frida_server(self):
        server_path = os.path.join(ROOT_DIR, 'assets', self.server_name)
        server_path_xz = server_path + '.xz'

        # if not exist frida server then install it
        if not self.adb.unsafe_shell("ls /data/local/tmp/" + self.server_name)['out']:
            self.log.info('download {} from github ...'.format(self.server_name))
            with __lock__:
                self.download('https://github.com/frida/frida/releases/download/{}/{}.xz'
                              .format(frida.__version__, self.server_name), server_path_xz)

            # extract frida server
            with open(server_path, 'wb') as f:
                with lzma.open(server_path_xz) as xz:
                    f.write(xz.read())

            # upload frida server
            self.adb.push(server_path, '/data/local/tmp/')

    def kill_frida_servers(self):
        try:
            apps = self.device.enumerate_processes()
        except (frida.ServerNotRunningError, frida.TransportError, frida.InvalidOperationError):
            # frida server has not been started, no need to start
            return

        for app in apps:
            if app.name == self.server_name:
                self.adb.unsafe_shell('kill -9 {}'.format(app.pid), root=True, debug=False)

    def run_frida_server(self):
        self.adb.unsafe_shell('chmod +x /data/local/tmp/' + self.server_name)
        threading.Thread(
            target=self.adb.unsafe_shell,
            args=('/data/local/tmp/{} -D'.format(self.server_name), True)
        ).start()

        # waiting for frida server
        while True:
            try:
                time.sleep(0.5)
                self.device.enumerate_processes()
                break
            except (frida.ServerNotRunningError, frida.TransportError, frida.InvalidOperationError):
                continue

    def hook_apps(self):
        apps = set()

        # monitor apps
        while True:
            if self.stop_flag:
                break

            time.sleep(0.1)

            new_apps = set(p.name for p in self.device.enumerate_processes())
            if not new_apps:
                continue

            incremental_apps = new_apps - apps
            decremental_apps = apps - new_apps

            for incremental_app in incremental_apps:
                if self.stop_flag:
                    break

                for regexp in self.regexps:
                    if re.search(regexp, incremental_app):
                        # waiting for app startup completely
                        time.sleep(0.1)

                        try:
                            self.hook(incremental_app)
                        except Exception as e:
                            self.log.error(e)
                        finally:
                            break

            for decremental_app in decremental_apps:
                if self.stop_flag:
                    break

                for regexp in self.regexps:
                    if re.search(regexp, decremental_app):
                        self.log.info('app {} has died'.format(decremental_app))
                        break

            apps = new_apps

    def hook(self, app: str):
        app = app.strip()
        if not app:
            raise RuntimeError('try to hook empty app name')

        self.log.info('hook app ' + app)
        if self.spawn:
            process = self.device.attach(self.device.spawn(app))
        else:
            process = self.device.attach(app)
        js = 'Java.perform(function() {'

        # load all scripts under folder 'scripts'
        for (dirpath, dirnames, filenames) in os.walk(os.path.join(ROOT_DIR, 'scripts')):
            for filename in filenames:
                _ = open(os.path.join(dirpath, filename), encoding="utf-8").read()
                if _.startswith(r'''/*Deprecated*/'''):
                    continue
                js += _
                js += '\n'

        js += '});'
        script = process.create_script(js)
        script.on('message', self.on_message(app))
        script.load()

        if self.spawn:
            self.device.resume(self.device.get_process(app).pid)

    def on_message(self, app: str):
        app_log = logging.getLogger('{}|{}|{}'.format(self.__class__.__name__, self.device.id, app))

        def on_message_inner(message, data):
            try:
                if message['type'] == 'error':
                    text = message['description'].strip()

                    if not text:
                        return

                    app_log.error(text)
                else:
                    text = message['payload'].strip() if message['type'] == 'send' else message.strip()

                    if not text:
                        return

                    app_log.info(text)
            except Exception as e:
                app_log.error(e)

        return on_message_inner

    def cancel(self):
        self.stop_flag = True

    def shutdown(self):
        self.log.debug('shutdown device ' + self.device.id)

        self.kill_frida_servers()

        if self.device.type == 'remote':
            port_manager.release_port(self.forward_port)
            self.adb.clear_forward(self.forward_port)

        if self.port:
            self.iptables.uninstall()
            self.adb.clear_reverse(self.port)
