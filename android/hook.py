#!/usr/bin/env python
# -*- coding: utf-8 -*-

import frida
import os
import re
import subprocess
import sys
import time


def gen_log_path():
    return os.path.join('logs', time.ctime()).replace(':', '_') + '.txt'


def append_log(log_path, text):
    log_dir = os.path.split(log_path)[0]
    os.makedirs(log_dir, mode=0o700, exist_ok=True)
    with open(log_path, 'a', encoding='utf8') as f:
        f.write(text)
        f.write(os.linesep)
    print(text)


def on_message(message, data):
    if message['type'] == 'error':
        text = message['description']
    elif message['type'] == 'send':
        text = message['payload']
    else:
        text = message

    append_log(gen_log_path(), text)


def hook_apps(hook_regexp=None):
    name_pool = set(_.name for _ in frida.get_usb_device().enumerate_processes())

    # init hook
    if hook_regexp:
        for name in name_pool:
            for _ in hook_regexp:
                if re.search(_, name):
                    print('init hook with <' + name + '>')
                    try:
                        hook(name)
                    except (frida.ProcessNotFoundError, frida.TransportError) as e:
                        print(e)
                    break

    # start hook infinitely
    while True:
        time.sleep(0.1)
        name_pool_2 = set(_.name for _ in frida.get_usb_device().enumerate_processes())
        if len(name_pool_2) == 0:
            continue
        differ_names = name_pool_2 - name_pool
        for name in differ_names:
            for _ in hook_regexp:
                if re.search(_, name):
                    time.sleep(1)
                    print('Now hook <' + name + '>')
                    try:
                        hook(name)
                    except (frida.ProcessNotFoundError, frida.TransportError) as e:
                        print(e)
        name_pool = name_pool_2


def hook(name):
    process = frida.get_usb_device().attach(name)
    js = 'Java.perform(function() {'
    for (dirpath, dirnames, filenames) in os.walk('scripts'):
        for filename in filenames:
            js += open(os.path.join(dirpath, filename)).read()
    js += '});'
    script = process.create_script(js)
    script.on('message', on_message)
    print('[*] All code activated!')
    script.load()


def check_frida_server():
    try:
        frida.get_usb_device().enumerate_processes()
    except frida.ServerNotRunningError as e:
        return False

    return True


def try_run_frida_server():
    output = subprocess.run('adb shell ls /data/local/tmp', stdout=subprocess.PIPE, shell=True).stdout.decode()
    frida_servers = []

    for filename in output.split('\r\n'):
        if filename.startswith('frida-server'):
            frida_servers.append('/data/local/tmp/' + filename)

    if len(frida_servers) == 0:
        return False
    elif len(frida_servers) == 1:
        print('start ' + frida_servers[0])
        subprocess.Popen('adb shell setsid ' + frida_servers[0], shell=True)
    else:
        print('select frida_server to start:\n')

        for i in range(len(frida_servers)):
            print('[{}] {}'.format(i, frida_servers[i]))

        choice = input('your choice: ')
        if not choice.isdigit() or int(choice) < 0:
            print('invalid input')
            sys.exit(-1)

        print('start ' + frida_servers[0])
        subprocess.Popen('adb shell setsid ' + frida_servers[int(choice)], shell=True)

    time.sleep(5)
    return True


def main():
    if not check_frida_server():
        print('frida server has not been started yet! now try to start frida-server from /data/local/tmp...')
        if not try_run_frida_server():
            print('run frida server failed! you need to start it manually')
            sys.exit(-1)

    hook_apps(hook_regexp=['^com\.huawei'])


if __name__ == '__main__':
    main()
