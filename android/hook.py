#!/usr/bin/env python
# -*- coding: utf-8 -*-

import frida
import os
import re
import time

LOG_PATH = os.path.join('logs', time.ctime()).replace(':', '_') + '.txt'


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

    append_log(LOG_PATH, text)


# hook all following started apps automatically for hands free
# hook_regexp: the app name regexp you want to hook with
# init_hook_regexp: the app name regexp you want to init hook before hook following apps
def hook_following_apps(hook_regexp=None, init_hook_regexp=None):
    # recording all apps first
    name_pool = set(_.name for _ in frida.get_usb_device().enumerate_processes())

    # init hook
    if init_hook_regexp:
        for name in name_pool:
            for _ in init_hook_regexp:
                if re.search(_, name):
                    print('init hook with <' + name + '>')
                    hook(name)
                    break

    while True:
        time.sleep(0.1)
        name_pool_2 = set(_.name for _ in frida.get_usb_device().enumerate_processes())
        differ_names = name_pool_2 - name_pool
        for name in differ_names:
            time.sleep(2)
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


def main():
    hook_following_apps(init_hook_regexp=['^com\.huawei\.'])


if __name__ == '__main__':
    main()
