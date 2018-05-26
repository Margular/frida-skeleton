#!/usr/bin/env python
# -*- coding: utf-8 -*-

import frida
import os
import sys
import time

PROCESS = 'io.github.margular'
SCRIPT = 'hook.js'
LOG_PATH = os.path.join('logs', time.ctime()).replace(':', '_') + '.txt'

def append_log(log_path, text):
    log_dir = os.path.split(log_path)[0]
    os.makedirs(log_dir, mode = 0o700, exist_ok = True)
    with open(log_path, 'a') as f:
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

def main():
    process = frida.get_usb_device().attach(PROCESS)
    script = process.create_script(open(SCRIPT).read())
    script.on('message', on_message)
    print('[*] All code activated!')
    script.load()
    sys.stdin.read()

if __name__ == '__main__':
    main()
