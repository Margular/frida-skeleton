#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import frida
import os
import re
import subprocess
import sys
import time
import threading

__LOG__ = time.strftime("%Y-%m-%d %H-%M-%S.log")


def append_log(log_path, text):
    text = text.strip()
    if len(text) == 0:
        return
    log_dir = os.path.split(log_path)[0]
    os.makedirs(log_dir, mode=0o700, exist_ok=True)
    with open(log_path, 'a', encoding='utf8') as f:
        f.write(text)
        f.write("\n")
    print(text)


def on_message(message, data):
    if message['type'] == 'error':
        text = message['description']
    elif message['type'] == 'send':
        text = message['payload']
    else:
        text = message

    append_log(os.path.join("logs", __LOG__), text)


def hook_apps(device, regexp):
    # [] or None
    if not regexp:
        regexp = ['.*']

    proc_names = set(_.name for _ in device.enumerate_processes())

    print('Start hooking apps that has been started by user...\n')
    for name in proc_names:
        for _ in regexp:
            if re.search(_, name):
                try:
                    hook(device, name)
                except Exception as e:
                    print(e)
                finally:
                    break

    print('Initial hooking finished!\n')

    # Start hooking all the following apps
    while True:
        time.sleep(1)
        new_proc_names = set(_.name for _ in device.enumerate_processes())
        if len(new_proc_names) == 0:
            continue

        differ_names = new_proc_names - proc_names
        for name in differ_names:
            for _ in regexp:
                if re.search(_, name):
                    # Wait for app starting completely
                    time.sleep(1)
                    try:
                        hook(device, name)
                    except Exception as e:
                        print(e)
                    finally:
                        break

        proc_names = new_proc_names


def hook(device, name):
    print('[*] Now hook app ' + name)
    process = device.attach(name)
    js = 'Java.perform(function() {'

    # Load all scripts under folder 'scripts'
    for (dirpath, dirnames, filenames) in os.walk('scripts'):
        for filename in filenames:
            js += open(os.path.join(dirpath, filename), encoding="utf-8").read()
            js += '\n'

    js += '});'
    script = process.create_script(js)
    script.on('message', on_message)
    print('[*] All code activated! ' + name)
    script.load()


def check_frida_server(device):
    try:
        # Try to enumerate processes so that we can determine the state of frida server
        device.enumerate_processes()
    except frida.InvalidArgumentError:
        print('Please plug-in your mobile device!')
        sys.exit(-1)
    except frida.ServerNotRunningError:
        return False

    return True


def run_frida_server(device):
    # Get filenames inside /data/local/tmp
    output = subprocess.run('adb -s "{}" shell ls /data/local/tmp'.format(device.id),
                            stdout=subprocess.PIPE, shell=True).stdout.decode()
    frida_servers = []  # Store all found frida server filenames

    # Seek out all frida-server
    for filename in output.split('\n'):
        filename = filename.strip()
        if filename.startswith('frida-server'):
            frida_servers.append('/data/local/tmp/' + filename)

    # No frida server
    if len(frida_servers) == 0:
        return False
    # Only one frida server has been found
    elif len(frida_servers) == 1:
        print('Running ' + frida_servers[0])
        subprocess.Popen('adb -s "{}" shell setsid "{}"'.format(device.id, frida_servers[0]), shell=True)
    else:
        print('Select the frida server you want to run:\n')

        # Print all frida servers
        for i in range(len(frida_servers)):
            print('[{}] {}'.format(i, frida_servers[i]))

        choice = input('Your choice: ')

        # Invalid choice
        if not choice.isdigit() or int(choice) < 0:
            print('Invalid choice ' + choice)
            sys.exit(-1)

        print('running ' + frida_servers[int(choice)])
        subprocess.Popen('adb shell -s "{}" setsid {}'.format(device.id, frida_servers[int(choice)]), shell=True)

    # Wait for frida server
    time.sleep(5)
    return True


def hook_device(device, regexp):
    # First check whether the frida server has been started
    if not check_frida_server(device):
        print('frida server has not been started yet! now try to run frida-server from /data/local/tmp...')
        # Try to run frida server automatically inside /data/local/tmp
        if not run_frida_server(device):
            print('failed to run frida server! you need to run it manually or put a frida-server '
                  'inside /data/local/tmp')
            sys.exit(-1)

    hook_apps(device, regexp)


def main():
    parser = argparse.ArgumentParser(description='A tool that hook all apps you need')
    parser.add_argument('regexp', type=str, nargs='*',
                        help=r'Regexp for the apps you want to hook such as "^com\.baidu\.", '
                             r'empty for hooking all apps')

    args = parser.parse_args()

    devices = frida.enumerate_devices()
    threads = []

    for device in devices:
        if device.type != 'usb':
            continue
        thread = threading.Thread(target=hook_device, args=(device, args.regexp))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()


if __name__ == '__main__':
    main()
