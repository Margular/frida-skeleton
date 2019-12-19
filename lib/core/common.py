#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys

import requests

from lib.core.log import LOGGER


def download(url, file_path):
    # get total size of file
    r1 = requests.get(url, stream=True, verify=False)
    total_size = int(r1.headers['Content-Length'])

    # check downloaded size
    if os.path.exists(file_path):
        temp_size = os.path.getsize(file_path)
    else:
        temp_size = 0

    if temp_size == total_size:
        LOGGER.info('{} has downloaded completely'.format(file_path))
        return

    if temp_size > total_size:
        LOGGER.error('{} has corrupted, download it again'.format(file_path))
        os.remove(file_path)
        return download(url, file_path)

    LOGGER.debug('{} of {} needs to be download'.format(total_size - temp_size, total_size))

    # download from temp size to end
    headers = {'Range': 'bytes={}-'.format(temp_size)}

    r = requests.get(url, stream=True, verify=False, headers=headers)

    with open(file_path, "ab") as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                temp_size += len(chunk)
                f.write(chunk)
                f.flush()

                # download progress
                done = int(50 * temp_size / total_size)
                sys.stdout.write("\r[{}{}] {}%".format('█' * done, ' ' * (50 - done), 100 * temp_size / total_size))
                sys.stdout.flush()

    sys.stdout.write(os.linesep)
