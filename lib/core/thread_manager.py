#!/usr/bin/env python
# -*- coding: utf-8 -*-

import threading

__lock__ = threading.Lock()


class ThreadManager:
    def __init__(self):
        self.thread_map = {}

    def add_thread(self, thread):
        with __lock__:
            self.thread_map[thread] = True

    def del_thread(self, thread):
        with __lock__:
            self.thread_map.pop(thread)

    def is_empty(self):
        with __lock__:
            return len(self.thread_map) == 0


thread_manager = ThreadManager()
