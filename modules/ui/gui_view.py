#!/usr/bin/env python3
import getpass
import shlex

from datetime import datetime
from datetime import timedelta
from shlex import quote

class GUI(object):
    def __init__(self, debug=False, verbose=False):
        self.verbose = verbose
        self.debug = debug
        