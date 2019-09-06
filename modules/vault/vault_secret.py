#!/usr/bin/env python3

class Secret(object):
    def __init__(self, secret_name='', secret_data=dict()):
        self.secret_name = secret_name
        self.secret_data = secret_data

