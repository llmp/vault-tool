#!/usr/bin/env python3

import yaml
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

yaml_params = yaml.load(open('.\\modules\\vault\\vault_config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

class Vault(object):
    def __init__(self, name, url, use=False, client_token='', secret=None, x_vault_token=None):
        self.name = name
        self.url = url
        self.use = use
        self.x_vault_token = x_vault_token
        self.secret = secret
        self.client_token = client_token
        self.unseal_key_quorum = yaml_params['vault_key_quorum']

    def clear_secret(self):
        self.secret = None

    def clear_x_vault_token(self):
        self.x_vault_token = ''

    def clear_use(self):
        self.use=True

    def clear_vault_cache(self):
        self.clear_secret()
        self.clear_x_vault_token()

