#!/usr/bin/env python3

import yaml
from sys import stderr
from yaml import load, dump
from pykeepass import PyKeePass 

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

yaml_params = yaml.load(open('.\\modules\\keepass\\keepass_config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

class Keepass(object):
    def __init__(self):
        self.use = yaml_params['kps_path'] != None and yaml_params['kps_path'] != ''
        self.keepass_file = yaml_params['kps_path']
        self.keepass_password = ''
        self.keepass_writeback_group = yaml_params['kps_writeback_group']
        self.keepass_writeback_history_at_environment = yaml_params['kps_writeback_history_groups']

    def read_keepass_data(self, entry_name, field_name):
        try:
            kp = PyKeePass(self.keepass_file, password=self.keepass_password)
            entry = kp.find_entries(title=entry_name, first=True)
            field_data = entry._get_string_field(field_name)
            
            return field_data
        except Exception as e:
            raise ValueError('[ERRO] - Erro ao ler o Keepass:\n%s \n\nVerifique a senha informada e tente novamente' % (str(e)), file=stderr)