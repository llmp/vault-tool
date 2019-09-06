#!/usr/bin/env python3

import yaml
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

yaml_params = yaml.load(open('.\\modules\\aws\\aws_config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

class AWSCliemt(object):
    def __init__(self):
        self.s3_role = yaml_params['aws_s3_role']
        self.dynamo_role = yaml_params['aws_dynamo_role']