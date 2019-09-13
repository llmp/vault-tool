#!/usr/bin/env python3

"""
    Autor: Leonardo Molina
    Script: Ferramenta de criação e gerenciamento de dados no Hashicorp Vault da CVC
"""


import yaml
from yaml import load, dump

from sys import argv, exit
from modules import jira, keepass, ui, vault, utils, aws

vault_core = vault.vault_core

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

yaml_params = yaml.load(open('.\\config\\config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

class Vtool(object):
    def __init__(self):
        self.vault_servers = {}
        self.view = None
        self.credentials = None

    def main(self):
        debug = False
        verbose = False
        console = True

        for arg in argv[1:]:
            if arg == '-d':
                debug = True
            elif arg == '-v':
                verbose = True
            elif arg == '-c':
                console == True

        for key, val in yaml_params['vault_envs'].items():
            self.vault_servers.update({ key : vault.vault_core.Vault(name=key,url=val) })
        
        self.view = ui.console_view.Console(debug, verbose) if console else ui.gui_view.GUI(debug, verbose)
        self.credentials = utils.Credential(self.view)

        try:
            option = self.view.main_menu()
            self.set_workflow(option) #vault_servers, credentials
        except Exception as e:
            raise(e)

    def set_workflow(self, option):
        if option == 0:
            exit(0)
        elif option == 1:
            try:
                selected_env = self.view.environment_selection_menu(self.vault_servers.keys())
                self.vault_servers = self.credentials.get_x_vault_tokens(selected_env, self.vault_servers)
                self.create_secret_menu()
            except Exception as e:
                print('[ERRO] - Não foi possível criar a secret: %s' % str(e))
        elif option == 2:
            try:
                selected_env = self.view.environment_selection_menu(self.vault_servers.keys())
                self.vault_servers = self.credentials.get_x_vault_tokens(selected_env, self.vault_servers)
                self.read_secret_menu()
            except Exception as e:
                print('[ERRO] - Não foi possível ler a secret: %s' % str(e))
        elif option == 3:
            try:
                selected_env = self.view.environment_selection_menu(self.vault_servers.keys())
                self.vault_servers = self.credentials.get_x_vault_tokens(selected_env, self.vault_servers)
                self.update_secret_menu()
            except Exception as e:
                print('[ERRO] - Não foi possível ler a secret: %s' % str(e))
        elif option == 4:
            self.view.list_secret_menu() #list
        elif option == 5:
            self.view.recreate_secret_menu(redo=True) #recreate
        elif option == 6:
            self.view.renew_token_menu() #renew
        elif option == 7:
            self.view.lookup_token_menu() #lookup
        elif option == 8:
            self.view.revoke_token_menu() #revoke
        elif option == 9:
            self.view.vault_operator_menu() #admin

    def set_aws_params(self):
        return aws.aws_client.AWSCliemt()

    def create_secret_menu(self):
        try:
            secret_name = self.view.get_secret_name()
            aws_client = self.set_aws_params()
            secret = vault.vault_secret.Secret(name=secret_name)

            for environment_name, environment_data in self.vault_servers.items():
                if environment_data.use:
                    
                    secret.secret_data = self.view.get_keys(environment_name)
                    self.vault_servers[environment_name].secret = secret
                    self.view.print_formatted_secret_data(environment_name, secret_name, self.vault_servers[environment_name].secret.secret_data)

                    if self.view.confirm_environment_change(environment_name):
                        policies = self.view.get_policies()
                        vault.vault_api.write_secret(environment_data.url,environment_data.x_vault_token, secret.data, secret.name)
                        vault.vault_api.policy_write(environment_data.url, environment_data.x_vault_token, secret_name,policies, aws_client.s3_role, aws_client.dynamo_role)
                        self.vault_servers[environment_name].client_token = vault.vault_api.token_create(environment_data.url, environment_data.x_vault_token, secret_name)
                        
            self.view.print_tokens(self.vault_servers)
                        
        except Exception as e:
            raise(e)

    def read_secret_menu(self):
        try:
            secret_name = self.view.get_secret_name()
            for environment_name, environment_data in self.vault_servers.items():
                if environment_data.use:
                    secret = vault.vault_api.read_secret(environment_data.url, environment_data.x_vault_token, secret_name)
                    self.view.print_formatted_secret_data(environment_name, secret_name, secret['data'])
        except Exception as e:
            raise(e)


    def update_secret_menu(self):
        try:
            secret_name = self.view.get_secret_name()
            for environment_name, environment_data in self.vault_servers.items():
                if environment_data.use:
                    secret = vault.vault_api.read_secret(environment_data.url, environment_data.x_vault_token, secret_name)
                    self.view.print_formatted_secret_data(environment_name, secret_name, secret['data'])
                    policy = vault.vault_api.policy_read(environment_data.url, environment_data.x_vault_token, secret_name)
                    self.view.print_formatted_policy_data(secret_name, policy)

                    option = self.view.update_action_menu()

                    if option == 0:
                        self.main()

                    elif option == 1:
                        secret = self.view.get_field_updates(secret)
                        vault.vault_api.write_secret(environment_data.url,environment_data.x_vault_token, secret['data'], secret['name'])
                    
                    elif option == 2:
                        aws_client = self.set_aws_params()
                        policies = self.view.get_policies()
                        vault.vault_api.policy_write(environment_data.url, environment_data.x_vault_token, secret_name, policies, aws_client.s3_role, aws_client.dynamo_role)
                    
                    elif option == 3:
                        secret = self.view.get_removed_field(secret)
                        vault.vault_api.write_secret(environment_data.url,environment_data.x_vault_token, secret['data'], secret['name'])
                    
                    secret = vault.vault_api.read_secret(environment_data.url, environment_data.x_vault_token, secret_name)
                    policy = vault.vault_api.policy_read(environment_data.url, environment_data.x_vault_token, secret_name)
                    secret = vault.vault_secret.Secret(secret['name'], secret['data'])
                    self.view.print_all_secret_data(environment_name, secret, policy)
                    
        except Exception as e:
            raise(e)


if __name__ == '__main__':
    while True:
        try:
            vtool = Vtool()
            vtool.main()
        except Exception as e:
            print(e)
            pass

        if not utils.get_yes_or_no('\nDeseja continuar a execução?'):
            exit(0)