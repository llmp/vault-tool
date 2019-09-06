#!/usr/bin/env python3

from modules.keepass import Keepass


class Credential(object):
    def __init__(self, view, kps=Keepass()):
        self.view = view
        self.kps_client = kps
    
    def get_x_vault_tokens(self, option, vault_servers):
        vault_names = vault_servers.keys() if option == 1 else [list(vault_servers.keys())[option-2]]
        # Validação de configuração do KeePass
        if self.kps_client.use:
            if all(vault_servers[name].x_vault_token for name in vault_names):
                for name in vault_names:
                    vault_servers[name].use = True
                self.view.message_already_loaded()
            else:
                choice = self.view.x_vault_token_input_method()
                try:
                    if choice == 1:
                        if self.kps_client.keepass_password == '':
                            self.kps_client.keepass_password = self.view.get_keepass_password()
                        for name in vault_names:
                            done = False
                            token = None

                            while not done:
                                try:
                                    token = self.kps_client.read_keepass_data(name, 'Password')
                                    done = True
                                except Exception as e:
                                    self.view.display_error(e)
                                    self.kps_client.keepass_password = self.view.get_keepass_password()
                                    pass

                            vault_servers[name].x_vault_token = token
                            vault_servers[name].use = True

                    elif choice == 2:
                        for name in vault_names:
                            vault_servers[name].x_vault_token = self.view.get_keepass_password()
                            vault_servers[name].use = True
                except Exception as e:
                    raise(e)

        # Caso de não configuração do path de arquivo do KeePass
        else:
            try:
                if all(vault_servers[name].token != '' for name in vault_names):
                    for name in vault_names:
                        vault_servers[name].use = True
                    self.view.message_already_loaded()

                else:
                    for name in vault_names:
                        vault_servers[name].token = self.view.get_environment_token(name)
                        vault_servers[name].use = True
            except Exception as e:
                raise(e)
        
        return vault_servers
        