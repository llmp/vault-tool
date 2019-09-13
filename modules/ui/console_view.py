#!/usr/bin/env python3
import getpass
import shlex

from sys import exit
from modules.utils import validations
from datetime import datetime
from datetime import timedelta
from shlex import quote


class Console(object):
    def __init__(self, debug=False, verbose=False):
        self.verbose = verbose
        self.debug = debug
        self.clear = "\n" * 100

    def main_menu(self):
        print("""\


        ██╗   ██╗ █████╗ ██╗   ██╗██╗  ████████╗
        ██║   ██║██╔══██╗██║   ██║██║  ╚══██╔══╝
        ██║   ██║███████║██║   ██║██║     ██║   
        ╚██╗ ██╔╝██╔══██║██║   ██║██║     ██║   
         ╚████╔╝ ██║  ██║╚██████╔╝███████╗██║   
          ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝   
            ████████╗ ██████╗  ██████╗ ██╗      
            ╚══██╔══╝██╔═══██╗██╔═══██╗██║      
               ██║   ██║   ██║██║   ██║██║      
               ██║   ██║   ██║██║   ██║██║      
               ██║   ╚██████╔╝╚██████╔╝███████╗ 
               ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝ 
                                       v2.0 by Leo Molina
==========================================================
    Selecione a opção desejada:

        Digite 1 para criar uma nova secret          
        Digite 2 para consultar uma secret
        Digite 3 para atualizar uma secret 
        Digite 4 para listar as secrets 
        Digite 5 para recriar um token
        Digite 6 para renovar um token
        Digite 7 para consultar um token
        Digite 8 para revogar um token
        Digite 9 para operações administrativas
        Digite 0 para sair
    
    Selecione a opção desejada:\n""")
        
        min_opt = 0
        max_opt = 10
        option = None

        try:
            option = validations.get_option(min_opt, max_opt)
        except:
            print('[DEBUG] - Exceção encontrada, limpando dados da aplicação...')
        return option

    def message_already_loaded(self):
        print(self.clear + "Chaves do(s) ambiente(s) selecionado(s) já carregadas. Prosseguindo...") 
    
    def get_keepass_password(self):
        return validations.get_input(self.clear + 'Informe a senha do KeePass (input estará ocultado):', hidden=True)

    def get_environment_token(self,name):
        return validations.get_input(self.clear + 'Informe o token do ambiente {} (input estará ocultado):'.format(name), hidden=True)

    def get_secret_name(self):
        return validations.get_input(self.clear + 'Informe o nome da secret:')

    def display_error(self, e):
        print(e)

    def x_vault_token_input_method(self):
        print("""\
                """+self.clear+"""
==================================================================\n
É necessário buscar o token do Vault para realizar esta operação\n
    Digite 1 para buscar o token no KeePass
    Digite 2 para inserir o token manualmente\n""")

        return validations.get_option(1,3)


    def environment_selection_menu(self, environment_names):
        max_option = self.print_environments(environment_names)
        option = validations.get_option(0, max_option + 1)

        if option == 0:
            exit(0)
        elif option < max_option:
            return option

    def print_environments(self, environment_names):
        i=2
        print("""\
    """+ self.clear +"""
==============================================================
    Informe os ambientes onde deseja executar a operação
        Digite 1 para todos os ambientes          """)
        for key in environment_names:
            print("\tDigite " + str(i) + " para " + str(key) + " (somente)")
            i += 1
        
        print("""\tDigite """ + str(i) + """ para retornar ao menu principal
        Digite 0 para sair\n""")

        return i

    def confirm_environment_change(self, environment_name):
        return validations.get_yes_or_no('\n\nConfirmar a execução para o ambiente %s?' % environment_name)
        

    def print_tokens(self, environments):
        print(""""""+self.clear+"""\n=======================================================================
                Geração de token(s) concluída: """)

        for key, data in environments.items():
            if data.use:
                print('\nToken para ' + key + ': ' + data.client_token)
        print("\n\nPressione alguma tecla para continuar...")
        getpass.getpass(' ')

    def get_keys(self,environment_name):
        i = 1
        secret_keys_pairs = {}
        
        print(""""""+self.clear+"""==============================================================\n
Informe agora os conjuntos de chaves e valores para o ambiente """ + environment_name + """\n""")

        while True:
            
            try:
                key = validations.get_input('Chave ' + str(i) + ': ', False, False)
                if key != '':
                    val = validations.get_input('Valor ' + str(i) + ': ')
                    secret_keys_pairs[key] = val
                    i = i+1
                    print('\n\nInforme a próxima chave ou, caso não haja mais chaves para cadastro, pressione ENTER\n')
                else:
                    break

            except (ValueError, NameError):
                print("[ERRO] - Valor inválido para chave/valor")
        
        if not secret_keys_pairs:
            secret_keys_pairs['1'] = '1'
        return secret_keys_pairs

    def print_formatted_secret_data(self, environment_name, secret_name, data):

        print("""\n====================================================
            Dados da Secret em """ + environment_name + """
====================================================

    Os dados da secret """ + secret_name + """ são:\n""")
        for key, value in data.items():
            print("\t" + key + " : " + value)

    def print_formatted_policy_data(self, secret_name, policy_rules):
        policy_name = secret_name + '-policy'
        print('\n\n    Permissões da policy \'' + policy_name +'\':\n\t' + policy_rules)

    def read_secret_menu(self, environment_names):
        pass

    def update_secret_menu(self, environment_names):
        pass

    def list_secret_menu(self, environment_names):
        pass

    def get_policies(self):
        redo = True
        policies = dict()
        
        while redo:
            print("""\
    """+self.clear+"""==============================================================\n
        Informe uma policy para ser adicionada ao token:\n
            Digite 1 para acesso à secret (default)
            Digite 2 para acesso ao S3 (Amazon)
            Digite 3 para acesso ao Dynamo (Amazon)
            Digite 4 para retornar ao menu principal
            Digite 0 para sair

            Policies já adicionadas: """ + ', '.join(list(policies.keys())) + """
    """)

            opt = validations.get_option(0,5)

            if opt == 0:
                exit(0)

            elif opt == 1:
                if 'read' in policies.keys():
                    print('Essa policy já foi adicionada!')
                else: 
                    capabilities = self.get_capabilities('read')
                    policies.update({'read': capabilities })

            elif opt == 2:
                if 'aws-s3' in policies.keys():
                    print('Essa policy já foi adicionada!')
                # elif aws_s3_role == '':
                #     print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
                else: 
                    capabilities = self.get_capabilities('aws-s3')
                    policies.update({'aws-s3': capabilities  })

            elif opt == 3:
                if 'aws-dynamo' in policies.keys():
                    print('Essa policy já foi adicionada!')
                # elif aws_dynamo_role == '':
                #     print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
                else: 
                    capabilities = self.get_capabilities('aws-dynamo')
                    policies.update({'aws-dynamo': capabilities  })

            elif opt == 4:
                # redo = False
                # main()
                exit(0)

            elif opt == 5:
                exit(0)

            if not validations.get_yes_or_no('\n\nDeseja adicionar alguma outra policy?', 'n'):
                redo = False
        return policies


    def get_capabilities(self, policy_type):
        capabilities = []
        if policy_type == 'read':
            if not self.get_yes_or_no('\nA policy utilizará alguma permissão além da default (leitura da secret)?', 'n'):
                capabilities.append('read')
            else:
                redo = True
                while redo:
                    print("""\
    """+self.clear+"""==============================================================\n
        Informe uma permissão para ser adicionada à policy:\n
            Digite 1 para permissão de leitura (read)
            Digite 2 para permissão de atualização (update)
            Digite 3 para permissão de criação (create)
            Digite 4 para permissão de deleção (delete)
            Digite 5 para permissão de listagem (list)

            Permissões já adicionadas: """ + ', '.join(capabilities) + """
        """)
                    opt = validations.get_option(1,6)

                    if opt == 1:
                        if 'read' in capabilities:
                            print('Essa policy já foi adicionada!')
                        else:
                            capabilities.append('read')
                            print('Policy adicionada.')
                    elif opt == 2:
                        if 'update' in capabilities:
                            print('Essa policy já foi adicionada!')
                        else:
                            capabilities.append('update')
                            print('Policy adicionada.')
                    elif opt == 3:
                        if 'create' in capabilities:
                            print('Essa policy já foi adicionada!')
                        else:
                            capabilities.append('create')
                            print('Policy adicionada.')
                    elif opt == 4:
                        if 'delete' in capabilities:
                            print('Essa policy já foi adicionada!')
                        else:
                            capabilities.append('delete')
                            print('Policy adicionada.')
                    elif opt == 5:
                        if 'list' in capabilities:
                            print('Essa policy já foi adicionada!')
                        else:
                            capabilities.append('list')
                            print('Policy adiciona da.')

                    if not validations.get_yes_or_no('\n\nDeseja adicionar alguma outra permissão à policy?', 'n'):
                        redo = False
        else:
            capabilities.append('update')
        return capabilities

    def update_action_menu(self):
        print("""\n==================================================================
    Informe o tipo de atualização a ser realizado:

        Digite 1 para atualizar um campo
        Digite 2 para atualizar as policies
        Digite 3 para remover um campo

        Digite 0 para voltar ao menu inicial
                    """)

        opt = validations.get_option(1,5)
        return opt

    def get_field_updates(self, secret):
        print("""\n\n============================================================================================================
    Durante a atualização das chaves e valores, tanto o nome quanto o valor do campo podem ser sobrescritos
    Para inserir um par novo, informe o nome de um campo não existente na secret
=============================================================================================================\n\n""")

        new_field_name = ''
        changes = dict()
        redo = True

        while redo:
            old_field_name = validations.get_input('Informe o nome do campo a ser atualizado:')                

            if old_field_name in secret['data'] and validations.get_yes_or_no('\nDeseja alterar o nome do campo?', 'n'):    
                new_field_name = validations.get_input('\nInforme o nome novo para o campo:')
            else:
                new_field_name = old_field_name

            new_field_value = validations.get_input('\nInforme o valor novo do campo:')
            if validations.get_yes_or_no('\nConfirmar atualização?'):
                changes[old_field_name] = { 'new_name': new_field_name, 'new_value': new_field_value}
            else:
                break

            redo = validations.get_yes_or_no('\nDeseja atualizar mais alguma chave?','n')

        for old_key, key_pair in changes.items():

            if old_key in secret['data']:
                if old_key == key_pair['new_name']:
                    secret['data'][old_key] = key_pair['new_value']
                else:
                    secret['data'].pop(old_key, None)
                    secret['data'][key_pair['new_name']] = key_pair['new_value']
            else:
                secret['data'][key_pair['new_name']] = key_pair['new_value']
                    
        return secret

    def get_removed_field(self, secret):
        field_name = validations.get_input('Informe o nome do campo a ser removido:')
        if validations.get_yes_or_no('O campo ' + field_name + ' (' + secret['data'][field_name]  + ') será removido.\nConfirmar?' ):
            if field_name in secret['data']:
                secret['data'].pop(field_name, None)
            else:
                print('[INFO] - A chave informada não está presente na secret')    
        return secret
                
    def print_all_secret_data(self, environment_name, secret, policy):
        self.print_formatted_secret_data(environment_name, secret.name, secret.data)
        self.print_formatted_policy_data(secret.name, policy)
        getpass.getpass('\n\nPressione alguma tecla para continuar...')

    def get_yes_or_no(self, message, valid='s'):
        return validations.get_yes_or_no(message, valid)

    def renew_token_menu(self, environment_names):
        pass

    def lookup_token_menu(self, environment_names):
        pass

    def revoke_token_menu(self, environment_names):
        pass

    def vault_operator_menu(self, environment_names):
        pass
