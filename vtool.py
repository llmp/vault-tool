#!/usr/bin/env python3

"""
    Autor: Leonardo Molina
    Script: Ferramenta de criação e gerenciamento de tokens no Vault
"""

from __future__ import print_function
import libkeepass
import getpass
import sys
import shlex
import requests
import hvac
import json
import yaml
from shlex import quote
from yaml import load, dump

try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

secret_name = 'secret/'
yaml_params = yaml.load(open('.\\config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

kps_file = yaml_params['kps_path']
vault_envs = yaml_params['vault_envs']
aws_s3_role = yaml_params['aws_s3_role']
aws_dynamo_role = yaml_params['aws_dynamo_role']

vault_data = { }
debug_mode = False
verbose_mode = False

for key, val in vault_envs.items():
    vault_data.update({ key : {'url' : val, 'client_token' : '', 'secret_data' : dict(), 'use' : False, 'token' : '' } })
clear = "\n" * 100


## INITIALIZATION OPERATIONS

def initialize_vault_data():
    global vault_data
    global kps_file
    global secret_name
    print('[+INFO] Limpando e inicializando variáveis de ambiente...') if verbose_mode else 0
    
    secret_name = 'secret/'

    for key, val in vault_envs.items():
        vault_data[key]['url'] = val
        vault_data[key]['client_token'] = ''
        vault_data[key]['secret_data'] = dict()
        vault_data[key]['use'] = False

    print(vault_data) if verbose_mode else 0

def clear_cache():
    initialize_vault_data()
    main()

def get_vault_tokens(vault_names):
        global kps_file
        kps_passwd = getpass.getpass('\nInforme a senha do KeePass:')
        print("""\n==================================================================
[INFO] - Autenticando e buscando chave(s), aguarde...""")
        try:
            for name in vault_names:
                print('[+INFO] Executando busca para ' + name ) if verbose_mode else 0

                try:
                    with libkeepass.open(kps_file, password=kps_passwd) as kdb:
                        found = {}
                        for entry in kdb.obj_root.findall('.//Group/Entry'):
                            uuid = entry.find('./UUID').text
                            kv = {string.find('./Key').text : string.find('./Value').text for string in entry.findall('./String')}
                            if kv['Title'] == name:
                                found[uuid] = kv['Password']

                        removed_uuids = {uuid.text for uuid in kdb.obj_root.findall('.//DeletedObject/UUID')}

                    for password in { found[k] for k in found.keys() if k not in removed_uuids }:
                        vault_data[name]['token'] = password
                        vault_data[name]['use'] = True
                        print('[+INFO] Busca de chave concluída...') if verbose_mode else 0
                except Exception as e:
                    print('[ERRO] - Erro ao conectar ao Keepass %s:\n%s' % (kps_file, str(e)), file=sys.stderr)
                    raise(e)
                    
            print("""[INFO] - Chave(s) de ambiente obtida(s)!
    ==================================================================
    """)
        except Exception as e:
            print('[ERRO] - Não foi possível autenticar com a senha informada')
            raise(e)


def insert_vault_tokens(vault_names):
    for name in vault_names:
        vault_data[name]['token'] = getpass.getpass('Informe o token do ambiente {}:'.format(name))
        vault_data[name]['use'] = True


######## INPUT OPERATIONS ########

def get_secret_name():
    global secret_name  
    print(""""""+clear+"""==============================================================\n
    Informe o nome da secret a ser criada\n""")
    secret_name += quote(input('Informe o nome da secret: '))
    print('\n[INFO] - O nome da secret a ser criada é: ' + secret_name)


def get_policies():
    redo = True
    policies = []
    while redo:
        print("""\
"""+clear+"""==============================================================\n
    Informe uma policy para ser adicionada ao token:\n
           Digite 1 para leitura da secret (default)
           Digite 2 para acesso ao S3 (Amazon)
           Digite 3 para acesso ao Dynamo (Amazon)
           Digite 4 para retornar ao menu principal
           Digite 0 para sair

           Policies já adicionadas: """ + ', '.join(policies) + """
""")

        opt = get_option(0,5)
        print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
        if opt == 0:
            sys.exit(0)
        elif opt == 1:
            if 'read' in policies:
                print('Essa policy já foi adicionada!')
            else: 
                policies.append('read')
        elif opt == 2:
            if 'aws-s3' in policies:
                print('Essa policy já foi adicionada!')
            elif aws_s3_role == '':
                print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
            else: 
                policies.append('aws-s3')
        elif opt == 3:
            if 'aws-dynamo' in policies:
                print('Essa policy já foi adicionada!')
            elif aws_dynamo_role == '':
                print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
            else: 
                policies.append('aws-dynamo')
        elif opt == 4:
            redo = False
            main()
        elif opt == 5:
            sys.exit(0)

        if not get_yes_or_no('\n\nDeseja adicionar alguma outra policy?', 'n'):
            redo = False
        
    return policies


def get_keys(environment_name):
    i = 1
    secret_keys_pairs = {}
    
    print(""""""+clear+"""==============================================================\n
Informe agora os conjuntos de chaves e valores para o ambiente """ + environment_name + """\n""")

    while True:
        
        try:
            key = input('Chave ' + str(i) + ': ')
            if key != '':
                val = input('Valor ' + str(i) + ': ')
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


def get_option(range_min, range_max):
    while True:
        try:
            res = input('Opção: ')
            if res == 'clear_cache':
                clear_cache()
            res = (int(res))
            if res not in range(range_min, range_max):
                raise ValueError('[ERRO]')
            break
        except (ValueError, NameError):
            print("[ERRO] - Informe uma opção válida!")
    return res


def get_yes_or_no(question, default="s"):
    valid = {"sim": True, "s": True, "si": True,
             "nao": False, "n": False, "na": False, "não": False}

    while True:
        if default == "s":
            sys.stdout.write(question + " [S/n] ")
        else:
            sys.stdout.write(question + " [s/N] ")
        choice = quote(input().lower())

        if choice == '\'\'':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("[ERRO] - Por favor responda com 'sim' ou 'nao' "
                             "('s' ou 'n').\n")


def get_token_input_method(vault_names):
    if all(vault_data[name]['token'] != '' for name in vault_names):
        for name in vault_names:
            vault_data[name]['use'] = True
        print("Chaves do(s) ambiente(s) selecionado(s) já carregadas. PASSO 2 concluído, prosseguindo...") 
    
    else:
        print("""\
        """+clear+"""
========================================================================\n
É necessário o token do ambiente no Vault para realizar esta operação\n
    Digite 1 para buscar o token no KeePass
    Digite 2 para inserir o token manualmente\n""")

        opt = get_option(1,3)
        try:
            if opt == 1:
                get_vault_tokens(vault_names)
            elif opt == 2:
                insert_vault_tokens(vault_names)
        except Exception as e:
            raise(e)


######### FACADE OPERATIONS #########

def create_secret_facade(targets):
    global vault_data
    global secret_name
    
    try:
        if kps_file != '': 
            get_token_input_method(targets)
        else:
            insert_vault_tokens(targets)
    except Exception as e:
        print('[ERRO] - Falha na autenticação')

    get_secret_name()
    created = False

    for environment_name, environment_data in vault_data.items():
        if environment_data['use']:

            client = hvac.Client(
                url= vault_data[environment_name]['url'],
                token=vault_data[environment_name]['token']
            )

            vault_data[environment_name]['secret_data'] = get_keys(environment_name)


            print("""\n==================================================================
[INFO] - As chaves da """ + secret_name + """ para o """ + environment_name +  """ serão:
""")
            
            print_formatted_secret_data(environment_name, secret_name, vault_data[environment_name]['secret_data'])

            if get_yes_or_no('\n\nOs dados estão corretos?'):
                write_secret(vault_data[environment_name], secret_name, client)
                policies = get_policies()
                policy_write(vault_data[environment_name], secret_name, client, policies)
                token_create(vault_data[environment_name], secret_name, client)
                created = True  
            else:
                print('\n[INFO] - OPERAÇÃO INTERROMPIDA PELO USUÁRIO!') if verbose_mode else 0
            client.adapter.close()
        
    if created:
        print_tokens()


def update_secret_facade(targets):
    global vault_data
    
    try:
        if kps_file != '': 
            get_token_input_method(targets)
        else:
            insert_vault_tokens(targets)

        try:
            for environment_name, environment_data in vault_data.items():
                if environment_data['use']:
                    secret_name = input('Informe o nome da secret:')
                    print(clear)

                    secret = read_secret(environment_name, secret_name)                
                    print_formatted_secret_data(environment_name, secret_name, secret['data'])
                    policy_data = policy_read(environment_name, secret_name + '-policy')
                    print_formatted_policy_data(secret_name + '-policy', policy_data)
                    
                    changes = dict()
                    redo = True

                    print("""\n==================================================================
    Informe o tipo de atualização a ser realizado:

        Digite 1 para atualizar um campo
        Digite 2 para atualizar as policies
        Digite 3 para remover um campo
                    """)
                    opt = get_option(1,4)

                    client = hvac.Client(
                        url= vault_data[environment_name]['url'],
                        token=vault_data[environment_name]['token']
                    )

                    if opt == 1:
                        print("""\n\n============================================================================================================
    Durante a atualização das chaves e valores, tanto o nome quanto o valor do campo podem ser sobrescritos
    Para inserir um par novo, informe o nome de um campo não existente na secret
=============================================================================================================\n\n""")

                        while redo:
                            old_field_name = input('Informe o nome do campo a ser atualizado:')
                            
                            if old_field_name in secret['data']:
                                if get_yes_or_no('\nDeseja alterar o nome do campo?', 'n'):
                                    new_field_name = input('\nInforme o nome novo para o campo:')
                                else:
                                    new_field_name = old_field_name

                            new_field_value = input('\nInforme o valor novo do campo:')

                            if get_yes_or_no('\nConfirmar atualização?'):
                                changes[old_field_name] = { 'new_name': new_field_name, 'new_value': new_field_value}
                            
                            redo = get_yes_or_no('\nDeseja atualizar mais alguma chave?','n')

                        for old_key, key_pair in changes.items():
                            print('[DEBUG] - Iterando em ', old_key) if debug_mode else 0
                            if old_key in secret['data']:
                                if old_key == key_pair['new_name']:
                                    secret['data'][old_key] = key_pair['new_value']
                                else:
                                    secret['data'].pop(old_key, None)
                                    secret['data'][key_pair['new_name']] = key_pair['new_value']
                            else:
                                secret['data'][key_pair['new_name']] = key_pair['new_value']
                        
                        environment_data['secret_data'] = secret['data']
                        print('[DEBUG] - DADOS DA ATUALIZAÇÃO') if debug_mode else 0
                        print(environment_data['secret_data']) if debug_mode else 0

                        write_secret(environment_data, 'secret/' + secret['name'], client)

                    elif opt == 2:
                        policies = get_policies()
                        policy_write(vault_data[environment_name], secret_name, client, policies)
                    
                    elif opt == 3:
                        field_name = input('Informe o nome do campo a ser removido:')
                        if get_yes_or_no('O campo ' + field_name + ' (' + secret['data'][field_name]  + ') será removido.\nConfirmar?' ):
                            if field_name in secret['data']:
                                secret['data'].pop(field_name, None)
                                environment_data['secret_data'] = secret['data']
                                write_secret(environment_data, 'secret/' + secret['name'], client)
                            else:
                                print('A chave informada não está presente na secret')

                    print('\n[INFO] - Atualização da secret concluída!\n')

                    secret = read_secret(environment_name, secret_name)
                    print_formatted_secret_data(environment_name, secret_name, secret['data'])

                    policy_rules = policy_read(environment_name, secret_name + '-policy')
                    print_formatted_policy_data(secret_name + '-policy', policy_rules)

        except Exception as err:
            print('Falha ao executar comando no Vault:', err)
            pass
    except Exception:
        print('[ERRO] - Não foi possível realizar a atualização da secret')
        pass


def list_secret_facade(targets):
    global vault_data
    global kps_file

    try:
        if kps_file != '': 
            get_token_input_method(targets)
        else:
            insert_vault_tokens(targets)
                
        try:
            print(""""""+clear+"""\n=======================================================================
                    Resultado da listagem de secrets """)
            
            for environment_name, environment_data in vault_data.items():
                if environment_data['use']:
                    client = hvac.Client(
                        url= vault_data[environment_name]['url'],
                        token=vault_data[environment_name]['token']
                    )
                    print("\n[" + environment_name + "]\n")
                    for secret in client.list('secret/')['data']['keys']:
                        try:
                            print(secret)
                        except Exception:
                            print('Dados não encontrados...')
                    
                    if get_yes_or_no('\nDeseja visualizar detalhes de alguma secret de ' + environment_name + '?', 'n'):
                        secret_name = input('Informe o nome da secret:')

                        secret = read_secret(environment_name, secret_name)
                        print_formatted_secret_data(environment_name, secret_name, secret['data'])

                        print("\n\nPressione alguma tecla para continuar...")
                        getpass.getpass(' ')
                        print(clear)

        except Exception as err:
            print('Falha ao executar comando no Vault:', err)

    except Exception:
        print('[ERRO] - Não foi possível realizar a listagem das secrets')
        pass


######### VAULT API OPERATIONS #########

def read_secret(environment_name, secret_name):
    client = hvac.Client(
                url= vault_data[environment_name]['url'],
                token=vault_data[environment_name]['token']
            )
            
    try:
        data = client.read('secret/'+secret_name)['data']
        return {'name': secret_name, 'data' : data}

    except Exception:
        print('\n[INFO] - A secret informada não foi encontrada no ambiente de ' + environment_name)
        pass


def write_secret(post_data, post_secret_name, client):
    url = post_data['url'] + '/v1/'  + post_secret_name
    payload = json.dumps(post_data['secret_data'], ensure_ascii=False)
    print('[DEBUG] - PAYLOAD DUMP') if debug_mode else 0
    print(payload) if debug_mode else 0

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': post_data['token'] }

    try:
        response = requests.post(url, data=payload, headers=headers)
        if verbose_mode:
            print('[+INFO] ', response) 
            print('[+INFO] ', response.json() )
        
        return True

    except Exception as e:
        if debug_mode:
            print('\n[DEBUG] - PAYLOAD')
            print(payload)

        print('[ERROR] - Erro ao enviar request para o vault: ' + str(e))
        pass


def policy_write(post_data, post_secret_name, client, policies):
    policy_name = post_secret_name.replace('secret/','') + '-policy'

    policy = ""

    for pol in policies:
        if policies.index(pol) != 0 :
            policy += ','
        if pol == 'read':
            policy += """
path \"""" + post_secret_name + """\" {
    policy = "read"
}"""
        elif pol == 'aws-dynamo':
            policy += """
path "aws/sts/""" + aws_dynamo_role + """\" {
    capabilities = [
        "update"
    ]
}"""
        elif pol == 'aws-s3':
            policy += """
path "aws/sts/""" + aws_s3_role + """\" {
    capabilities = [
        "update"
    ]
}"""
         
    try:
        client.sys.create_or_update_policy(
            name=policy_name,
            policy=policy,
        )

        print('[+INFO] Policy gerada') if verbose_mode else 0
        return True

    except Exception as e:
        print('[ERROR] - Erro ao enviar request para o vault: ' + e)
        

def policy_read(environment_name, policy_name):
    try:
        client = hvac.Client(url= vault_data[environment_name]['url'],
                            token=vault_data[environment_name]['token'])

        policy_rules = client.sys.read_policy(name=policy_name)['data']['rules']
        return policy_rules

    except Exception as e:
        print('[INFO] - Não foi encontrada nenhuma policy para esta secret: ' + e)
        pass


def policy_list(environment_name):
    try:
        client = hvac.Client(url= vault_data[environment_name]['url'],
                            token=vault_data[environment_name]['token'])

        list_policies_resp = client.sys.list_policies()['data']['policies']
        return list_policies_resp

    except Exception as e:
        print('[ERROR] - Erro ao enviar request para o vault: ' + e)
        pass


def policy_delete(environment_name, policy_name):
    try:
        client = hvac.Client(url= vault_data[environment_name]['url'],
                            token=vault_data[environment_name]['token'])

        client.sys.delete_policy(name=policy_name)
        return True

    except Exception as e:
        print('[ERROR] - Erro ao enviar request para o vault: ' + e)
        pass


def token_create(post_data, post_secret_name, client):
    policy_name = post_secret_name.replace('secret/','') + '-policy'
    token_name = post_secret_name.replace('secret/','') + '-token'

    url = post_data['url'] + '/v1/auth/token/create'
    
    payload = json.dumps({
        "policies": [
            policy_name
        ],
        "ttl": "43800h",
        "renewable": True,
        "display_name" : token_name
    }, ensure_ascii=False) 

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': post_data['token'] }

    try:
        response = requests.post(url, data=payload, headers=headers)
        post_data['client_token'] = response.json()['auth']['client_token']

        if verbose_mode:
            print('[+INFO] Token gerado ', response )
            print('[+INFO] ', response.json() ) 

        return True
        
    except Exception as e:
        print('[ERROR] - Erro ao enviar request para o vault: ' + str(e))


####### PRINTING FUNCTIONS ########

def print_env_pick_menu(headline):
    i=2
      
    print("""\
"""+clear+"""
"""+headline+"""
        Digite 1 para todos os ambientes          """)
    for key, val in vault_data.items():
        print("\tDigite " + str(i) + " para " + str(key) + " (somente)")
        i += 1
    
    print("""\tDigite """ + str(i) + """ para retornar ao menu principal
        Digite 0 para sair\n""")
    return i


def print_formatted_secret_data(environment_name, secret_name, data):
    print("""\n====================================================
            Dados da Secret em """ + environment_name + """
====================================================

    Os dados da secret """ + secret_name + """ são:\n""")
    for key, value in data.items():
        print("\t" + key + " : " + value)


def print_formatted_policy_data(policy_name, policy_rules):
    print('\n\n    Regras da policy \'' + policy_name +'\':\n\t' + policy_rules)


def print_tokens():
    print(""""""+clear+"""\n=======================================================================
                Geração de token(s) concluída: """)

    for key, value in vault_data.items():
        if value['use']:
            print('\nToken para ' + key + ': ' + value['client_token'])
    print("\n\nPressione alguma tecla para continuar...")
    getpass.getpass(' ')


####### MENUS ########

def read_secret_menu():
    global kps_file

    try:
        if kps_file != '':  
            get_token_input_method(vault_data.keys())
        else:
            insert_vault_tokens(vault_data.keys())

        secret_name = input('Informe o nome da secret:')
        print(clear)

        for environment_name in vault_data.keys():
            secret = read_secret(environment_name, secret_name)                
            print_formatted_secret_data(environment_name, secret_name, secret['data'])
            policy_data = policy_read(environment_name, secret_name + '-policy')
            print_formatted_policy_data(secret_name + '-policy', policy_data)

    except Exception:
        print('[ERRO] - Não foi possível realizar a leitura da secret')
        pass


def create_secret_menu():
    headline = """
==============================================================
    Informe os ambientes onde as chaves serão criadas:\n"""

    max_opt = print_env_pick_menu(headline)

    opt = get_option(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        create_secret_facade(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        create_secret_facade([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()


def update_secret_menu():
    headline = """
==============================================================
    Informe os ambientes onde as secrets serão atualizadas:\n"""

    max_opt = print_env_pick_menu(headline)
    opt = get_option(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        update_secret_facade(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        update_secret_facade([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()


def list_secret_menu():
    headline = """
==============================================================
    Informe os ambientes que deseja consultar:\n"""

    max_opt = print_env_pick_menu(headline)
    opt = get_option(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        list_secret_facade(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        list_secret_facade([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()

def main_menu(more):

    options = ''

    if not more:
        options = """
           Digite 1 para criar uma nova secret          
           Digite 2 para consultar uma secret
           Digite 3 para atualizar uma secret 
           Digite 4 para listar as secrets 
           Digite 5 para mais opções
           
           Digite 0 para sair"""
    
    else:
        options = """
           Digite 5 para recriar um token
           Digite 6 para revogar um token
           Digite 7 para renovar um token
           Digite 9 para voltar ao menu anterior
           """

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
                                        v 1.0

==========================================================
    
    Selecione a opção desejada:\n""" + options)
    
    min_opt = 0 if not more else 5
    max_opt = 6 if not more else 10
    opt = get_option(min_opt, max_opt)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if not more:
        if opt == 0:
            sys.exit(0)
        elif opt == 1:
            create_secret_menu()
        elif opt == 2:
            read_secret_menu()
        elif opt == 3:
            update_secret_menu()
        elif opt == 4:
            list_secret_menu()
        elif opt == 5:
            print(clear)
            main_menu(not more)

    else:
        if opt == 5:
            print('[WIP] - Recriar token')
        elif opt == 6:
            print('[WIP] - Revogar token')
        elif opt == 7:
            print('[WIP] - Renovar token')
        elif opt == 9:
            print(clear)
            main_menu(not more)

def main():
    initialize_vault_data()
    print(clear)

    global debug_mode
    global verbose_mode

    for arg in sys.argv[1:]:
        if arg == '-d':
            debug_mode = True
        elif arg == '-v':
            verbose_mode = True

    print('\n\n\n*******    EXECUTANDO APLICAÇÃO EM MODO DEBUG    *******') if debug_mode else 0

    main_menu(False)
    
    if get_yes_or_no('\nDeseja continuar a execução?'):
        main()
    else:
        sys.exit(0)
    
if __name__ == '__main__':
    main()