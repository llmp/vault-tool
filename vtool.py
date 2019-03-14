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

    print(vault_envs)
    
    secret_name = 'secret/'

    for key, val in vault_envs.items():
        vault_data[key]['url'] = val
        vault_data[key]['client_token'] = ''
        vault_data[key]['secret_data'] = dict()
        vault_data[key]['use'] = False

    print(vault_data)

def print_formatted_secret_data(data):
    print('\n')
    for key, value in data.items():
        print("\t" + key + " : " + value)

def get_vault_tokens(vault_names):
        global kps_file
        kps_passwd = getpass.getpass('\nInforme a senha do KeePass:')
        print("""\n==================================================================
[INFO] - Autenticando e buscando chave(s), aguarde...""")
        
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
                
        print("""[INFO] - Chave(s) de ambiente obtida(s)!
==================================================================
""")

def insert_vault_tokens(vault_names):
    for name in vault_names:
        vault_data[name]['token'] = getpass.getpass('Informe o token do ambiente {}:'.format(name))
        vault_data[name]['use'] = True


######## INPUT OPERATIONS ########

def get_secret_name():
    global secret_name  
    print(""""""+clear+"""# ====================== PASSO 3 =========================== #\n
    Informe o nome da secret a ser criada\n""")
    secret_name += quote(input('Informe o nome da secret: '))
    print('\n[INFO] - O nome da secret a ser criada é: ' + secret_name)
    
def get_policies():
    redo = True
    policies = []
    while redo:
        print("""\
"""+clear+"""# ====================== PASSO 5 =========================== #\n
    Informe uma policy para ser adicionada na criação do token:\n
           Digite 1 para leitura da secret (default)
           Digite 2 para acesso ao S3 (Amazon)
           Digite 3 para acesso ao Dynamo (Amazon)
           Digite 4 para retornar ao menu principal
           Digite 0 para sair

           Policies já adicionadas: """ + ', '.join(policies) + """
""")

        opt = get_numeric(0,5)
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

def create_secret(targets):
    global vault_data
    global secret_name
    
    if kps_file != '': 
        get_token_input_method(targets)
    else:
        insert_vault_tokens(targets)

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
            
            print_formatted_secret_data(vault_data[environment_name]['secret_data'])

            if get_yes_or_no('\n\nOs dados estão corretos?'):
                post_secret(vault_data[environment_name], secret_name, client)
                policies = get_policies()
                post_policy(vault_data[environment_name], secret_name, client, policies)
                generate_token(vault_data[environment_name], secret_name, client)
                created = True  
            else:
                print('\n[INFO] - OPERAÇÃO INTERROMPIDA PELO USUÁRIO!') if verbose_mode else 0
            client.adapter.close()
        
    if created:
        print_tokens()

def update_secret(targets):
    global vault_data
    
    if kps_file != '': 
        get_token_input_method(targets)
    else:
        insert_vault_tokens(targets)

    try:
        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                secret_name = input('Informe o nome da secret:')
                secret = get_secret_details(environment_name, secret_name)
                print("""\n\n==================================================================================================================
    Durante a atualização dos pares (chave e valor) tanto o nome quanto o valor do campo poderão ser sobrescritos\n
    Para inserir um par (chave e valor) novo, informe o nome de um campo não existente na secret
==================================================================================================================\n\n""")

                changes = dict()
                redo = True
                while redo:
                    old_field_name = input('Informe o nome do campo a ser atualizado:')

                    if get_yes_or_no('\nDeseja alterar o nome do campo?', 'n'):
                        new_field_name = input('\nInforme o nome novo para o campo:')
                    else:
                        new_field_name = old_field_name

                    new_field_value = input('\nInforme o valor novo do campo:')

                    if get_yes_or_no('\nConfirmar atualização do campo?'):
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

                client = hvac.Client(
                    url= vault_data[environment_name]['url'],
                    token=vault_data[environment_name]['token']
                )

                post_secret(environment_data, 'secret/' + secret['name'], client)
                get_secret_details(environment_name, secret_name)
                print('\n[INFO] - Atualização da secret concluída com sucesso!\n')
    except Exception as err:
        print('Falha ao executar comando no Vault:', err)
                

def list_secret(targets):
    global vault_data
    global kps_file

    if kps_file != '': 
        get_token_input_method(targets)
    else:
        insert_vault_tokens(targets)

    try:
        print(""""""+clear+"""\n=======================================================================
                Listagem de secrets concluída """)
        
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

                    get_secret_details(environment_name, secret_name)
                    print("\n\nPressione alguma tecla para continuar...")
                    getpass.getpass(' ')
                    print(clear)
    except Exception as err:
        print('Falha ao executar comando no Vault:', err)

def get_secret_details(environment_name, secret_name):
    client = hvac.Client(
                url= vault_data[environment_name]['url'],
                token=vault_data[environment_name]['token']
            )
            
    try:
        data = client.read('secret/'+secret_name)['data']
        print(""""""+clear+"""====================================================
                Dados da Secret
====================================================

    Os dados da secret """ + secret_name + """ são:""")
        print_formatted_secret_data(data)
        return {'name': secret_name, 'data' : data}
    except Exception as err:
        print('[ERRO] - Não foi possível realizar a consulta')
        raise err


def get_keys(environment_name):
    i = 1
    secret_keys_pairs = {}
    
    print(""""""+clear+"""# ====================== PASSO 4 =========================== #\n
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


def get_numeric(range_min, range_max):
    while True:
        try:
            res = int(input('Opção: '))
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
# =========================== PASSO 2 ================================ #\n
É necessário o token do ambiente no Vault para realizar esta operação\n
    Digite 1 para buscar o token no KeePass
    Digite 2 para inserir o token manualmente\n""")

        opt = get_numeric(1,3)
        if opt == 1:
            get_vault_tokens(vault_names)
        elif opt == 2:
            insert_vault_tokens(vault_names)


######### VAULT API OPERATIONS #########

def post_secret(post_data, post_secret_name, client):
    url = post_data['url'] + '/v1/'  + post_secret_name
    payload = json.dumps(post_data['secret_data'], ensure_ascii=False)
    print('[DEBUG] - PAYLOAD DUMP') if debug_mode else 0
    print(payload) if debug_mode else 0

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': post_data['token'] }

    try:
        response = requests.post(url, data=payload, headers=headers)
        print('[+INFO] ', response) if verbose_mode else 0
        print('[+INFO] ', response.json() ) if verbose_mode else 0
    except Exception as e:
        print('[DEBUG] - REQUEST DUMP') if debug_mode else 0
        print('\n[DEBUG] - PAYLOAD') if debug_mode else 0
        print(payload) if debug_mode else 0
        print('[ERROR] - Erro ao enviar request para o vault: ' + str(e))

def post_policy(post_data, post_secret_name, client, policies):
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
    except Exception as e:
        print(e)
    print('[+INFO] Policy gerada') if verbose_mode else 0

def generate_token(post_data, post_secret_name, client):
    policy_name = post_secret_name.replace('secret/','') + '-policy'
    token_name = post_secret_name.replace('secret/','') + '-token'

    url = post_data['url'] + '/v1/auth/token/create'
    
    payload = json.dumps({
        "policies": [
            policy_name
        ],
        "ttl": "8760h",
        "renewable": True,
        "display_name" : token_name
    }, ensure_ascii=False) 

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': post_data['token'] }

    try:
        response = requests.post(url, data=payload, headers=headers)
        print('[+INFO] Token gerado ', response ) if verbose_mode else 0
        print('[+INFO] ', response.json() ) if verbose_mode else 0
        post_data['client_token'] = response.json()['auth']['client_token']

    except Exception as e:
        print('[ERROR] - Erro ao enviar request para o vault: ' + str(e))


####### DRAWING MENUS ########

def print_tokens():
    print(""""""+clear+"""\n=======================================================================
                Geração de token(s) concluída: """)

    for key, value in vault_data.items():
        if value['use']:
            print('\nToken para ' + key + ': ' + value['client_token'])
    print("\n\nPressione alguma tecla para continuar...")
    getpass.getpass(' ')

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

def create_secret_menu():
    headline = """
# ====================== PASSO 1 =========================== #
    Informe os ambientes onde as chaves serão criadas:\n"""

    max_opt = print_env_pick_menu(headline)

    opt = get_numeric(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        create_secret(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        create_secret([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()

def update_secret_menu():
    headline = """
# ====================== PASSO 1 =========================== #
    Informe os ambientes onde as secrets serão atualizadas:\n"""

    max_opt = print_env_pick_menu(headline)
    opt = get_numeric(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        update_secret(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        update_secret([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()


def list_secret_menu():
    headline = """
# ====================== PASSO 1 =========================== #
    Informe os ambientes que deseja consultar:\n"""

    max_opt = print_env_pick_menu(headline)
    opt = get_numeric(0, max_opt + 1)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        list_secret(vault_data.keys())
    elif opt >= 2 and opt < max_opt:
        list_secret([list(vault_data.keys())[opt-2]])
    elif opt == max_opt:
        main()

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

    if debug_mode:
        print('\n\n\n*******    EXECUTANDO APLICAÇÃO EM MODO DEBUG    *******')

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
    Selecione a opção desejada:\n
           Digite 1 para criar uma nova secret          
           Digite 2 para atualizar uma secret 
           Digite 3 para listar as secrets
           Digite 0 para sair """)

    opt = get_numeric(0,4)
    
    print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
    if opt == 0:
        sys.exit(0)
    elif opt == 1:
        create_secret_menu()
    elif opt == 2:
        update_secret_menu()
    elif opt == 3:
        list_secret_menu()
    
    if get_yes_or_no('\nDeseja continuar a execução?'):
        main()
    else:
        sys.exit(0)
    
if __name__ == '__main__':
    main()