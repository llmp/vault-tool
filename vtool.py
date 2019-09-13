#!/usr/bin/env python3

"""
    Autor: Leonardo Molina
    Script: Ferramenta de criação e gerenciamento de tokens no Vault
"""

from __future__ import print_function
from pykeepass import PyKeePass 
from datetime import datetime
from datetime import timedelta
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
yaml_params = yaml.load(open('.\\config\\config.yaml', 'r', encoding="utf-8"), Loader=yaml.SafeLoader)

kps_file = yaml_params['kps_path']
kps_writeback_group = yaml_params['kps_writeback_group']
kps_writeback_history_group = yaml_params['kps_writeback_history_group']

vault_envs = yaml_params['vault_envs']
vault_key_quorum = yaml_params['vault_key_quorum']

aws_s3_role = yaml_params['aws_s3_role']
aws_dynamo_role = yaml_params['aws_dynamo_role']

vault_data = { }
debug_mode = False
verbose_mode = False

for key, val in vault_envs.items():
    vault_data.update({ key : {'url' : val, 'client_token' : '', 'secret_data' : dict(), 'use' : False, 'token' : '' } })
clear = "\n" * 100


################ INITIALIZATION OPERATIONS ################

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


def clear_cache():
    initialize_vault_data()
    main()


def read_keepass_data(entry_name, field_name, kps_passwd=''):
    try:
        if kps_passwd == '':
            kps_passwd = get_input('\nInforme a senha do KeePass (input estará ocultado):', hidden=True)
        print(clear + '[INFO] - Buscando dados de %s, aguarde...' % entry_name)
        kp = PyKeePass(kps_file, password=kps_passwd)
        entry = kp.find_entries(title=entry_name, first=True)
        field_data = entry._get_string_field(field_name)
        
        return field_data
    except Exception as e:
        print('[ERRO] - Erro ao ler o Keepass:\n%s \n\nVerifique a senha informada e tente novamente' % (str(e)), file=sys.stderr)
        read_keepass_data(entry_name, field_name, '')
        

def write_token_data(entry_name, kps_group, token_data, kps_pswd, history_group=None):
    try:
        kp = PyKeePass(kps_file, password=kps_pswd)
        entry = kp.find_entries(title=entry_name, first=True)
        
        if entry is not None:
            notes = entry._get_string_field('Notes')
            updated_notes = ''
            current_envs = dict()

            for env in notes.split('\n'):
                try:
                    splitted = env.split(':')    
                    current_envs.update({splitted[0]: splitted[1]})
                except:
                    pass


            for updated_environment in token_data.keys():
                if history_group:
                    if updated_environment == history_group:
                        entry.notes = updated_notes
                        entry.expiry_time = datetime.now() + timedelta(days=365)
                        entry.expires = True

                else:
                    entry.notes = updated_notes
                    entry.expiry_time = datetime.now() + timedelta(days=365)
                    entry.expires = True


            for current_env_name, current_env_token in current_envs.items():
                if current_env_name not in token_data.keys():
                    token_data.update({ current_env_name : current_env_token })

               
            for env_name, env_token in token_data.items():
                updated_notes += env_name + ': ' + env_token + '\n'

        else:
            group = kp.find_groups(name=kps_group, first=True)
            entry = kp.add_entry(group, entry_name, '', '')
            notes = ''

            for env_name, env_token in token_data.items():
                notes += env_name + ': ' + env_token + '\n'

            entry.notes = notes
            entry.expiry_time = datetime.now() + timedelta(days=365)
            entry.expires = True
        
        kp.save()
        
        return True

    except Exception as e:
        print('[ERRO] - Erro ao gravar dados no Keepass %s:\n%s' % (kps_file, str(e)), file=sys.stderr)
        pass


def get_secret_name():
    global secret_name
    secret_name += get_input(clear + 'Informe o nome da secret:')
    print('\n[INFO] - O nome da secret é: ' + secret_name)


def get_policies():
    redo = True
    policies = dict()
    
    while redo:
        print("""\
"""+clear+"""==============================================================\n
    Informe uma policy para ser adicionada ao token:\n
           Digite 1 para acesso à secret (default)
           Digite 2 para acesso ao S3 (Amazon)
           Digite 3 para acesso ao Dynamo (Amazon)
           Digite 4 para retornar ao menu principal
           Digite 0 para sair

           Policies já adicionadas: """ + ', '.join(list(policies.keys())) + """
""")

        opt = get_option(0,5)

        if opt == 0:
            sys.exit(0)

        elif opt == 1:
            if 'read' in policies.keys():
                print('Essa policy já foi adicionada!')
            else: 
                capabilities = get_capabilities('read')
                policies.update({'read': capabilities })

        elif opt == 2:
            if 'aws-s3' in policies.keys():
                print('Essa policy já foi adicionada!')
            elif aws_s3_role == '':
                print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
            else: 
                capabilities = get_capabilities('aws-s3')
                policies.update({'aws-s3': capabilities  })

        elif opt == 3:
            if 'aws-dynamo' in policies.keys():
                print('Essa policy já foi adicionada!')
            elif aws_dynamo_role == '':
                print('Não existe uma role da aws configurada para essa policy (verifique o arquivo config.yaml)')
            else: 
                capabilities = get_capabilities('aws-dynamo')
                policies.update({'aws-dynamo': capabilities  })

        elif opt == 4:
            redo = False
            main()

        elif opt == 5:
            sys.exit(0)

        if not get_yes_or_no('\n\nDeseja adicionar alguma outra policy?', 'n'):
            redo = False

    return policies


def get_capabilities(policy_type):
    capabilities = []
    if policy_type == 'read':
        if not get_yes_or_no('\nA policy utilizará alguma permissão além da default (leitura da secret)?', 'n'):
            capabilities.append('read')
        else:
            redo = True
            while redo:
                print("""\
"""+clear+"""==============================================================\n
    Informe uma permissão para ser adicionada à policy:\n
           Digite 1 para permissão de leitura (read)
           Digite 2 para permissão de atualização (update)
           Digite 3 para permissão de criação (create)
           Digite 4 para permissão de deleção (delete)
           Digite 5 para permissão de listagem (list)

           Permissões já adicionadas: """ + ', '.join(capabilities) + """
    """)
                opt = get_option(1,6)

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
                        print('Policy adicionada.')

                if not get_yes_or_no('\n\nDeseja adicionar alguma outra permissão à policy?', 'n'):
                    redo = False
    else:
        capabilities.append('update')
    return capabilities

def get_keys(environment_name):
    i = 1
    secret_keys_pairs = {}
    
    print(""""""+clear+"""==============================================================\n
Informe agora os conjuntos de chaves e valores para o ambiente """ + environment_name + """\n""")

    while True:
        
        try:
            key = get_input('Chave ' + str(i) + ': ', False, False)
            if key != '':
                val = get_input('Valor ' + str(i) + ': ')
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
            res = get_input('Opção: ')
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


def get_vault_tokens(opt, kps_pwsd=''):
    vault_names = vault_data.keys() if opt == 1 else [list(vault_data.keys())[opt-2]]
    # Validação de configuração do KeePass
    if kps_file != '':
        if all(vault_data[name]['token'] != '' for name in vault_names):
            for name in vault_names:
                vault_data[name]['use'] = True
            print(clear + "Chaves do(s) ambiente(s) selecionado(s) já carregadas. PASSO 2 concluído, prosseguindo...") 
        
        else:
            print("""\
            """+clear+"""
==================================================================\n
É necessário buscar o token do Vault para realizar esta operação\n
    Digite 1 para buscar o token no KeePass
    Digite 2 para inserir o token manualmente\n""")

            choice = get_option(1,3)
            try:
                if choice == 1:
                    if kps_pwsd == '':
                        kps_pwsd = get_input('\nInforme a senha do KeePass (input estará ocultado):', hidden=True)
                    for name in vault_names:
                        token = read_keepass_data(name, 'Password', kps_pwsd)
                        vault_data[name]['token'] = token
                        vault_data[name]['use'] = True
                elif choice == 2:
                    for name in vault_names:
                        vault_data[name]['token'] = get_input('Informe o token do ambiente {} (input estará ocultado):'.format(name), hidden=True)
                        vault_data[name]['use'] = True
            except Exception as e:
                raise(e)


    # Caso de não configuração do path de arquivo do KeePass
    else:
        try:
            if all(vault_data[name]['token'] != '' for name in vault_names):
                for name in vault_names:
                    vault_data[name]['use'] = True
                print(clear + "Chaves do(s) ambiente(s) selecionado(s) já carregadas. PASSO 2 concluído, prosseguindo...") 

            else:
                for name in vault_names:
                    vault_data[name]['token'] = get_input('Informe o token do ambiente {} (input estará ocultado):'.format(name), hidden=True)
                    vault_data[name]['use'] = True
        except Exception as e:
            raise(e)
    
    return kps_pwsd


def get_input(message, hidden=False, verify_empty=True):
    redo = True
    value = ''
    while redo:
        if hidden:
            value = getpass.getpass(message)
        else:
            value = quote(input(message)).replace('\'','')
        if  not verify_empty or value != '':
            redo = False
        else:
            print('[ERRO] - O valor informado está vazio, tente novamente\n')
            print(value)

    return value

################# FACADE OPERATIONS #################

def create_secret_facade(redo, kps_pswd=''):
    global vault_data
    global secret_name

    try:
        get_secret_name()

        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                
                if not redo:
                    vault_data[environment_name]['secret_data'] = get_keys(environment_name)

                    print("""\n==================================================================
[INFO] - As chaves da """ + secret_name + """ para o """ + environment_name +  """ serão:
""")
                    
                    print_formatted_secret_data(environment_name, secret_name, vault_data[environment_name]['secret_data'])

                if get_yes_or_no('\n\nConfirmar a execução para o ambiente %s?' % environment_name):
                    if not redo:
                        write_secret(vault_data[environment_name], secret_name)
                        policies = get_policies()
                        policy_write(vault_data[environment_name], secret_name, policies)
                    token_create(vault_data[environment_name], secret_name)
                else:
                    print('\n[INFO] - OPERAÇÃO INTERROMPIDA PELO USUÁRIO!') if verbose_mode else 0

        print_tokens()
        if kps_writeback_group is not None and kps_writeback_group != '':
            
            if get_yes_or_no('Deseja salvar os dados gerados no Keepass?','s'):
                
                if kps_pswd == '':
                    kps_pswd = get_input('\nInforme a senha do KeePass (input estará ocultado):', hidden=True)
                tokens = dict()
                token_entry = secret_name.replace('secret/','')

                for environment_name, environment_data in vault_data.items():
                    if environment_data['use']:
                        tokens.update({environment_name : environment_data['client_token']})

                print('Gravando dados para %s, aguarde...' % token_entry)
                try:
                    write_token_data(token_entry, kps_writeback_group, tokens, kps_pswd, kps_writeback_history_group)
                    print('\n[INFO] - Dados para %s gravados com sucesso' % token_entry)
                except Exception as e:
                    print('Erro na gravação dos dados de %s : %s' % (token_entry, str(e)) )
    
    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar a operação: %s' % str(e))        


def update_secret_facade():
    global vault_data
    try:
        secret_name = get_input(clear + 'Informe o nome da secret:')
        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                print(clear)
                secret = read_secret(environment_name, secret_name)                
                print_formatted_secret_data(environment_name, secret_name, secret['data'])
                policy_data = policy_read(vault_data[environment_name]['url'], vault_data[environment_name]['token'], secret_name + '-policy')
                print_formatted_policy_data(secret_name + '-policy', policy_data)
                
                changes = dict()
                redo = True

                print("""\n==================================================================
    Informe o tipo de atualização a ser realizado:

        Digite 1 para atualizar um campo
        Digite 2 para atualizar as policies
        Digite 3 para remover um campo

        Digite 4 para retornar ao menu principal
                    """)

                opt = get_option(1,5)
                
                if opt == 4:
                    main()
                elif opt == 1:
                    print("""\n\n============================================================================================================
    Durante a atualização das chaves e valores, tanto o nome quanto o valor do campo podem ser sobrescritos
    Para inserir um par novo, informe o nome de um campo não existente na secret
=============================================================================================================\n\n""")

                    new_field_name = ''
                    
                    while redo:
                        old_field_name = get_input('Informe o nome do campo a ser atualizado:')
                        
                        if old_field_name in secret['data'] and get_yes_or_no('\nDeseja alterar o nome do campo?', 'n'):    
                            new_field_name = get_input('\nInforme o nome novo para o campo:')
                        else:
                            new_field_name = old_field_name
                            
                        new_field_value = get_input('\nInforme o valor novo do campo:')
                        if get_yes_or_no('\nConfirmar atualização?'):
                            changes[old_field_name] = { 'new_name': new_field_name, 'new_value': new_field_value}
                        else:
                            break
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
                    
                    if debug_mode:
                        print('[DEBUG] - DADOS DA ATUALIZAÇÃO')
                        print(environment_data['secret_data'])

                    write_secret(environment_data, 'secret/' + secret['name'])

                elif opt == 2:
                    policies = get_policies()
                    policy_write(vault_data[environment_name], 'secret/' + secret_name, policies)
                
                elif opt == 3:
                    field_name = get_input('Informe o nome do campo a ser removido:')
                    if get_yes_or_no('O campo ' + field_name + ' (' + secret['data'][field_name]  + ') será removido.\nConfirmar?' ):
                        if field_name in secret['data']:
                            secret['data'].pop(field_name, None)
                            environment_data['secret_data'] = secret['data']
                            write_secret(environment_data, 'secret/' + secret['name'])
                        else:
                            print('[INFO] - A chave informada não está presente na secret')
                print("""\n====================================================
              DADOS DA SECRET""")
                secret = read_secret(environment_name, secret_name)
                print_formatted_secret_data(environment_name, secret_name, secret['data'])
                policy_rules = policy_read(vault_data[environment_name]['url'],vault_data[environment_name]['token'], secret_name + '-policy')
                print_formatted_policy_data(secret_name + '-policy', policy_rules)
                getpass.getpass('\n\nPressione alguma tecla para continuar...')

    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar a operação: %s' % str(e))


def list_secret_facade():
    global vault_data
    
    try:
        print(""""""+clear+"""\n=======================================================================
                Resultado da listagem de secrets """)
        
        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                print("\n[" + environment_name + "]\n")
                for secret in list_secret(environment_name):
                    try:
                        print(secret)
                    except Exception:
                        print('Dados não encontrados...')
                
                if get_yes_or_no('\nDeseja visualizar detalhes de alguma secret de ' + environment_name + '?', 'n'):
                    secret_name = get_input(clear + 'Informe o nome da secret:')
                    secret = read_secret(environment_name, secret_name)
                    print_formatted_secret_data(environment_name, secret_name, secret['data'])
                    getpass.getpass('\n\nPressione alguma tecla para continuar...')
                    print(clear)
    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar a operação: %s' % str(e))


def revoke_token_facade():
    global vault_data
    
    try:
        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                client_token = get_input('Informe o token:')
                if client_token != '':
                    token_revoke(environment_name, client_token)
                    print('[INFO] - Token ' + client_token + ' revogado no ambiente ' + environment_name)
    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar a operação: %s' % str(e))


def renew_token_facade():
    global vault_data
    try:
        for environment_name, environment_data in vault_data.items():
            if environment_data['use']:
                client_token = get_input('Informe o token:')
                if client_token != '':
                    token_renew(environment_name, client_token)
                    print(clear + '[INFO] - Token ' + client_token + ' renovado no ambiente ' + environment_name)
    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar a operação: %s' % str(e))


def vault_operator_facade():
    try:
        print("""\
    """+clear+"""
==========================================================

    Qual operação deseja executar?

        Digite 1 para consultar o status do vault
        Digite 2 para destrancar o vault
        Digite 3 para trancar o vault         
        Digite 4 para retornar ao menu inicial

        Digite 0 para sair
    """)
        opt = get_option(0,5)

        if opt == 0:
            sys.exit(0)
        elif opt == 4:
            main()
        else:
            print(clear)
            for environment_name, environment_data in vault_data.items():
                if environment_data['use']:
                    if opt == 1:
                         
                        status = 'Trancado' if vault_operator_status(environment_name) else 'Destrancado'
                        print('\nStatus do vault no ambiente ' + environment_name + ': ' + status)
                    elif opt == 2:
                        print(clear + "Para executar essa ação é necessário usar um conjunto de unseal keys.")

                        unseal_keys = []
                        quorum = vault_key_quorum if vault_key_quorum != None else 5
                        i = 0

                        if kps_file != '':
                            print("""
    Digite 1 para buscar no KeePass
    Digite 2 para inserir manualmente

    Digite 3 para voltar ao menu principal
                    """)
                            input_type = get_option(1,4)
                            print(clear)
                            if input_type == 1:
                                unseal_keys = str(read_keepass_data(environment_name, 'Notes')).split('\n')
                                
                            elif input_type == 2:
                                for key_num in range(i,quorum):
                                    key = get_input('Informe a unseal key de número {} (input estará ocultado):'.format(key_num+1), True)
                                    unseal_keys.append(key)
                                    i += 1

                        else:
                            for key_num in range(i,quorum):
                                key = get_input('Informe a unseal key de número {} (input estará ocultado):'.format(key_num+1), True)
                                unseal_keys.append(key)
                                i += 1
                                
                        print(clear + '[INFO] - Iniciando operação de destravamento. Aguarde...')

                        response = vault_operator_unseal(environment_name, unseal_keys)
                        status = 'Trancado' if response else 'Destrancado'
                        print('\n[INFO] - O status do vault no ambiente '  + environment_name + ' é sealed= ' + status)

                    elif opt == 3:
                        response = vault_operator_seal(environment_name)
                        status = 'Trancado' if response else 'Destrancado'
                        print('\n[INFO] - O status do vault no ambiente '  + environment_name + ' é sealed= ' + status)

            
    except Exception as e:
        print('[ERRO] - Uma falha ocorreu ao realizar operação: %s' % str(e))


################# VAULT API OPERATIONS #################

def read_secret(environment_name, secret_name):
    client = hvac.Client(
                url= vault_data[environment_name]['url'],
                token=vault_data[environment_name]['token']
            )
            
    try:
        data = client.read('secret/'+secret_name)['data']

        return {'name': secret_name, 'data' : data}

    except Exception as e:
        raise(e)
    

def list_secret(environment_name):
    try:
        client = hvac.Client(
                    url= vault_data[environment_name]['url'],
                    token=vault_data[environment_name]['token']
                )

        return client.list('secret/')['data']['keys']

    except Exception as e:
        raise(e)


def write_secret(post_data, post_secret_name):
    url = post_data['url'] + '/v1/'  + post_secret_name
    payload = json.dumps(post_data['secret_data'], ensure_ascii=False)

    if debug_mode:
        print('[DEBUG] - PAYLOAD DUMP')
        print(payload)

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': post_data['token'] }

    try:
        response = requests.post(url, data=payload, headers=headers)
        if verbose_mode:
            print('[+INFO] ', response) 
            print('[+INFO] ', response.json())

        return True

    except Exception as e:
        if debug_mode:
            print('\n[DEBUG] - PAYLOAD')
            print(payload)

        raise(e)


def policy_write(post_data, post_secret_name, policies):
    policy_name = post_secret_name.replace('secret/','') + '-policy'
    
    policy = ""
    i = 0
    try:
        for policy_type, capabilities in policies.items():
            if  i != 0 :
                policy += '\n'

            capabilities_str = ''

            j = 0
            for index in range(j,len(capabilities)):
                capabilities_str += '\"' + capabilities[index] + '\"'
                if j != (len(capabilities) - 1):
                    capabilities_str += ','
                j += 1

            if policy_type == 'read':
                policy += """
path \"""" + post_secret_name + """\" {
    capabilities = [""" + capabilities_str + """]
}"""

            elif policy_type == 'aws-dynamo':
                policy += """
path "aws/sts/""" + aws_dynamo_role + """\" {
    capabilities = [
        "read", "update"
    ]
}"""

            elif policy_type == 'aws-s3':
                policy += """
path "aws/sts/""" + aws_s3_role + """\" {
    capabilities = [
        "read", "update"
    ]
}"""    
            i += 1
    
        client = hvac.Client(url=post_data['url'],
                            token=post_data['token'])

        client.sys.create_or_update_policy(
            name=policy_name,
            policy=policy,
        )
        
        print('[+INFO] Policy gerada') if verbose_mode else 0

        return True

    except Exception as e:
        raise(e)


def policy_read(url, token, policy_name):
    try:
        client = hvac.Client(url=url,
                            token=token)
        
        policy_rules = client.sys.read_policy(name=policy_name)['data']['rules']
        return policy_rules

    except Exception as e:
        raise(e)


def policy_list(url, token):
    try:
        client = hvac.Client(url=url,
                            token=token)
        list_policies_resp = client.sys.list_policies()['data']['policies']

        return list_policies_resp

    except Exception as e:
        raise(e)


def policy_delete(environment_name, policy_name):
    try:
        client = hvac.Client(url= vault_data[environment_name]['url'],
                            token=vault_data[environment_name]['token'])
        client.sys.delete_policy(name=policy_name)
        
        return True

    except Exception as e:
        raise(e)


def token_create(post_data, post_secret_name):
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
        raise(e)


def token_revoke(environment_name, client_token):    
    try:
        url = vault_data[environment_name]['url'] + '/v1/auth/token/revoke'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)
        requests.post(url, data=payload, headers=headers)

        return True

    except Exception as e:
        raise(e)


def token_lookup(environment_name, client_token):
    try:
        url = vault_data[environment_name]['url'] + '/v1/auth/token/lookup'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)
        response = requests.post(url, data=payload, headers=headers)

        return response.json()

    except Exception as e:
        raise(e)


def token_renew(environment_name, client_token):
    try:
        url = vault_data[environment_name]['url'] + '/v1/auth/token/renew'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)

        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            print(vault_data[environment_name]['token'])
            raise Exception('status code %s' % response.status_code)

    except Exception as e:
        raise(e)


def vault_operator_status(environment_name):
    try:
        url = vault_data[environment_name]['url'] + '/v1/sys/seal-status'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        response = requests.get(url, headers=headers)

        return response.json()['sealed']

    except Exception as e:
        raise(e)



def vault_operator_seal(environment_name):
    try:
        url = vault_data[environment_name]['url'] + '/v1/sys/seal'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        response = requests.put(url, headers=headers)
        
        return True

    except Exception as e:
        raise(e)


def vault_operator_unseal(environment_name, keys):
    try:
        url = vault_data[environment_name]['url'] + '/v1/sys/unseal'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': vault_data[environment_name]['token'] }
        response = None

        for key in keys:
            payload = json.dumps({"key" : key}, ensure_ascii=False)
            response = requests.put(url, data=payload, headers=headers)

        return response.json()['sealed']

    except Exception as e:
        raise(e)


############### PRINTING FUNCTIONS ################

def print_env_pick_menu():
    i=2
      
    print("""\
"""+clear+"""
==============================================================

    Informe os ambientes onde deseja executar a operação
        Digite 1 para todos os ambientes          """)
    for key in vault_data.keys():
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
    print('\n\n    Permissões da policy \'' + policy_name +'\':\n\t' + policy_rules)


def print_tokens():
    print(""""""+clear+"""\n=======================================================================
                Geração de token(s) concluída: """)

    for key, value in vault_data.items():
        if value['use']:
            print('\nToken para ' + key + ': ' + value['client_token'])
    print("\n\nPressione alguma tecla para continuar...")
    getpass.getpass(' ')


############### MENUS ################
def read_secret_menu():
    global kps_file

    try:
        get_vault_tokens(1)    

        secret_name = get_input(clear + 'Informe o nome da secret:')

        for environment_name in vault_data.keys():
            secret = read_secret(environment_name, secret_name)
            print_formatted_secret_data(environment_name, secret_name, secret['data'])
            policy_data = policy_read(vault_data[environment_name]['url'], vault_data[environment_name]['token'], secret_name + '-policy')
            print_formatted_policy_data(secret_name + '-policy', policy_data)

    except Exception as e:
        print('[ERRO] - Não foi possível realizar a leitura da secret: %s' % str(e))


def create_secret_menu(redo):
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)

    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            kps_pswd = get_vault_tokens(opt)
            create_secret_facade(redo=redo, kps_pswd=kps_pswd)
        except Exception as e:
            print('[ERRO] - Não foi possível criar a secret: %s' % str(e)) 

    elif opt == max_opt:
        main()


def revoke_token_menu():
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)
    
    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            get_vault_tokens(opt)
            revoke_token_facade()
        except Exception as e:
            print('[ERRO] - Não foi possível revogar o token: %s' % str(e))
            
    elif opt == max_opt:
        main()


def renew_token_menu():
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)

    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            get_vault_tokens(opt)
            renew_token_facade()
        except Exception as e:
            print('[ERRO] - Não foi possível renovar o token: %s' % str(e))
            
    elif opt == max_opt:
        main()


def lookup_token_menu():
    try:
        i=1
        
        print("""\
    """+clear+"""
==============================================================

    Informe o ambiente onde deseja executar a operação""")
        for key, val in vault_data.items():
            print("\tDigite " + str(i) + " para " + str(key) + " (somente)")
            i += 1

        print("""\tDigite """ + str(i) + """ para retornar ao menu principal
            Digite 0 para sair\n""")
    
        opt = get_option(0, i + 1)

        if opt == 0:
            sys.exit(0)
        elif opt < i:
            get_vault_tokens(opt+1)
            token =  get_input(clear+'Informe o token que deseja consultar:')
            env = list(vault_data.keys())[opt-1]
            token_data = token_lookup(env,token)
            print('[INFO] - Resultado da operação:\n')

            for key, val in token_data.items():
                if isinstance(val,dict):
                    for inner_key, inner_val in val.items():
                        print('\t' + str(inner_key) + ' : ' + str(inner_val))    
                else:
                    print('\t' + str(key) + ' : ' + str(val))
        elif opt == i:
            main()

    except Exception as e:
        print('[ERRO] - Não foi possível ler os dados do token: %s' % str(e))

def update_secret_menu():
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)

    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            get_vault_tokens(opt)
            update_secret_facade()
        except Exception as e:
            print('[ERRO] - Não foi possível atualizar a secret: %s' % str(e))
            
    elif opt == max_opt:
        main()


def list_secret_menu():
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)
    
    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            get_vault_tokens(opt)
            list_secret_facade()
        except Exception as e:
            print('[ERRO] - Não foi possível listar as secrets: %s' % str(e))
            
    elif opt == max_opt:
        main()


def vault_operator_menu():
    max_opt = print_env_pick_menu()
    opt = get_option(0, max_opt + 1)

    if opt == 0:
        sys.exit(0)
    elif opt < max_opt:
        try:
            get_vault_tokens(opt)
            vault_operator_facade()
        except Exception as e:
            print('[ERRO] - Não foi possível realizar a operação: %s' % str(e))
            
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
           Digite 1 para recriar um token
           Digite 2 para revogar um token
           Digite 3 para renovar um token
           Digite 4 para visualizar dados do token
           Digite 5 para operações administrativas
                      
           Digite 0 para voltar ao menu anterior"""

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
    
    min_opt = 0
    max_opt = 6

    try:
        opt = get_option(min_opt, max_opt)
        
        print('[INFO] - Opção ' + str(opt) + ' selecionada') if verbose_mode else 0
        if not more:
            if opt == 0:
                sys.exit(0)
            elif opt == 1:
                create_secret_menu(redo=False)
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
            if opt == 0:
                print(clear)
                main_menu(not more)
            elif opt == 1:
                create_secret_menu(redo=True)
            elif opt == 2:
                revoke_token_menu()
            elif opt == 3:
                renew_token_menu()
            elif opt == 4:
                lookup_token_menu()
            elif opt == 5:
                vault_operator_menu()
    except:
        print('[DEBUG] - Exceção encontrada, limpando dados da aplicação...') if debug_mode else 0
        initialize_vault_data()
        for env in vault_data.keys():
            vault_data[env]['token'] = ''

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
    
    if  get_yes_or_no('\nDeseja continuar a execução?'):
        main()
    else:
        sys.exit(0)
    
if __name__ == '__main__':
    main()