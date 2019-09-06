#!/usr/bin/env python3

import requests
import hvac
import json

def read_secret(url, x_vault_token, secret_name):
    client = hvac.Client(url=url, token=x_vault_token)
    try:
        data = client.read('secret/'+secret_name)['data']
        return {'name': secret_name, 'data' : data}

    except Exception as e:
        raise(e)
    

def list_secret(url, x_vault_token):
    try:
        client = hvac.Client(url= url,token=x_vault_token)
        return client.list('secret/')['data']['keys']

    except Exception as e:
        raise(e)


def write_secret(url, x_vault_token, secret_data, secret_name):
    url = url + '/v1/secret/'  + secret_name
    payload = json.dumps(secret_data, ensure_ascii=False)

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }

    try:
        requests.post(url, data=payload, headers=headers)
        return True

    except Exception as e:
        raise(e)


def policy_write(url, x_vault_token, secret_name, policies, aws_s3_role=None,  aws_dynamo_role=None):
    policy_name = secret_name + '-policy'
    
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
path \"secret/""" + secret_name + """\" {
    capabilities = [""" + capabilities_str + """]
}"""

            elif policy_type == 'aws-dynamo' and aws_dynamo_role:
                policy += """
path "aws/sts/""" + aws_dynamo_role + """\" {
    capabilities = [
        "read", "update"
    ]
}"""

            elif policy_type == 'aws-s3' and aws_s3_role:
                policy += """
path "aws/sts/""" + aws_s3_role + """\" {
    capabilities = [
        "read", "update"
    ]
}"""    
            i += 1
    
        client = hvac.Client(url=url, token=x_vault_token)
        client.sys.create_or_update_policy(name=policy_name, policy=policy)
        
        return True

    except Exception as e:
        raise(e)


def policy_read(url, x_vault_token, policy_name):
    try:
        client = hvac.Client(url=url,token=x_vault_token)
        policy_rules = client.sys.read_policy(name=policy_name)['data']['rules']
        return policy_rules

    except Exception as e:
        raise(e)


def policy_list(url, x_vault_token):
    try:
        client = hvac.Client(url=url,token=x_vault_token)
        policies = client.sys.list_policies()['data']['policies']
        return policies

    except Exception as e:
        raise(e)


def policy_delete(url, x_vault_token, policy_name):
    try:
        client = hvac.Client(url=url,token=x_vault_token)
        client.sys.delete_policy(name=policy_name)
        return True

    except Exception as e:
        raise(e)


def token_create(base_url, x_vault_token, secret_name):
    policy_name = secret_name + '-policy'
    token_name = secret_name + '-token'

    url = base_url + '/v1/auth/token/create'
    
    payload = json.dumps({
        "policies": [policy_name],
        "ttl": "43800h",
        "renewable": True,
        "display_name" : token_name
    }, ensure_ascii=False) 

    headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }

    try:
        response = requests.post(url, data=payload, headers=headers)
        new_token = response.json()['auth']['client_token']
        return new_token
        
    except Exception as e:
        raise(e)


def token_revoke(base_url, x_vault_token, client_token):    
    try:
        url = base_url + '/v1/auth/token/revoke'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)
        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            raise Exception('status code %s' % response.status_code)

    except Exception as e:
        raise(e)


def token_lookup(base_url, x_vault_token, client_token):
    try:
        url = base_url + '/v1/auth/token/lookup'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)
        response = requests.post(url, data=payload, headers=headers)
        return response.json()

    except Exception as e:
        raise(e)


def token_renew(base_url, x_vault_token, client_token):
    try:
        url = base_url + '/v1/auth/token/renew'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        payload = json.dumps({"token" : client_token}, ensure_ascii=False)

        response = requests.post(url, data=payload, headers=headers)
        if response.status_code == 200:
            return True
        else:
            raise Exception('status code %s' % response.status_code)

    except Exception as e:
        raise(e)


def vault_operator_status(base_url, x_vault_token):
    try:
        url = base_url + '/v1/sys/seal-status'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        response = requests.get(url, headers=headers)

        return response.json()['sealed']

    except Exception as e:
        raise(e)


def vault_operator_seal(base_url, x_vault_token):
    try:
        url = base_url + '/v1/sys/seal'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        response = requests.put(url, headers=headers)
        if response.status_code == 200:
            return True
        else:
            raise Exception('status code %s' % response.status_code)

    except Exception as e:
        raise(e)


def vault_operator_unseal(base_url,x_vault_token, keys):
    try:
        url = base_url + '/v1/sys/unseal'
        headers = { 'Content-type': 'application/json', 'X-Vault-Token': x_vault_token }
        response = None

        for key in keys:
            payload = json.dumps({"key" : key}, ensure_ascii=False)
            response = requests.put(url, data=payload, headers=headers)

        return response.json()['sealed']

    except Exception as e:
        raise(e)
