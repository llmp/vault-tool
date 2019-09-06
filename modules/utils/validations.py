#!/usr/bin/env python3

import getpass
import shlex
from sys import stdout
from shlex import quote

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

    return value

def get_option(range_min, range_max):
    while True:
        try:
            option = get_input('Opção: ')
            option = (int(option))
            if option not in range(range_min, range_max):
                raise ValueError('[ERRO]')
            break
        except (ValueError, NameError):
            print("[ERRO] - Informe uma opção válida!")
    return option


def get_yes_or_no(question, default="s"):
    valid = {"sim": True, "s": True, "si": True,
             "nao": False, "n": False, "na": False, "não": False}

    while True:
        if default == "s":
            stdout.write(question + " [S/n] ")
        else:
            stdout.write(question + " [s/N] ")
        choice = quote(input().lower())

        if choice == '\'\'':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            stdout.write("[ERRO] - Por favor responda com 'sim' ou 'nao' "
                             "('s' ou 'n').\n")