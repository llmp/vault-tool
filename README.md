# VAUL TOOL
Autor: Leonardo Molina			       CVC Corp - 2018

Email: leonardomolina@cvc.com.br       Segurança da Informação

Uso
-----
  Este software tem como finalidade prover uma ferramenta para facilitar a criação e gerenciamento de secrets e tokens no cofre do Vault da Hashicorp, bem como serviços administrativos de travamento/destravamento do cofre.
  
  Existe a integração com um recurso opcional de utilização do Keepass para armazenamento e busca das credenciais de acesso ao Vault.
  

Pré-requisitos
-----
1 - Python v.3.x.x

2 - Permissão de acesso ao diretório de rede de Segurança da Informação

3 - Configuração dos parâmetros no arquivo config.yaml


Configurações opcionais
-----
1 - Keepass2

2 - KPScript (compatível com a versão do Keepass e colocado no diretório local onde se encontra instalado o Keepass)


Instalação
-----

1 - Acesse o diretério do projeto vtool e execute o comando de instalação das dependências: 
	pip install -U -r .\config\requirements.txt

2 - Execute o script com o comando: python .\vtool.py


Notas
-----
1 - Os nomes das entradas (entries) no KeePass devem ser iguais aos nomes de ambientes listados no config.yaml 
(a busca é feita com base no nome da chave)
