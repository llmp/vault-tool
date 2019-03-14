# VAUL TOOL

Uso
-----
  Este software tem como finalidade prover uma ferramenta para facilitar a criação e gerenciamento de chaves no cofre do Vault da Hashicorp.

Pré-requisitos
-----
1 - Python v.3.x.x
2 - Keepass
3 - KPScript (compatível com a versão do Keepass)
4 - Permissão de acesso ao diretório de rede de Seguran�a da Informação (\\intra.cvc\fscvc\ti\ti\cvcfs\fs02)

Instalação
-----
1 - Descompacte o .zip do KPScript e mova o conteúdo para o diretório local onde se encontra instalado o Keepass 

2 - Acesse o diretério do projeto vtool e execute o comando de instalação das dependências: 
	pip install -U -r requirements.txt

3 - Execute o script com o comando: python .\vtool.py