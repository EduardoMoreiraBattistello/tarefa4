import os
import ssl
import OpenSSL
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Função para carregar um certificado a partir de um arquivo
def carregar_certificado(caminho_arquivo):
    with open(caminho_arquivo, 'rb') as file:
        return x509.load_pem_x509_certificate(file.read(), default_backend())

# Função para verificar a cadeia de confiança de um certificado
def verificar_cadeia_confianca(certificado_usuario, caminho_ac_confiaveis):
    try:
        # Carregar o certificado de usuário
        certificado = carregar_certificado(certificado_usuario)
        
        # Lista todos os certificados confiáveis da pasta
        ac_confiaveis = []
        for arquivo in os.listdir(caminho_ac_confiaveis):
            if arquivo.endswith('.crt'):
                caminho_completo = os.path.join(caminho_ac_confiaveis, arquivo)
                ac_confiaveis.append(carregar_certificado(caminho_completo))
        
        # Obter o emissor do certificado do usuário
        emissor = certificado.issuer
        
        # Remontar a cadeia de certificação até a raiz
        cadeia_confiavel = False
        for ac in ac_confiaveis:
            if ac.subject == emissor:
                cadeia_confiavel = True
                print(f"Certificado confia na AC-Raiz: {ac.subject}")
                break

        if not cadeia_confiavel:
            print("Certificado não é confiável.")

    except Exception as e:
        print(f"Erro ao verificar a cadeia de confiança: {str(e)}")

if __name__ == "__main__":
    certificado_usuario = input("Digite o caminho para o certificado digital do usuário (.cer ou .crt): ")
    caminho_ac_confiaveis = input("Digite o caminho para a pasta contendo as Autoridades Certificadoras Raiz confiáveis: ")
    verificar_cadeia_confianca(certificado_usuario, caminho_ac_confiaveis)
