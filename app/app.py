import streamlit as st
from streamlit_option_menu import option_menu


class InfraApp:

    def gcd(self, a, b):
        while b != 0:
            a, b = b, a % b
        return a

    def mod_inverse(self, e, phi):
        d = 0
        x1, x2, y1 = 0, 1, 1
        temp_phi = phi
        while e > 0:
            temp1 = temp_phi // e
            temp2 = temp_phi - temp1 * e
            temp_phi, e = e, temp2

            x = x2 - temp1 * x1
            y = d - temp1 * y1

            x2, x1 = x1, x
            d, y1 = y1, y

        if temp_phi == 1:
            return d + phi

    def generate_keys(self, p, q):
        n = p * q
        phi = (p - 1) * (q - 1)

        e = 2
        while e < phi:
            if self.gcd(e, phi) == 1:
                break
            else:
                e += 1

        d = self.mod_inverse(e, phi)
        return (e, n), (d, n)

    def encrypt(self, plaintext, public_key):
        e, n = public_key
        cipher = [(ord(char) ** e) % n for char in plaintext]
        return cipher

    def decrypt(self, ciphertext, private_key):
        d, n = private_key
        plain = [chr((char ** d) % n) for char in ciphertext]
        return ''.join(plain)

    def sidebar(self):
        with st.sidebar:
            st.sidebar.title("Navegação")
            selection = option_menu("Selecione", ["Home", "O que é Infraestrutura Computacional?",
                                    "Redes de computadores, Internet e Web", "Nuvem e acesso remoto e criptografia",
                                                  "Referências"],
                                    icons=['house', 'hdd-stack', 'globe', 'cloud'])

        if selection == "Home":
            st.header("Home")
            st.write("Bem-vindo ao App de Infraestrutura Computacional!")
            st.write("""
            Esta é uma aplicação que tem como objetivo explicar o que é infraestrutura computacional, 
            tanto a parte física (hardware), quanto a parte de software.""")

        elif selection == "O que é Infraestrutura Computacional?":
            st.header("O que é Infraestrutura Computacional?")
            st.write("A infraestrutura computacional é tudo o que você precisa para criar e executar aplicações "
                     "de software em uma organização. Ela inclui hardware, componentes de rede, o sistema operacional, "
                     "armazenamento de dados e vários softwares que uma organização utiliza para fornecer serviços "
                     "computacionais e executar soluções internas de software.\n"
                     "\nTradicionalmente, o gerenciamento da infraestrutura "
                     "computacional era complexo devido aos requisitos "
                     "de compra própria e ao grande investimento inicial. Também havia as complexidades de manutenção e "
                     "upgrades que precisavam ser realizados internamente. "
                     "No entanto, com a computação em nuvem, provedores "
                     "terceirizados podem gerenciar totalmente a maioria dos requisitos de infraestrutura computacional. "
                     "As organizações agora têm a flexibilidade de escolher os componentes de infraestrutura que desejam "
                     "adquirir e os que preferem utilizar como serviço.")
            st.header("Componentes da Infraestrutura Computacional")

            st.subheader("Hardware")
            st.write("Hardware computacional se refere a todas as máquinas e dispositivos físicos que uma organização "
                     "utiliza em seu ambiente computacional. Os dispositivos de armazenamento e os servidores que "
                     "fornecem recursos de rede à empresa fazem parte do hardware computacional. "
                     "Todos os dispositivos de endpoint, como computadores, telefones e tablets, "
                     "também se enquadram nessa categoria.")

            st.subheader("Software")
            st.write("""
            A infraestrutura de software computacional inclui:
            
            - Sistemas Operacionais
            - Middleware
            - Banco de Dados
            - Servidores de Aplicações
            - Gerenciamento de relacionamento com o Cliente
            - Software de planejamento de recursos empresariais
            - Sistemas de gerenciamento de conteúdo
            - Software de Virtualização
                        
            Ela também inclui outros tipos de recursos do sistema que facilitam a troca de dados, 
            hospedam aplicações e, de outras formas, são essenciais para os 
            sistemas computacionais de uma organização.""")

        elif selection == "Redes de computadores, Internet e Web":
            st.header("Redes de computadores, Internet e Web")
            st.write("""
            - **Redes de Computadores**: Consiste em um conjunto de dispositivos conectados entre si, 
            permitindo a troca de informações e recursos entre eles.
            - **Internet**: Uma rede global de redes de computadores que conecta bilhões de dispositivos no mundo todo. 
            Utiliza protocolos padronizados, como o TCP/IP, para garantir que a comunicação aconteça 
            de forma eficiente e segura.
            - **Web**: A World Wide Web é um serviço da Internet que permite o acesso a informações e 
            recursos por meio de hipertextos, acessíveis por navegadores web. É apenas uma parte da Internet, 
            que inclui muitos outros serviços, como email, FTP, etc.
            """)
            st.header("Camadas de redes de computadores - Modelo OSI (Open System Interconnection)")
            st.subheader("1. Camada Física", divider=True)
            st.write("Trata dos aspectos físicos da transmissão de dados, "
                         "como os meios de comunicação (cabos, rádio, fibras ópticas) e os sinais elétricos "
                         "ou ópticos usados para transmitir bits.")

            st.subheader("2. Camada de Enlace de Dados", divider=True)
            st.write("Garante uma transmissão de dados confiável entre dois dispositivos diretamente conectados, "
                     "lidando com erros de transmissão e organizando os dados em quadros (frames).")

            st.subheader("3. Camada de Rede", divider=True)
            st.write("Gerencia o roteamento dos pacotes de dados através da rede, possibilitando a comunicação "
                     "entre dispositivos em diferentes redes. O protocolo mais conhecido nesta "
                     "camada é o IP (Internet Protocol).")

            st.subheader("4. Camada de Transporte", divider=True)
            st.write("Fornece comunicação confiável de ponta a ponta, assegurando que os dados cheguem corretamente "
                     "ao destino, na ordem certa. Protocolos como TCP (Transmission Control Protocol) e "
                     "UDP (User Datagram Protocol) operam nesta camada.")

            st.subheader("5. Camada de Sessão", divider=True)
            st.write("Controla o diálogo entre duas aplicações, gerenciando o estabelecimento, "
                     "manutenção e término de sessões. É responsável por organizar e sincronizar a troca de dados.")

            st.subheader("6. Camada de Apresentação", divider=True)
            st.write("Lida com a tradução de dados entre o formato usado pelas aplicações e o formato de rede, "
                     "incluindo a criptografia e compressão de dados.")

            st.subheader("7. Camada de Aplicação", divider=True)
            st.write("Fornece serviços de rede diretamente aos aplicativos, como o HTTP (utilizado na web), "
                     "FTP (transferência de arquivos), e SMTP (envio de e-mails).")

        elif selection == "Nuvem e acesso remoto e criptografia":
            st.title("Nuvem computacional")
            st.write(" A nuvem computacional (cloud computing) refere-se à entrega de serviços de computação pela "
                     "internet. Esses serviços incluem servidores, armazenamento, bancos de dados, redes, "
                     "software, entre outros, que podem ser acessados sob demanda, sem a necessidade de "
                     "gerenciamento direto pelo usuário. Em vez de depender de servidores locais ou "
                     "dispositivos físicos, as organizações podem utilizar recursos na nuvem para "
                     "maior flexibilidade e escalabilidade.")

            st.title("Acesso Remoto")
            st.write("O acesso remoto é a capacidade de acessar um sistema, servidor ou dispositivo de qualquer "
                     "local geográfico através de uma rede (geralmente a internet). "
                     "Esse tipo de acesso permite que usuários interajam com os recursos do sistema como se "
                     "estivessem fisicamente presentes, facilitando o trabalho remoto e o suporte técnico.")

            st.title("Criptografia")
            st.write("A criptografia é a técnica de codificar informações de modo que apenas aqueles com a chave "
                     "correta possam decifrá-las. Ela garante a confidencialidade e segurança dos dados transmitidos "
                     "ou armazenados, transformando texto legível (texto claro) em um formato ilegível (texto cifrado) "
                     "e, posteriormente, convertendo-o de volta ao formato original com a chave correta.")

            # Seção de Introdução
            st.latex(r'''
            \textbf{O Algoritmo RSA}
            ''')

            st.write("""
            O RSA (Rivest-Shamir-Adleman) é um algoritmo de criptografia assimétrica que utiliza duas chaves: 
            uma chave pública para criptografar e uma chave privada para descriptografar. 
            O algoritmo depende da dificuldade de fatorar grandes números primos.
            """)

            # Seção de Passos do Algoritmo
            st.latex(r'''
            \text{Passos do Algoritmo RSA}:
            ''')

            # Passo 1: Escolha de dois números primos grandes
            st.latex(r'''
            1. \ \text{Escolha de dois números primos grandes: } p \text{ e } q.
            ''')

            # Passo 2: Cálculo de n e φ(n)
            st.latex(r'''
            2. \ \text{Cálculo de } n \text{ e } \phi(n):
            \ n = p \times q
            \ \phi(n) = (p - 1) \times (q - 1)
            ''')

            # Passo 3: Escolha de e
            st.latex(r'''
            3. \ \text{Escolha de } e: \ 1 < e < \phi(n) \text{ e } \text{MDC}(e, \phi(n)) = 1
            ''')

            # Passo 4: Cálculo da chave privada d
            st.latex(r'''
            4. \ \text{Cálculo de } d: \ d \times e \equiv 1 \ (\text{mod} \ \phi(n))
            ''')

            # Passo 5: Criptografia
            st.latex(r'''
            5. \ \text{Criptografia: } C = M^e \ (\text{mod} \ n)
            ''')

            # Passo 6: Descriptografia
            st.latex(r'''
            6. \ \text{Descriptografia: } M = C^d \ (\text{mod} \ n)
            ''')

            st.title("Teste a criptografia RSA!")
            p = st.number_input("Insira um número primo p", min_value=2, value=61)
            q = st.number_input("Insira um número primo q", min_value=2, value=53)

            if p > 1 and q > 1:
                public_key, private_key = self.generate_keys(p, q)
                st.write(f"Chave pública: {public_key}")
                st.write(f"Chave privada: {private_key}")

                message = st.text_input("Digite a mensagem para cifrar")

                if message:
                    encrypted_message = self.encrypt(message, public_key)
                    st.write(f"Mensagem Cifrada: {encrypted_message}")

                    decrypted_message = self.decrypt(encrypted_message, private_key)
                    st.write(f"Mensagem Decifrada: {decrypted_message}")


        elif selection == "Referências":
            st.header("Referências")
            st.markdown(":link: [O que é infraestrutura de TI?](https://aws.amazon.com/pt/what-is/it-infrastructure/)")
            st.markdown(":globe_with_meridians: [Camadas - OSI](https://pt.wikipedia.org/wiki/Modelo_OSI)")


if __name__ == '__main__':
    app = InfraApp()
    app.sidebar()
