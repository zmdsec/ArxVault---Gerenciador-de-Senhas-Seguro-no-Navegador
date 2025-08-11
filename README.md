# ArxVault - Gerenciador de Senhas Offline

Bem-vindo ao **ArxVault**, um gerenciador de senhas offline 100% criptografado que coloca você no controle total da sua privacidade. Sem servidores, sem nuvem, sem rastreamento – apenas você e seus dados seguros localmente. Este é um **MVP (Minimum Viable Product)** open-source, ideal para quem busca segurança contra vazamentos ou vigilância governamental.

## Sobre
O ArxVault permite criar, armazenar e gerenciar senhas de forma segura no seu dispositivo, usando criptografia AES-GCM e derivação de chaves PBKDF2. Você pode gerar senhas fortes, auditar suas entradas e fazer backups criptografados. Tudo funciona offline, tornando-o uma alternativa confiável para proteger suas informações pessoais.

## Recursos
- **Criptografia Local**: Dados protegidos com senha mestra, sem envio a servidores.
- **Gerador de Senhas**: Crie senhas seguras e personalizáveis.
- **Auditoria de Senhas**: Identifique senhas fracas, reutilizadas ou antigas.
- **Exportação/Importação**: Faça backups criptografados para segurança extra.
- **Modo Paranóico**: Opção para apagar tudo rapidamente (em desenvolvimento).
- **Interface Simples**: Fácil de usar para iniciantes e personalizável para avançados.

## Instalação
1. **Clone o Repositório**:
   ```bash
   git clone https://github.com/zmdsec/ArxVault---Gerenciador-de-Senhas-Seguro-no-Navegador
   cd arxvault
Rode Localmente:
Use um servidor web local (ex.: Python):
python -m http.server 8080
Acesse em http://localhost:8080 no seu navegador.
Como PWA (Opcional):
Adicione à tela inicial do seu dispositivo após abrir no navegador (disponível em breve).
Uso
Crie um Cofre: Digite uma senha mestra forte (mínimo 12 caracteres, com letras maiúsculas, minúsculas, números e símbolos).
Adicione Entradas: Insira títulos, usuários e senhas.
Gerencie: Edite, exclua ou copie senhas para a área de transferência.
Backups: Exporte o cofre como JSON e guarde em local seguro.
Tutorial Avançado
Verifique o Código: Este é um projeto open-source. Clone o repositório, revise o código em script.js e confirme que não há backdoors. Contribuições são bem-vindas!
Uso Offline: Após instalar, desconecte da internet para máxima privacidade.
Segurança Extra: Use uma senha adicional no export para proteger o backup.
Responsabilidades do Usuário
Este é um aplicativo offline, e você é totalmente responsável por:
Senha Mestra: Escolha uma forte e memorize-a. Sem ela, os dados são irrecuperáveis.
Backups: Faça exportações regulares e armazene em locais seguros (ex.: pendrive criptografado).
Dispositivo: Proteja contra malware ou roubo, pois os dados ficam no seu computador.
Uso por Conta e Risco: Este é um projeto open-source sem suporte oficial ou auditoria formal. Use com cautela e verifique o código!
Licença
Este projeto está sob a Licença MIT. Você pode usá-lo, modificá-lo e distribuí-lo livremente, desde que mantenha o aviso de copyright.
Contribuições
Quer ajudar? Abra issues ou envie pull requests no GitHub. Sugestões para melhorias (ex.: suporte a chaves USB, sincronização P2P) são bem-vindas!
Aviso
ArxVault é um MVP em desenvolvimento. Não garantimos segurança total – use por sua conta e risco. Para máxima proteção, audite o código ou contrate uma auditoria profissional.
Proteja sua privacidade com ArxVault – offline e no seu controle! 🔒