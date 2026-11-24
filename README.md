# KAD Padaria — Servidor Local + Banco PostgreSQL + PDV em Rede

Arquitetura completa estilo KAD para rodar em rede local na padaria (servidor + múltiplos caixas + mesas/comandas + clientes/fiado + fornecedores + financeiro).

## Estrutura de Arquivos
- `schema.sql` — Criação de todas as tabelas no PostgreSQL e 12 mesas iniciais.
- `server.js` — API REST em Node.js + Express com transações (`BEGIN / COMMIT / ROLLBACK`).
- `public/index.html` — Interface completa (PDV com leitor e balança, Mesas, Caixa/Turno, Produtos, Clientes/Fiado, Fornecedores/Financeiro e Relatórios).
- `package.json` e `.env.example` — Dependências e configuração do banco.

## Como rodar no seu PC / Servidor Local
1. Instale o **Node.js (v18+)** e o **PostgreSQL**.
2. Crie um banco chamado `padaria_kad` no PostgreSQL e execute o script `schema.sql`:
   ```bash
   psql -U postgres -c "CREATE DATABASE padaria_kad;"
   psql -U postgres -d padaria_kad -f schema.sql
   ```
3. Copie `.env.example` para `.env` e defina `DB_PASSWORD` (credencial do PostgreSQL) e `ADMIN_PASSWORD` (senha inicial do administrador, mínimo 8 caracteres). O sistema pede a troca da senha inicial no primeiro acesso. Não compartilhe nem versione o arquivo `.env`.
4. Instale as dependências e inicie o servidor:
   ```bash
   npm install
   npm start
   ```
5. Acesse no navegador:
   - No servidor: `http://localhost:3000`
   - Nos outros caixas/tablets da rede Wi-Fi ou cabo da padaria: `http://IP-DO-SERVIDOR:3000` (ex: `http://192.168.1.10:3000`).

## Segurança e operação
- Todas as rotas da API exigem login, exceto `POST /api/login`; sessões expiram após 8 horas e o login limita tentativas inválidas.
- A aplicação atende na rede local. Não exponha a porta 3000 diretamente à internet nem configure encaminhamento de porta no roteador.
- Faça e teste backups regulares do PostgreSQL. No Windows, execute `powershell -ExecutionPolicy Bypass -File .\scripts\backup.ps1`; os arquivos são guardados fora do projeto em `%LOCALAPPDATA%\kad-padaria\backups`. Para automatizar diariamente, agende esse comando no Agendador de Tarefas do Windows. Os backups não são removidos automaticamente.
- O backup deve ser copiado para outro dispositivo/local seguro; uma cópia no mesmo computador não protege contra falha do disco.
