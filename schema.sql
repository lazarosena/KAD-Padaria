-- ====================================================
-- BANCO DE DADOS - SISTEMA KAD PADARIA (POSTGRESQL)
-- ====================================================

CREATE TABLE IF NOT EXISTS config (
  id INT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  nome VARCHAR(120) NOT NULL DEFAULT 'Padaria',
  balanca_cod INT NOT NULL DEFAULT 6,
  balanca_val INT NOT NULL DEFAULT 5,
  balanca_tipo VARCHAR(10) NOT NULL DEFAULT 'peso'
);

CREATE TABLE IF NOT EXISTS usuarios (
  id SERIAL PRIMARY KEY,
  nome VARCHAR(80) NOT NULL,
  usuario VARCHAR(80) UNIQUE NOT NULL,
  senha_hash VARCHAR(255) NOT NULL,
  ativo BOOLEAN NOT NULL DEFAULT TRUE,
  must_change_password BOOLEAN NOT NULL DEFAULT TRUE,
  criado_em TIMESTAMP NOT NULL DEFAULT NOW()
);

ALTER TABLE usuarios
  ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT TRUE;

INSERT INTO config (id, nome, balanca_cod, balanca_val, balanca_tipo)
VALUES (1, 'Padaria Modelo', 6, 5, 'peso')
ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS produtos (
  id SERIAL PRIMARY KEY,
  codigo VARCHAR(30) UNIQUE,
  nome VARCHAR(120) NOT NULL,
  preco NUMERIC(12,2) NOT NULL,
  custo NUMERIC(12,2) NOT NULL DEFAULT 0,
  unidade VARCHAR(5) NOT NULL DEFAULT 'un', -- 'un' ou 'kg'
  estoque NUMERIC(12,3) NOT NULL DEFAULT 0,
  estoque_min NUMERIC(12,3) NOT NULL DEFAULT 0,
  atalho BOOLEAN NOT NULL DEFAULT FALSE,
  ativo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS clientes (
  id SERIAL PRIMARY KEY,
  nome VARCHAR(120) NOT NULL,
  telefone VARCHAR(30),
  limite_fiado NUMERIC(12,2) NOT NULL DEFAULT 0,
  saldo_devedor NUMERIC(12,2) NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS fornecedores (
  id SERIAL PRIMARY KEY,
  nome VARCHAR(120) NOT NULL,
  documento VARCHAR(20),
  telefone VARCHAR(30)
);

CREATE TABLE IF NOT EXISTS caixas (
  id SERIAL PRIMARY KEY,
  terminal VARCHAR(40) NOT NULL DEFAULT 'CAIXA-01',
  operador VARCHAR(80) NOT NULL,
  abertura TIMESTAMP NOT NULL DEFAULT NOW(),
  fechamento TIMESTAMP,
  valor_inicial NUMERIC(12,2) NOT NULL DEFAULT 0,
  valor_esperado NUMERIC(12,2),
  valor_contado NUMERIC(12,2),
  diferenca NUMERIC(12,2),
  aberto BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS mesas (
  id SERIAL PRIMARY KEY,
  numero INT UNIQUE NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'livre', -- 'livre', 'ocupada', 'fechando'
  cliente_id INT REFERENCES clientes(id) ON DELETE SET NULL
);

-- Cria 12 mesas iniciais
INSERT INTO mesas (numero, status)
SELECT g, 'livre' FROM generate_series(1, 12) AS g
ON CONFLICT (numero) DO NOTHING;

CREATE TABLE IF NOT EXISTS comanda_itens (
  id SERIAL PRIMARY KEY,
  mesa_id INT NOT NULL REFERENCES mesas(id) ON DELETE CASCADE,
  produto_id INT NOT NULL REFERENCES produtos(id),
  qtd NUMERIC(12,3) NOT NULL,
  preco_unit NUMERIC(12,2) NOT NULL,
  criado_em TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS vendas (
  id SERIAL PRIMARY KEY,
  caixa_id INT NOT NULL REFERENCES caixas(id),
  cliente_id INT REFERENCES clientes(id) ON DELETE SET NULL,
  mesa_numero INT,
  data_hora TIMESTAMP NOT NULL DEFAULT NOW(),
  subtotal NUMERIC(12,2) NOT NULL,
  desconto NUMERIC(12,2) NOT NULL DEFAULT 0,
  total NUMERIC(12,2) NOT NULL,
  pagamento VARCHAR(20) NOT NULL, -- 'dinheiro', 'pix', 'debito', 'credito', 'fiado'
  recebido NUMERIC(12,2) NOT NULL DEFAULT 0,
  troco NUMERIC(12,2) NOT NULL DEFAULT 0,
  estornada BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS venda_itens (
  id SERIAL PRIMARY KEY,
  venda_id INT NOT NULL REFERENCES vendas(id) ON DELETE CASCADE,
  produto_id INT REFERENCES produtos(id) ON DELETE SET NULL,
  nome_snapshot VARCHAR(120) NOT NULL,
  qtd NUMERIC(12,3) NOT NULL,
  preco_unit NUMERIC(12,2) NOT NULL,
  unidade VARCHAR(5) NOT NULL
);

CREATE TABLE IF NOT EXISTS movimentacoes_caixa (
  id SERIAL PRIMARY KEY,
  caixa_id INT NOT NULL REFERENCES caixas(id) ON DELETE CASCADE,
  tipo VARCHAR(20) NOT NULL, -- 'suprimento', 'sangria', 'recebimento_fiado'
  valor NUMERIC(12,2) NOT NULL,
  motivo VARCHAR(160),
  data_hora TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS financeiro_lancamentos (
  id SERIAL PRIMARY KEY,
  tipo VARCHAR(10) NOT NULL, -- 'pagar' ou 'receber'
  fornecedor_id INT REFERENCES fornecedores(id) ON DELETE SET NULL,
  cliente_id INT REFERENCES clientes(id) ON DELETE SET NULL,
  descricao VARCHAR(160) NOT NULL,
  valor NUMERIC(12,2) NOT NULL,
  vencimento DATE NOT NULL,
  pago BOOLEAN NOT NULL DEFAULT FALSE,
  pago_em TIMESTAMP
);
