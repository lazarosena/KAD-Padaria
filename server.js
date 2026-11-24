import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';
import crypto from 'crypto';
import pg from 'pg';
import {
  SESSION_TTL_MS,
  hashPassword,
  isSessionExpired,
  isValidISODate,
  isValidPassword,
  parseFiniteNumber,
  parsePositiveId,
  parseText,
  verifyPassword
} from './security.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

if (!process.env.DB_PASSWORD) {
  throw new Error('Defina DB_PASSWORD no arquivo .env');
}

const { Pool } = pg;
const pool = new Pool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 5432),
  database: process.env.DB_NAME || 'padaria_kad',
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD
});

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use(express.json({ limit: '32kb' }));
app.use((req, _res, next) => {
  if (req.body === undefined) req.body = {};
  next();
});
app.use(express.static(path.join(__dirname, 'public')));

const r2 = v => Math.round((Number(v) + Number.EPSILON) * 100) / 100;
const r3 = v => Math.round((Number(v) + Number.EPSILON) * 1000) / 1000;
const asyncRoute = handler => (req, res, next) => Promise.resolve(handler(req, res, next)).catch(next);

const sessions = new Map();
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 5;

async function iniciarBanco() {
  const schema = await fs.readFile(path.join(__dirname, 'schema.sql'), 'utf8');
  await pool.query(schema);
  const adm = await pool.query("SELECT id FROM usuarios WHERE usuario = 'admin'");
  if (!adm.rows.length) {
    if (!isValidPassword(process.env.ADMIN_PASSWORD)) {
      throw new Error('Defina ADMIN_PASSWORD (mínimo 8 caracteres) no .env para criar o administrador inicial');
    }
    await pool.query(
      'INSERT INTO usuarios (nome, usuario, senha_hash, must_change_password) VALUES ($1, $2, $3, TRUE)',
      ['Administrador', 'admin', hashPassword(process.env.ADMIN_PASSWORD)]
    );
  }
  await pool.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'produtos_preco_positivo') THEN
        ALTER TABLE produtos ADD CONSTRAINT produtos_preco_positivo CHECK (preco >= 0);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'produtos_estoque_nao_negativo') THEN
        ALTER TABLE produtos ADD CONSTRAINT produtos_estoque_nao_negativo CHECK (estoque >= 0);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'venda_itens_qtd_positiva') THEN
        ALTER TABLE venda_itens ADD CONSTRAINT venda_itens_qtd_positiva CHECK (qtd > 0);
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'vendas_total_nao_negativo') THEN
        ALTER TABLE vendas ADD CONSTRAINT vendas_total_nao_negativo CHECK (total >= 0);
      END IF;
    END $$;
  `);
  console.log('Banco PostgreSQL conectado e schema atualizado');
}

function exigirLogin(req, res, next) {
  const token = req.headers['x-session-token'];
  const session = token && sessions.get(token);
  if (!session || isSessionExpired(session)) {
    if (token) sessions.delete(token);
    return res.status(401).json({ erro: 'Faça login novamente' });
  }
  req.usuario = session.usuario;
  if (req.usuario.mustChangePassword && !['/senha', '/logout', '/api/senha', '/api/logout'].includes(req.path)) {
    return res.status(403).json({ erro: 'Altere sua senha antes de continuar', exigirTrocaSenha: true });
  }
  next();
}

app.post('/api/login', asyncRoute(async (req, res) => {
  try {
    const usuario = typeof req.body.usuario === 'string' ? req.body.usuario.trim().toLowerCase() : '';
    const senha = typeof req.body.senha === 'string' ? req.body.senha : '';
    const attemptKey = `${req.ip}:${usuario}`;
    const now = Date.now();
    for (const [key, value] of loginAttempts) {
      if (value.expiresAt <= now) loginAttempts.delete(key);
    }
    const currentAttempt = loginAttempts.get(attemptKey);
    if (currentAttempt?.count >= LOGIN_MAX_ATTEMPTS) {
      return res.status(429).json({ erro: 'Muitas tentativas. Aguarde 15 minutos e tente novamente.' });
    }

    const { rows } = await pool.query(
      'SELECT id, nome, usuario, senha_hash, must_change_password FROM usuarios WHERE usuario = $1 AND ativo = TRUE',
      [usuario]
    );
    if (!rows[0] || !verifyPassword(senha || '', rows[0].senha_hash)) {
      const count = (currentAttempt?.count || 0) + 1;
      loginAttempts.set(attemptKey, { count, expiresAt: now + LOGIN_WINDOW_MS });
      return res.status(401).json({ erro: 'Usuário ou senha inválidos' });
    }

    loginAttempts.delete(attemptKey);
    const token = crypto.randomBytes(32).toString('hex');
    const usuarioLogado = {
      id: rows[0].id,
      nome: rows[0].nome,
      usuario: rows[0].usuario,
      mustChangePassword: rows[0].must_change_password
    };
    sessions.set(token, { usuario: usuarioLogado, expiresAt: now + SESSION_TTL_MS });
    res.json({ token, usuario: usuarioLogado });
  } catch (err) {
    res.status(500).json({ erro: 'Não foi possível autenticar' });
  }
}));

app.post('/api/logout', exigirLogin, (req, res) => {
  sessions.delete(req.headers['x-session-token']);
  res.json({ ok: true });
});

app.use('/api', (req, res, next) => {
  if (req.method === 'OPTIONS') return next();
  exigirLogin(req, res, next);
});

app.post('/api/senha', exigirLogin, asyncRoute(async (req, res) => {
  const usuario = req.usuario;
  const senhaAtual = typeof req.body.senhaAtual === 'string' ? req.body.senhaAtual : '';
  const novaSenha = req.body.novaSenha;
  const confirmarSenha = req.body.confirmarSenha;
  if (!isValidPassword(novaSenha)) {
    return res.status(400).json({ erro: 'A senha deve ter entre 8 e 128 caracteres' });
  }
  if (novaSenha !== confirmarSenha) {
    return res.status(400).json({ erro: 'A confirmação da senha não confere' });
  }

  try {
    const { rows } = await pool.query(
      'SELECT senha_hash FROM usuarios WHERE id = $1 AND ativo = TRUE',
      [usuario.id]
    );
    if (!rows[0] || !verifyPassword(senhaAtual, rows[0].senha_hash)) {
      return res.status(401).json({ erro: 'Senha atual incorreta' });
    }
    if (verifyPassword(novaSenha, rows[0].senha_hash)) {
      return res.status(400).json({ erro: 'A nova senha precisa ser diferente da atual' });
    }
    await pool.query(
      'UPDATE usuarios SET senha_hash = $1, must_change_password = FALSE WHERE id = $2',
      [hashPassword(novaSenha), usuario.id]
    );
    usuario.mustChangePassword = false;
    res.json({ ok: true });
  } catch (err) {
    console.error(`Falha ao alterar senha: ${err.message}`);
    res.status(500).json({ erro: 'Não foi possível alterar a senha' });
  }
}));

// ---------------- ESTADO GERAL / CONFIG ----------------
app.get('/api/estado', asyncRoute(async (_req, res) => {
  try {
    const [cfg, prods, cx, mesas, clis, forns, fin] = await Promise.all([
      pool.query('SELECT * FROM config WHERE id = 1'),
      pool.query('SELECT * FROM produtos WHERE ativo = TRUE ORDER BY nome ASC'),
      pool.query('SELECT * FROM caixas WHERE aberto = TRUE ORDER BY id DESC LIMIT 1'),
      pool.query(`
        SELECT m.id, m.numero, m.status, m.cliente_id, c.nome AS cliente_nome,
               COALESCE(SUM(ci.qtd * ci.preco_unit), 0) AS total
        FROM mesas m
        LEFT JOIN clientes c ON c.id = m.cliente_id
        LEFT JOIN comanda_itens ci ON ci.mesa_id = m.id
        GROUP BY m.id, c.nome
        ORDER BY m.numero ASC
      `),
      pool.query('SELECT * FROM clientes ORDER BY nome ASC'),
      pool.query('SELECT * FROM fornecedores ORDER BY nome ASC'),
      pool.query('SELECT * FROM financeiro_lancamentos ORDER BY pago ASC, vencimento ASC')
    ]);

    let caixaAtual = cx.rows[0] || null;
    if (caixaAtual) {
      const [vendasCx, movsCx] = await Promise.all([
        pool.query('SELECT * FROM vendas WHERE caixa_id = $1 AND estornada = FALSE ORDER BY id DESC', [caixaAtual.id]),
        pool.query('SELECT * FROM movimentacoes_caixa WHERE caixa_id = $1 ORDER BY id DESC', [caixaAtual.id])
      ]);
      caixaAtual.vendas = vendasCx.rows;
      caixaAtual.movs = movsCx.rows;
    }

    res.json({
      config: cfg.rows[0],
      produtos: prods.rows,
      caixaAberto: caixaAtual,
      mesas: mesas.rows,
      clientes: clis.rows,
      fornecedores: forns.rows,
      financeiro: fin.rows
    });
  } catch (err) {
    res.status(500).json({ erro: err.message });
  }
}));

app.put('/api/config', asyncRoute(async (req, res) => {
  try {
    const nome = parseText(req.body.nome || 'Padaria', 'Nome', 120);
    const balancaCod = parsePositiveId(req.body.balanca_cod || 6, 'Código da balança');
    const balancaVal = parsePositiveId(req.body.balanca_val || 5, 'Valor da balança');
    const balancaTipo = req.body.balanca_tipo || 'peso';
    if (!['peso', 'unidade'].includes(balancaTipo)) throw new Error('Tipo de balança inválido');
    const { rows } = await pool.query(
      `UPDATE config SET nome = $1, balanca_cod = $2, balanca_val = $3, balanca_tipo = $4
       WHERE id = 1 RETURNING *`,
      [nome, balancaCod, balancaVal, balancaTipo]
    );
    res.json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível atualizar a configuração' });
  }
}));

// ---------------- PRODUTOS ----------------
app.post('/api/produtos', asyncRoute(async (req, res) => {
  try {
    const { codigo, nome, preco, custo, unidade, estoque, estoque_min, atalho } = req.body;
    const nomeValido = parseText(nome, 'Nome do produto');
    const precoValido = r2(parseFiniteNumber(preco, 'Preço'));
    const custoValido = r2(parseFiniteNumber(custo ?? 0, 'Custo'));
    const estoqueValido = r3(parseFiniteNumber(estoque ?? 0, 'Estoque'));
    const estoqueMinimo = r3(parseFiniteNumber(estoque_min ?? 0, 'Estoque mínimo'));
    if (!['un', 'kg'].includes(unidade || 'un')) throw new Error('Unidade inválida');
    const { rows } = await pool.query(
      `INSERT INTO produtos (codigo, nome, preco, custo, unidade, estoque, estoque_min, atalho)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8) RETURNING *`,
      [codigo ? parseText(codigo, 'Código', 30) : null, nomeValido, precoValido, custoValido, unidade || 'un', estoqueValido, estoqueMinimo, !!atalho]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível cadastrar o produto' });
  }
}));

app.put('/api/produtos/:id', asyncRoute(async (req, res) => {
  try {
    const { codigo, nome, preco, custo, unidade, estoque, estoque_min, atalho } = req.body;
    const id = parsePositiveId(req.params.id, 'Produto');
    const nomeValido = parseText(nome, 'Nome do produto');
    const precoValido = r2(parseFiniteNumber(preco, 'Preço'));
    const custoValido = r2(parseFiniteNumber(custo ?? 0, 'Custo'));
    const estoqueValido = r3(parseFiniteNumber(estoque ?? 0, 'Estoque'));
    const estoqueMinimo = r3(parseFiniteNumber(estoque_min ?? 0, 'Estoque mínimo'));
    if (!['un', 'kg'].includes(unidade || 'un')) throw new Error('Unidade inválida');
    const { rows } = await pool.query(
      `UPDATE produtos
       SET codigo=$1, nome=$2, preco=$3, custo=$4, unidade=$5, estoque=$6, estoque_min=$7, atalho=$8
       WHERE id=$9 RETURNING *`,
      [codigo ? parseText(codigo, 'Código', 30) : null, nomeValido, precoValido, custoValido, unidade || 'un', estoqueValido, estoqueMinimo, !!atalho, id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Produto não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível atualizar o produto' });
  }
}));

app.delete('/api/produtos/:id', asyncRoute(async (req, res) => {
  try {
    const id = parsePositiveId(req.params.id, 'Produto');
    const result = await pool.query('UPDATE produtos SET ativo = FALSE WHERE id = $1', [id]);
    if (!result.rowCount) return res.status(404).json({ erro: 'Produto não encontrado' });
    res.json({ ok: true });
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível excluir o produto' });
  }
}));

app.post('/api/produtos/exemplos', asyncRoute(async (_req, res) => {
  const exemplos = [
    ['1', 'Pão francês (kg)', 18.90, 7.50, 'kg', 25, 4, true],
    ['2', 'Pão de queijo (kg)', 42.00, 18.00, 'kg', 12, 2, true],
    ['3', 'Sonho de creme', 6.50, 2.20, 'un', 24, 6, true],
    ['4', 'Café coado xícara', 4.00, 0.90, 'un', 100, 15, true],
    ['5', 'Pão de forma 500g', 9.90, 5.10, 'un', 18, 5, false],
    ['7890000000017', 'Café torrado 500g', 18.90, 12.50, 'un', 14, 4, false],
    ['7890000000024', 'Leite integral 1L', 5.49, 4.10, 'un', 36, 8, false],
    ['7890000000031', 'Refrigerante lata 350ml', 4.50, 2.60, 'un', 48, 12, false]
  ];
  for (const e of exemplos) {
    await pool.query(
      `INSERT INTO produtos (codigo, nome, preco, custo, unidade, estoque, estoque_min, atalho)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8) ON CONFLICT (codigo) DO NOTHING`,
      e
    );
  }
  res.json({ ok: true });
}));

// ---------------- CAIXA ----------------
app.post('/api/caixas/abrir', asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT pg_advisory_xact_lock(7262025)');
    const terminal = req.body.terminal ? parseText(req.body.terminal, 'Terminal', 40) : 'CAIXA-01';
    const operador = parseText(req.body.operador, 'Operador', 80);
    const valorInicial = r2(parseFiniteNumber(req.body.valorInicial ?? 0, 'Troco inicial'));
    const aberto = await client.query('SELECT id FROM caixas WHERE aberto = TRUE LIMIT 1');
    if (aberto.rows.length) throw new Error('Já existe um caixa aberto');
    const { rows } = await client.query(
      'INSERT INTO caixas (terminal, operador, valor_inicial) VALUES ($1, $2, $3) RETURNING *',
      [terminal, operador, valorInicial]
    );
    await client.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message || 'Não foi possível abrir o caixa' });
  } finally {
    client.release();
  }
}));

app.post('/api/caixas/:id/movimentacao', asyncRoute(async (req, res) => {
  try {
    const caixaId = parsePositiveId(req.params.id, 'Caixa');
    const { tipo } = req.body;
    const valor = r2(parseFiniteNumber(req.body.valor, 'Valor', { min: 0.01 }));
    const motivo = req.body.motivo ? parseText(req.body.motivo, 'Motivo', 160) : '-';
    if (!['suprimento', 'sangria'].includes(tipo)) throw new Error('Tipo de movimentação inválido');
    const caixa = await pool.query('SELECT id FROM caixas WHERE id = $1 AND aberto = TRUE', [caixaId]);
    if (!caixa.rows[0]) return res.status(404).json({ erro: 'Caixa aberto não encontrado' });
    const { rows } = await pool.query(
      'INSERT INTO movimentacoes_caixa (caixa_id, tipo, valor, motivo) VALUES ($1, $2, $3, $4) RETURNING *',
      [caixaId, tipo, valor, motivo]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível registrar a movimentação' });
  }
}));

app.post('/api/caixas/:id/fechar', asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const caixaId = parsePositiveId(req.params.id, 'Caixa');
    const contado = r2(parseFiniteNumber(req.body.valorContado, 'Valor contado'));
    const cx = (await client.query(
      'SELECT * FROM caixas WHERE id = $1 AND aberto = TRUE FOR UPDATE',
      [caixaId]
    )).rows[0];
    if (!cx) {
      await client.query('ROLLBACK');
      return res.status(404).json({ erro: 'Caixa aberto não encontrado' });
    }

    const dinVendas = await client.query(
      `SELECT COALESCE(SUM(total), 0) AS s FROM vendas WHERE caixa_id = $1 AND pagamento = 'dinheiro' AND estornada = FALSE`,
      [caixaId]
    );
    const movs = await client.query(
      `SELECT tipo, COALESCE(SUM(valor), 0) AS s FROM movimentacoes_caixa WHERE caixa_id = $1 GROUP BY tipo`,
      [caixaId]
    );
    let suprimentos = 0, sangrias = 0, recebimentosFiado = 0;
    movs.rows.forEach(m => {
      if (m.tipo === 'sangria') sangrias = Number(m.s);
      else if (m.tipo === 'suprimento') suprimentos = Number(m.s);
      else if (m.tipo === 'recebimento_fiado') recebimentosFiado = Number(m.s);
    });

    const esperado = r2(Number(cx.valor_inicial) + Number(dinVendas.rows[0].s) + suprimentos + recebimentosFiado - sangrias);
    const diferenca = r2(contado - esperado);
    const { rows } = await client.query(
      `UPDATE caixas SET aberto = FALSE, fechamento = NOW(), valor_esperado = $1, valor_contado = $2, diferenca = $3
       WHERE id = $4 RETURNING *`,
      [esperado, contado, diferenca, caixaId]
    );
    await client.query('COMMIT');
    res.json(rows[0]);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message || 'Não foi possível fechar o caixa' });
  } finally {
    client.release();
  }
}));

app.get('/api/caixas/historico', asyncRoute(async (_req, res) => {
  const { rows } = await pool.query('SELECT * FROM caixas WHERE aberto = FALSE ORDER BY id DESC LIMIT 15');
  res.json(rows);
}));

// ---------------- MESAS / COMANDAS ----------------
app.get('/api/mesas/:numero', asyncRoute(async (req, res) => {
  const numero = parsePositiveId(req.params.numero, 'Mesa');
  const mesa = (await pool.query('SELECT * FROM mesas WHERE numero = $1', [numero])).rows[0];
  if (!mesa) return res.status(404).json({ erro: 'Mesa não encontrada' });
  const itens = (await pool.query(
    `SELECT ci.id, ci.produto_id AS "produtoId", p.nome, ci.qtd, ci.preco_unit AS preco, p.unidade
     FROM comanda_itens ci
     JOIN produtos p ON p.id = ci.produto_id
     WHERE ci.mesa_id = $1
     ORDER BY ci.id ASC`,
    [mesa.id]
  )).rows;
  res.json({ ...mesa, itens });
}));

app.post('/api/mesas/:numero/itens', asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const numero = parsePositiveId(req.params.numero, 'Mesa');
    const produtoId = parsePositiveId(req.body.produtoId, 'Produto');
    const qtd = r3(parseFiniteNumber(req.body.qtd ?? 1, 'Quantidade', { min: 0.001, max: 100000 }));
    const mesa = (await client.query('SELECT * FROM mesas WHERE numero = $1 FOR UPDATE', [numero])).rows[0];
    const prod = (await client.query('SELECT * FROM produtos WHERE id = $1 AND ativo = TRUE', [produtoId])).rows[0];
    if (!mesa || !prod) throw new Error('Mesa ou produto inválido');

    await client.query(
      `INSERT INTO comanda_itens (mesa_id, produto_id, qtd, preco_unit) VALUES ($1, $2, $3, $4)`,
      [mesa.id, prod.id, qtd, prod.preco]
    );
    await client.query(`UPDATE mesas SET status = 'ocupada' WHERE id = $1`, [mesa.id]);
    await client.query('COMMIT');
    res.status(201).json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message });
  } finally {
    client.release();
  }
}));

app.delete('/api/mesas/:numero/itens/:itemId', asyncRoute(async (req, res) => {
  const numero = parsePositiveId(req.params.numero, 'Mesa');
  const itemId = parsePositiveId(req.params.itemId, 'Item');
  const mesa = (await pool.query('SELECT * FROM mesas WHERE numero = $1', [numero])).rows[0];
  if (!mesa) return res.status(404).json({ erro: 'Mesa não encontrada' });
  const deleted = await pool.query('DELETE FROM comanda_itens WHERE id = $1 AND mesa_id = $2', [itemId, mesa.id]);
  if (!deleted.rowCount) return res.status(404).json({ erro: 'Item não encontrado nesta mesa' });
  const rest = await pool.query('SELECT COUNT(*)::int AS c FROM comanda_itens WHERE mesa_id = $1', [mesa.id]);
  if (rest.rows[0].c === 0) {
    await pool.query(`UPDATE mesas SET status = 'livre', cliente_id = NULL WHERE id = $1`, [mesa.id]);
  }
  res.json({ ok: true });
}));

// ---------------- VENDAS (PDV + FECHAMENTO DE MESA + FIADO) ----------------
app.post('/api/vendas', asyncRoute(async (req, res) => {
  const { caixaId, clienteId, mesaNumero, itens, desconto = 0, pagamento, recebido = 0 } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    if (!Array.isArray(itens) || !itens.length) throw new Error('Nenhum item na venda');
    const caixaIdValido = parsePositiveId(caixaId, 'Caixa');
    const caixa = (await client.query(
      'SELECT id FROM caixas WHERE id = $1 AND aberto = TRUE FOR UPDATE',
      [caixaIdValido]
    )).rows[0];
    if (!caixa) throw new Error('O caixa informado não está aberto');
    const pagamentosValidos = new Set(['dinheiro', 'pix', 'debito', 'credito', 'fiado']);
    if (!pagamentosValidos.has(pagamento)) throw new Error('Forma de pagamento inválida');

    const itensValidados = [];
    for (const i of itens) {
      const qtd = r3(parseFiniteNumber(i.qtd, 'Quantidade', { min: 0.001, max: 100000 }));
      if (i.produtoId) {
        const produtoId = parsePositiveId(i.produtoId, 'Produto');
        const prod = (await client.query(
          'SELECT id, nome, preco, unidade, estoque, ativo FROM produtos WHERE id = $1 FOR UPDATE',
          [produtoId]
        )).rows[0];
        if (!prod || !prod.ativo) throw new Error('Produto inválido ou inativo');
        if (Number(prod.estoque) < qtd) {
          throw new Error(`Estoque insuficiente: ${prod.nome}`);
        }
        itensValidados.push({
          produtoId: prod.id,
          nome: prod.nome,
          qtd,
          preco: r2(prod.preco),
          unidade: prod.unidade
        });
      } else {
        const preco = r2(parseFiniteNumber(i.preco, 'Preço do item'));
        const unidade = i.unidade || 'un';
        if (!['un', 'kg'].includes(unidade)) throw new Error('Unidade do item inválida');
        itensValidados.push({
          produtoId: null,
          nome: parseText(i.nome, 'Nome do item', 120),
          qtd,
          preco,
          unidade
        });
      }
    }
    let subtotal = itensValidados.reduce((soma, i) => soma + r2(i.qtd * i.preco), 0);
    subtotal = r2(subtotal);
    const desc = r2(parseFiniteNumber(desconto, 'Desconto'));
    if (desc > subtotal) throw new Error('Desconto não pode ser maior que o subtotal');
    const total = r2(subtotal - desc);
    const recebidoDeclarado = r2(parseFiniteNumber(recebido ?? 0, 'Valor recebido'));
    const recebidoVenda = pagamento === 'dinheiro' ? recebidoDeclarado : total;
    if (pagamento === 'dinheiro' && recebidoVenda < total) {
      throw new Error('Valor recebido insuficiente');
    }
    const trocoCalculado = pagamento === 'dinheiro' ? r2(recebidoVenda - total) : 0;

    if (pagamento === 'fiado') {
      if (!clienteId) throw new Error('Selecione o cliente para vender no fiado');
      const cli = (await client.query('SELECT * FROM clientes WHERE id = $1 FOR UPDATE', [clienteId])).rows[0];
      if (!cli) throw new Error('Cliente não encontrado');
      if (Number(cli.saldo_devedor) + total > Number(cli.limite_fiado)) {
        throw new Error(`Limite de fiado excedido (Disponível: R$ ${r2(Number(cli.limite_fiado) - Number(cli.saldo_devedor)).toFixed(2)})`);
      }
      await client.query('UPDATE clientes SET saldo_devedor = saldo_devedor + $1 WHERE id = $2', [total, clienteId]);
    }

    const venda = (await client.query(
      `INSERT INTO vendas (caixa_id, cliente_id, mesa_numero, subtotal, desconto, total, pagamento, recebido, troco)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *`,
      [
        caixaIdValido,
        clienteId ? parsePositiveId(clienteId, 'Cliente') : null,
        mesaNumero ? parsePositiveId(mesaNumero, 'Mesa') : null,
        subtotal, desc, total, pagamento, recebidoVenda, trocoCalculado
      ]
    )).rows[0];

    for (const i of itensValidados) {
      await client.query(
        `INSERT INTO venda_itens (venda_id, produto_id, nome_snapshot, qtd, preco_unit, unidade)
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [venda.id, i.produtoId || null, i.nome, r3(i.qtd), r2(i.preco), i.unidade || 'un']
      );
      if (i.produtoId) {
        await client.query('UPDATE produtos SET estoque = estoque - $1 WHERE id = $2', [r3(i.qtd), i.produtoId]);
      }
    }

    if (mesaNumero) {
      const m = (await client.query('SELECT id FROM mesas WHERE numero = $1', [mesaNumero])).rows[0];
      if (m) {
        await client.query('DELETE FROM comanda_itens WHERE mesa_id = $1', [m.id]);
        await client.query(`UPDATE mesas SET status = 'livre', cliente_id = NULL WHERE id = $1`, [m.id]);
      }
    }

    await client.query('COMMIT');
    res.status(201).json(venda);
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message });
  } finally {
    client.release();
  }
}));

app.get('/api/vendas', asyncRoute(async (req, res) => {
  try {
    const { de, ate } = req.query;
    const validDate = value => value == null || isValidISODate(value);
    if (!validDate(de) || !validDate(ate)) {
      return res.status(400).json({ erro: 'Período inválido' });
    }
    if (de && ate && de > ate) {
      return res.status(400).json({ erro: 'A data inicial não pode ser posterior à final' });
    }
    const { rows } = await pool.query(
      `SELECT v.*, c.nome AS cliente_nome,
              COALESCE(json_agg(json_build_object(
                'nome', vi.nome_snapshot, 'qtd', vi.qtd, 'preco', vi.preco_unit, 'unidade', vi.unidade
              )) FILTER (WHERE vi.id IS NOT NULL), '[]') AS itens
       FROM vendas v
       LEFT JOIN clientes c ON c.id = v.cliente_id
       LEFT JOIN venda_itens vi ON vi.venda_id = v.id
       WHERE v.estornada = FALSE
         AND ($1::date IS NULL OR v.data_hora::date >= $1::date)
         AND ($2::date IS NULL OR v.data_hora::date <= $2::date)
       GROUP BY v.id, c.nome
       ORDER BY v.id DESC
       LIMIT 300`,
      [de || null, ate || null]
    );
    res.json(rows);
  } catch (err) {
    res.status(400).json({ erro: 'Não foi possível consultar as vendas' });
  }
}));

app.post('/api/vendas/:id/estornar', asyncRoute(async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const vendaId = parsePositiveId(req.params.id, 'Venda');
    const v = (await client.query('SELECT * FROM vendas WHERE id = $1 FOR UPDATE', [vendaId])).rows[0];
    if (!v || v.estornada) throw new Error('Venda inválida ou já estornada');
    const cx = (await client.query('SELECT aberto FROM caixas WHERE id = $1', [v.caixa_id])).rows[0];
    if (!cx || !cx.aberto) throw new Error('Só é possível estornar vendas do caixa ainda aberto');

    const itens = (await client.query('SELECT * FROM venda_itens WHERE venda_id = $1', [v.id])).rows;
    for (const i of itens) {
      if (i.produto_id) {
        await client.query('UPDATE produtos SET estoque = estoque + $1 WHERE id = $2', [i.qtd, i.produto_id]);
      }
    }
    if (v.pagamento === 'fiado' && v.cliente_id) {
      await client.query('UPDATE clientes SET saldo_devedor = GREATEST(0, saldo_devedor - $1) WHERE id = $2', [v.total, v.cliente_id]);
    }
    await client.query('UPDATE vendas SET estornada = TRUE WHERE id = $1', [v.id]);
    await client.query('COMMIT');
    res.json({ ok: true });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message });
  } finally {
    client.release();
  }
}));

// ---------------- CLIENTES & FIADO ----------------
app.post('/api/clientes', asyncRoute(async (req, res) => {
  try {
    const nome = parseText(req.body.nome, 'Nome do cliente');
    const telefone = typeof req.body.telefone === 'string' ? req.body.telefone.trim().slice(0, 30) : '';
    const limite = r2(parseFiniteNumber(req.body.limite_fiado ?? 0, 'Limite de fiado'));
    const { rows } = await pool.query(
      'INSERT INTO clientes (nome, telefone, limite_fiado) VALUES ($1, $2, $3) RETURNING *',
      [nome, telefone, limite]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível cadastrar o cliente' });
  }
}));

app.post('/api/clientes/:id/pagar-fiado', asyncRoute(async (req, res) => {
  const { valor, caixaId } = req.body;
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const v = r2(parseFiniteNumber(valor, 'Valor', { min: 0.01 }));
    const clienteId = parsePositiveId(req.params.id, 'Cliente');
    const cli = (await client.query('SELECT * FROM clientes WHERE id = $1 FOR UPDATE', [clienteId])).rows[0];
    if (!cli) throw new Error('Cliente não encontrado');
    const abatido = Math.min(v, Number(cli.saldo_devedor));
    await client.query('UPDATE clientes SET saldo_devedor = saldo_devedor - $1 WHERE id = $2', [abatido, cli.id]);
    if (caixaId) {
      const caixaIdValido = parsePositiveId(caixaId, 'Caixa');
      const caixa = await client.query('SELECT id FROM caixas WHERE id = $1 AND aberto = TRUE', [caixaIdValido]);
      if (!caixa.rows[0]) throw new Error('O caixa informado não está aberto');
      await client.query(
        `INSERT INTO movimentacoes_caixa (caixa_id, tipo, valor, motivo) VALUES ($1, 'recebimento_fiado', $2, $3)`,
        [caixaIdValido, abatido, `Recebimento fiado: ${cli.nome}`]
      );
    }
    await client.query('COMMIT');
    res.json({ ok: true, abatido });
  } catch (err) {
    await client.query('ROLLBACK');
    res.status(400).json({ erro: err.message });
  } finally {
    client.release();
  }
}));

// ---------------- FORNECEDORES & FINANCEIRO ----------------
app.post('/api/fornecedores', asyncRoute(async (req, res) => {
  try {
    const nome = parseText(req.body.nome, 'Nome do fornecedor');
    const documento = typeof req.body.documento === 'string' ? req.body.documento.trim().slice(0, 20) : '';
    const telefone = typeof req.body.telefone === 'string' ? req.body.telefone.trim().slice(0, 30) : '';
    const { rows } = await pool.query(
      'INSERT INTO fornecedores (nome, documento, telefone) VALUES ($1, $2, $3) RETURNING *',
      [nome, documento, telefone]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível cadastrar o fornecedor' });
  }
}));

app.post('/api/financeiro', asyncRoute(async (req, res) => {
  try {
    const { tipo, fornecedor_id, descricao, vencimento } = req.body;
    if (!['pagar', 'receber'].includes(tipo || 'pagar')) throw new Error('Tipo de lançamento inválido');
    if (!isValidISODate(vencimento)) {
      throw new Error('Data de vencimento inválida');
    }
    const valor = r2(parseFiniteNumber(req.body.valor, 'Valor', { min: 0.01 }));
    const fornecedorId = fornecedor_id ? parsePositiveId(fornecedor_id, 'Fornecedor') : null;
    const { rows } = await pool.query(
      `INSERT INTO financeiro_lancamentos (tipo, fornecedor_id, descricao, valor, vencimento)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [tipo || 'pagar', fornecedorId, parseText(descricao, 'Descrição', 160), valor, vencimento]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível criar o lançamento' });
  }
}));

app.post('/api/financeiro/:id/baixar', asyncRoute(async (req, res) => {
  try {
    const id = parsePositiveId(req.params.id, 'Lançamento');
    const { rows } = await pool.query(
      'UPDATE financeiro_lancamentos SET pago = TRUE, pago_em = NOW() WHERE id = $1 RETURNING *',
      [id]
    );
    if (!rows[0]) return res.status(404).json({ erro: 'Lançamento não encontrado' });
    res.json(rows[0]);
  } catch (err) {
    res.status(400).json({ erro: err.message || 'Não foi possível baixar o lançamento' });
  }
}));

app.use('/api', (err, req, res, next) => {
  if (res.headersSent) return next(err);
  const status = err.status === 413 ? 413 : err.status === 400 ? 400 : 500;
  if (status === 500) console.error(`Erro inesperado em ${req.method} ${req.path}: ${err.message}`);
  const erro = status === 413
    ? 'Requisição muito grande'
    : status === 400
      ? 'JSON inválido'
      : 'Erro interno do servidor';
  res.status(status).json({ erro });
});

const PORT = Number(process.env.PORT || 3000);
iniciarBanco()
  .then(() => {
    app.listen(PORT, '0.0.0.0', () => {
      console.log(`Servidor KAD Padaria rodando em http://localhost:${PORT} (e acessível na rede local pelo IP desta máquina)`);
    });
  })
  .catch(err => {
    console.error(`Não foi possível iniciar o banco de dados: ${err.message}`);
    process.exit(1);
  });
