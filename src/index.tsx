import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'
import * as XLSX from 'xlsx'

type Bindings = {
  DB: D1Database;
}

const app = new Hono<{ Bindings: Bindings }>()

// ============================================
// CONFIGURACIÓN
// ============================================
const JWT_SECRET = 'lyra-secret-key-change-in-production'
const SESSION_COOKIE = 'lyra_session'

// ============================================
// UTILIDADES - AUTENTICACIÓN
// ============================================

// Hash de password (simple SHA-256)
async function hashPassword(password: string): Promise<string> {
  const encoder = new TextEncoder()
  const data = encoder.encode(password + 'LYRA_SALT_2024')
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// Generar JWT simple
function generateJWT(userId: string, email: string): string {
  const header = btoa(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))
  const payload = btoa(JSON.stringify({
    userId,
    email,
    exp: Date.now() + (24 * 60 * 60 * 1000) // 24 horas
  }))
  const signature = btoa(`${header}.${payload}.${JWT_SECRET}`)
  return `${header}.${payload}.${signature}`
}

// Verificar JWT
function verifyJWT(token: string): { userId: string; email: string } | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null

    const payload = JSON.parse(atob(parts[1]))

    if (payload.exp < Date.now()) {
      return null // Expirado
    }

    return { userId: payload.userId, email: payload.email }
  } catch {
    return null
  }
}

// Generar ID único
function generateId(): string {
  return crypto.randomUUID().replace(/-/g, '')
}

// ============================================
// UTILIDADES - CÁLCULO DE SALDO (CRÍTICO)
// ============================================

/**
 * Calcula el saldo de una cuenta hasta una fecha específica
 * ESTA ES LA FUNCIÓN MÁS IMPORTANTE DEL SISTEMA
 */
async function calculateBalance(
  DB: D1Database,
  accountId: string,
  upToDate?: string
): Promise<number> {
  // 1. Obtener cuenta
  const account = await DB.prepare(
    'SELECT initial_saldo FROM bank_accounts WHERE id = ?'
  ).bind(accountId).first()

  if (!account) throw new Error('Cuenta no encontrada')

  // 2. Obtener suma de movimientos (solo completados y conciliados, NO cancelados)
  const dateFilter = upToDate ? 'AND date <= ?' : ''
  const params = upToDate ? [accountId, upToDate] : [accountId]

  const result = await DB.prepare(`
    SELECT
      SUM(CASE WHEN type = 'income' AND status != 'cancelled' THEN amount ELSE 0 END) as total_income,
      SUM(CASE WHEN type = 'expense' AND status != 'cancelled' THEN amount ELSE 0 END) as total_expense
    FROM movements
    WHERE account_id = ? ${dateFilter}
  `).bind(...params).first() as any

  // 3. Calcular saldo
  const initialSaldo = parseFloat(account.initial_saldo as string) || 0
  const totalIncome = parseFloat(result?.total_income || '0')
  const totalExpense = parseFloat(result?.total_expense || '0')

  return initialSaldo + totalIncome - totalExpense
}

// ============================================
// MIDDLEWARE - AUTENTICACIÓN
// ============================================

async function authMiddleware(c: any, next: any) {
  const token = getCookie(c, SESSION_COOKIE)

  if (!token) {
    return c.json({ error: 'No autenticado' }, 401)
  }

  const user = verifyJWT(token)

  if (!user) {
    return c.json({ error: 'Sesión inválida o expirada' }, 401)
  }

  c.set('user', user)
  await next()
}

// ============================================
// CORS
// ============================================
app.use('/*', cors({
  origin: '*',
  credentials: true
}))

// ============================================
// ENDPOINTS - AUTENTICACIÓN
// ============================================

// POST /api/auth/register
app.post('/api/auth/register', async (c) => {
  try {
    const { email, password, name } = await c.req.json()

    // Validaciones
    if (!email || !password || !name) {
      return c.json({ error: 'Faltan campos requeridos' }, 400)
    }

    if (password.length < 6) {
      return c.json({ error: 'La contraseña debe tener al menos 6 caracteres' }, 400)
    }

    const DB = c.env.DB

    // Verificar si ya existe
    const existing = await DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email).first()

    if (existing) {
      return c.json({ error: 'El email ya está registrado' }, 400)
    }

    // Crear usuario
    const userId = generateId()
    const passwordHash = await hashPassword(password)

    await DB.prepare(`
      INSERT INTO users (id, email, password_hash, name, role, created_at)
      VALUES (?, ?, ?, ?, 'admin', CURRENT_TIMESTAMP)
    `).bind(userId, email, passwordHash, name).run()

    // Crear categorías predefinidas para el usuario
    const categories = [
      { name: 'Ventas', type: 'income', color: '#10B981', icon: '💰' },
      { name: 'Servicios Prestados', type: 'income', color: '#34D399', icon: '🛠️' },
      { name: 'Inversiones', type: 'income', color: '#6EE7B7', icon: '📈' },
      { name: 'Otros Ingresos', type: 'income', color: '#A7F3D0', icon: '💵' },
      { name: 'Nómina', type: 'expense', color: '#EF4444', icon: '👥' },
      { name: 'Renta', type: 'expense', color: '#F87171', icon: '🏢' },
      { name: 'Servicios Públicos', type: 'expense', color: '#FCA5A5', icon: '💡' },
      { name: 'Compras', type: 'expense', color: '#FEE2E2', icon: '🛒' },
      { name: 'Impuestos', type: 'expense', color: '#DC2626', icon: '🏛️' },
      { name: 'Marketing', type: 'expense', color: '#FB923C', icon: '📢' },
      { name: 'Mantenimiento', type: 'expense', color: '#FDBA74', icon: '🔧' },
      { name: 'Otros Gastos', type: 'expense', color: '#FED7AA', icon: '💸' }
    ]

    for (const cat of categories) {
      await DB.prepare(`
        INSERT INTO categories (id, user_id, name, type, color, icon)
        VALUES (?, ?, ?, ?, ?, ?)
      `).bind(generateId(), userId, cat.name, cat.type, cat.color, cat.icon).run()
    }

    // Generar JWT
    const token = generateJWT(userId, email)

    // Set cookie
    setCookie(c, SESSION_COOKIE, token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24 // 24 horas
    })

    return c.json({
      success: true,
      user: { id: userId, email, name, role: 'admin' }
    })

  } catch (error: any) {
    console.error('Error en registro:', error)
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/auth/login
app.post('/api/auth/login', async (c) => {
  try {
    const { email, password } = await c.req.json()

    if (!email || !password) {
      return c.json({ error: 'Email y contraseña requeridos' }, 400)
    }

    const DB = c.env.DB

    // Buscar usuario
    const user = await DB.prepare(
      'SELECT id, email, password_hash, name, role FROM users WHERE email = ?'
    ).bind(email).first() as any

    if (!user) {
      return c.json({ error: 'Email o contraseña incorrectos' }, 401)
    }

    // Verificar contraseña
    const passwordHash = await hashPassword(password)

    if (passwordHash !== user.password_hash) {
      return c.json({ error: 'Email o contraseña incorrectos' }, 401)
    }

    // Actualizar last_login
    await DB.prepare(
      'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(user.id).run()

    // Generar JWT
    const token = generateJWT(user.id, user.email)

    // Set cookie
    setCookie(c, SESSION_COOKIE, token, {
      httpOnly: true,
      secure: true,
      sameSite: 'Lax',
      maxAge: 60 * 60 * 24
    })

    return c.json({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    })

  } catch (error: any) {
    console.error('Error en login:', error)
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/auth/logout
app.post('/api/auth/logout', (c) => {
  deleteCookie(c, SESSION_COOKIE)
  return c.json({ success: true })
})

// GET /api/auth/me
app.get('/api/auth/me', authMiddleware, async (c) => {
  const user = c.get('user')
  const DB = c.env.DB

  const userData = await DB.prepare(
    'SELECT id, email, name, role, created_at, last_login FROM users WHERE id = ?'
  ).bind(user.userId).first()

  return c.json({ user: userData })
})

// ============================================
// ENDPOINTS - EMPRESAS
// ============================================

// GET /api/companies
app.get('/api/companies', authMiddleware, async (c) => {
  const user = c.get('user')
  const DB = c.env.DB

  const companies = await DB.prepare(`
    SELECT id, name, initial_saldo, currency, logo_url, color, active, created_at
    FROM companies
    WHERE user_id = ? AND active = 1
    ORDER BY created_at DESC
  `).bind(user.userId).all()

  return c.json({ companies: companies.results })
})

// POST /api/companies
app.post('/api/companies', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { name, initial_saldo, currency, color } = await c.req.json()

    if (!name) {
      return c.json({ error: 'El nombre es requerido' }, 400)
    }

    const DB = c.env.DB
    const companyId = generateId()

    await DB.prepare(`
      INSERT INTO companies (id, user_id, name, initial_saldo, currency, color, active)
      VALUES (?, ?, ?, ?, ?, ?, 1)
    `).bind(
      companyId,
      user.userId,
      name,
      initial_saldo || 0,
      currency || 'MXN',
      color || '#3B82F6'
    ).run()

    const company = await DB.prepare(
      'SELECT * FROM companies WHERE id = ?'
    ).bind(companyId).first()

    return c.json({ success: true, company })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// PUT /api/companies/:id
app.put('/api/companies/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const companyId = c.req.param('id')
    const { name, initial_saldo, currency, color } = await c.req.json()

    const DB = c.env.DB

    // Verificar que la empresa pertenece al usuario
    const company = await DB.prepare(
      'SELECT id FROM companies WHERE id = ? AND user_id = ?'
    ).bind(companyId, user.userId).first()

    if (!company) {
      return c.json({ error: 'Empresa no encontrada' }, 404)
    }

    await DB.prepare(`
      UPDATE companies
      SET name = ?, initial_saldo = ?, currency = ?, color = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(name, initial_saldo, currency, color, companyId).run()

    const updated = await DB.prepare(
      'SELECT * FROM companies WHERE id = ?'
    ).bind(companyId).first()

    return c.json({ success: true, company: updated })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/companies/:id
app.delete('/api/companies/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const companyId = c.req.param('id')
    const DB = c.env.DB

    // Soft delete
    await DB.prepare(
      'UPDATE companies SET active = 0 WHERE id = ? AND user_id = ?'
    ).bind(companyId, user.userId).run()

    return c.json({ success: true })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - CUENTAS BANCARIAS
// ============================================

// GET /api/accounts
app.get('/api/accounts', authMiddleware, async (c) => {
  const user = c.get('user')
  const DB = c.env.DB

  const accounts = await DB.prepare(`
    SELECT
      a.*,
      c.name as company_name,
      c.color as company_color
    FROM bank_accounts a
    JOIN companies c ON a.company_id = c.id
    WHERE c.user_id = ? AND a.active = 1
    ORDER BY c.name, a.name
  `).bind(user.userId).all()

  // Calcular saldo actual de cada cuenta
  const accountsWithBalance = []
  for (const account of accounts.results) {
    const balance = await calculateBalance(DB, account.id as string)
    accountsWithBalance.push({
      ...account,
      current_balance: balance
    })
  }

  return c.json({ accounts: accountsWithBalance })
})

// POST /api/accounts
app.post('/api/accounts', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { company_id, name, account_number, bank_name, initial_saldo } = await c.req.json()

    if (!company_id || !name) {
      return c.json({ error: 'company_id y name son requeridos' }, 400)
    }

    const DB = c.env.DB

    // Verificar que la empresa pertenece al usuario
    const company = await DB.prepare(
      'SELECT id FROM companies WHERE id = ? AND user_id = ?'
    ).bind(company_id, user.userId).first()

    if (!company) {
      return c.json({ error: 'Empresa no encontrada' }, 404)
    }

    const accountId = generateId()

    await DB.prepare(`
      INSERT INTO bank_accounts (id, company_id, name, account_number, bank_name, initial_saldo, active)
      VALUES (?, ?, ?, ?, ?, ?, 1)
    `).bind(accountId, company_id, name, account_number || '', bank_name || '', initial_saldo || 0).run()

    const account = await DB.prepare(
      'SELECT * FROM bank_accounts WHERE id = ?'
    ).bind(accountId).first()

    return c.json({ success: true, account })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/accounts/:id/balance
app.get('/api/accounts/:id/balance', authMiddleware, async (c) => {
  try {
    const accountId = c.req.param('id')
    const DB = c.env.DB

    const balance = await calculateBalance(DB, accountId)

    return c.json({ account_id: accountId, balance })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - MOVIMIENTOS
// ============================================

// GET /api/movements
app.get('/api/movements', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const DB = c.env.DB

    const accountId = c.req.query('account_id')
    const from = c.req.query('from')
    const to = c.req.query('to')
    const type = c.req.query('type')
    const status = c.req.query('status')
    const search = c.req.query('search')

    let query = `
      SELECT
        m.*,
        c.name as category_name,
        c.color as category_color,
        a.name as account_name,
        comp.name as company_name
      FROM movements m
      LEFT JOIN categories c ON m.category_id = c.id
      LEFT JOIN bank_accounts a ON m.account_id = a.id
      LEFT JOIN companies comp ON a.company_id = comp.id
      WHERE comp.user_id = ?
    `

    const params: any[] = [user.userId]

    if (accountId) {
      query += ' AND m.account_id = ?'
      params.push(accountId)
    }

    if (from) {
      query += ' AND m.date >= ?'
      params.push(from)
    }

    if (to) {
      query += ' AND m.date <= ?'
      params.push(to)
    }

    if (type) {
      query += ' AND m.type = ?'
      params.push(type)
    }

    if (status) {
      query += ' AND m.status = ?'
      params.push(status)
    }

    if (search) {
      query += ' AND (m.name LIKE ? OR m.description LIKE ?)'
      params.push(`%${search}%`, `%${search}%`)
    }

    query += ' ORDER BY m.date DESC, m.created_at DESC LIMIT 100'

    const movements = await DB.prepare(query).bind(...params).all()

    return c.json({ movements: movements.results })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/movements
app.post('/api/movements', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const {
      account_id,
      date,
      type,
      amount,
      reference,
      name,
      category_id,
      description,
      comments
    } = await c.req.json()

    // Validaciones
    if (!account_id || !date || !type || !amount || !name) {
      return c.json({ error: 'Faltan campos requeridos' }, 400)
    }

    if (type !== 'income' && type !== 'expense') {
      return c.json({ error: 'type debe ser income o expense' }, 400)
    }

    if (amount <= 0) {
      return c.json({ error: 'amount debe ser mayor a 0' }, 400)
    }

    const DB = c.env.DB

    // Verificar que la cuenta pertenece al usuario
    const account = await DB.prepare(`
      SELECT a.id
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(account_id, user.userId).first()

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    const movementId = generateId()

    await DB.prepare(`
      INSERT INTO movements (
        id, account_id, date, type, amount, reference, name,
        category_id, description, comments, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'completed', ?)
    `).bind(
      movementId, account_id, date, type, amount,
      reference || '', name, category_id || null,
      description || '', comments || '', user.userId
    ).run()

    const movement = await DB.prepare(
      'SELECT * FROM movements WHERE id = ?'
    ).bind(movementId).first()

    return c.json({ success: true, movement })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// PUT /api/movements/:id
app.put('/api/movements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const movementId = c.req.param('id')
    const {
      date,
      type,
      amount,
      reference,
      name,
      category_id,
      description,
      comments
    } = await c.req.json()

    const DB = c.env.DB

    // Verificar que el movimiento pertenece al usuario
    const movement = await DB.prepare(`
      SELECT m.id, m.is_transfer
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE m.id = ? AND c.user_id = ?
    `).bind(movementId, user.userId).first() as any

    if (!movement) {
      return c.json({ error: 'Movimiento no encontrado' }, 404)
    }

    if (movement.is_transfer) {
      return c.json({ error: 'No se puede editar un movimiento de transferencia directamente' }, 400)
    }

    await DB.prepare(`
      UPDATE movements
      SET date = ?, type = ?, amount = ?, reference = ?, name = ?,
          category_id = ?, description = ?, comments = ?,
          updated_at = CURRENT_TIMESTAMP, updated_by = ?
      WHERE id = ?
    `).bind(
      date, type, amount, reference, name,
      category_id, description, comments, user.userId, movementId
    ).run()

    const updated = await DB.prepare(
      'SELECT * FROM movements WHERE id = ?'
    ).bind(movementId).first()

    return c.json({ success: true, movement: updated })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/movements/:id (soft delete - marcar como cancelado)
app.delete('/api/movements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const movementId = c.req.param('id')
    const DB = c.env.DB

    // Verificar que el movimiento pertenece al usuario
    const movement = await DB.prepare(`
      SELECT m.id, m.is_transfer
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE m.id = ? AND c.user_id = ?
    `).bind(movementId, user.userId).first() as any

    if (!movement) {
      return c.json({ error: 'Movimiento no encontrado' }, 404)
    }

    if (movement.is_transfer) {
      return c.json({ error: 'Use DELETE /api/transfers/:id para cancelar transferencias' }, 400)
    }

    await DB.prepare(
      'UPDATE movements SET status = \'cancelled\', updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(movementId).run()

    return c.json({ success: true })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - TRANSFERENCIAS (CRÍTICO)
// ============================================

// POST /api/transfers
app.post('/api/transfers', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { from_account_id, to_account_id, amount, date, concept } = await c.req.json()

    // Validaciones
    if (!from_account_id || !to_account_id || !amount || !date) {
      return c.json({ error: 'Faltan campos requeridos' }, 400)
    }

    if (from_account_id === to_account_id) {
      return c.json({ error: 'Las cuentas de origen y destino deben ser diferentes' }, 400)
    }

    if (amount <= 0) {
      return c.json({ error: 'El monto debe ser mayor a 0' }, 400)
    }

    const DB = c.env.DB

    // Verificar que ambas cuentas pertenecen al usuario
    const fromAccount = await DB.prepare(`
      SELECT a.id, a.name, c.name as company_name
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(from_account_id, user.userId).first() as any

    const toAccount = await DB.prepare(`
      SELECT a.id, a.name, c.name as company_name
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(to_account_id, user.userId).first() as any

    if (!fromAccount || !toAccount) {
      return c.json({ error: 'Una o ambas cuentas no encontradas' }, 404)
    }

    // TRANSACCIÓN: Todo o nada
    const transferId = generateId()
    const outMovementId = generateId()
    const inMovementId = generateId()

    // 1. Crear registro de transferencia
    await DB.prepare(`
      INSERT INTO transfers (id, from_account_id, to_account_id, amount, date, concept, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).bind(transferId, from_account_id, to_account_id, amount, date, concept || '', user.userId).run()

    // 2. Crear movimiento de SALIDA en cuenta origen
    await DB.prepare(`
      INSERT INTO movements (
        id, account_id, date, type, amount, name, description, comments,
        is_transfer, transfer_id, status, created_by
      ) VALUES (?, ?, ?, 'expense', ?, 'Transferencia interna', ?, ?, 1, ?, 'completed', ?)
    `).bind(
      outMovementId,
      from_account_id,
      date,
      amount,
      `Transferencia a ${toAccount.company_name} - ${toAccount.name}`,
      concept || '',
      transferId,
      user.userId
    ).run()

    // 3. Crear movimiento de ENTRADA en cuenta destino
    await DB.prepare(`
      INSERT INTO movements (
        id, account_id, date, type, amount, name, description, comments,
        is_transfer, transfer_id, status, created_by
      ) VALUES (?, ?, ?, 'income', ?, 'Transferencia interna', ?, ?, 1, ?, 'completed', ?)
    `).bind(
      inMovementId,
      to_account_id,
      date,
      amount,
      `Transferencia desde ${fromAccount.company_name} - ${fromAccount.name}`,
      concept || '',
      transferId,
      user.userId
    ).run()

    // 4. Actualizar IDs en transfer
    await DB.prepare(`
      UPDATE transfers
      SET from_movement_id = ?, to_movement_id = ?
      WHERE id = ?
    `).bind(outMovementId, inMovementId, transferId).run()

    const transfer = await DB.prepare(
      'SELECT * FROM transfers WHERE id = ?'
    ).bind(transferId).first()

    return c.json({
      success: true,
      transfer,
      out_movement_id: outMovementId,
      in_movement_id: inMovementId
    })

  } catch (error: any) {
    console.error('Error en transferencia:', error)
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/transfers
app.get('/api/transfers', authMiddleware, async (c) => {
  const user = c.get('user')
  const DB = c.env.DB

  const transfers = await DB.prepare(`
    SELECT
      t.*,
      fa.name as from_account_name,
      ta.name as to_account_name,
      fc.name as from_company_name,
      tc.name as to_company_name
    FROM transfers t
    JOIN bank_accounts fa ON t.from_account_id = fa.id
    JOIN bank_accounts ta ON t.to_account_id = ta.id
    JOIN companies fc ON fa.company_id = fc.id
    JOIN companies tc ON ta.company_id = tc.id
    WHERE fc.user_id = ?
    ORDER BY t.date DESC, t.created_at DESC
  `).bind(user.userId).all()

  return c.json({ transfers: transfers.results })
})

// DELETE /api/transfers/:id (cancelar transferencia)
app.delete('/api/transfers/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const transferId = c.req.param('id')
    const DB = c.env.DB

    // Verificar que la transferencia pertenece al usuario
    const transfer = await DB.prepare(`
      SELECT t.id, t.from_movement_id, t.to_movement_id
      FROM transfers t
      JOIN bank_accounts fa ON t.from_account_id = fa.id
      JOIN companies c ON fa.company_id = c.id
      WHERE t.id = ? AND c.user_id = ?
    `).bind(transferId, user.userId).first() as any

    if (!transfer) {
      return c.json({ error: 'Transferencia no encontrada' }, 404)
    }

    // Cancelar ambos movimientos
    await DB.prepare(`
      UPDATE movements
      SET status = 'cancelled'
      WHERE id IN (?, ?)
    `).bind(transfer.from_movement_id, transfer.to_movement_id).run()

    return c.json({ success: true })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - CATEGORÍAS
// ============================================

// GET /api/categories
app.get('/api/categories', authMiddleware, async (c) => {
  const user = c.get('user')
  const DB = c.env.DB

  const categories = await DB.prepare(`
    SELECT * FROM categories
    WHERE user_id = ?
    ORDER BY type, name
  `).bind(user.userId).all()

  return c.json({ categories: categories.results })
})

// POST /api/categories
app.post('/api/categories', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { name, type, color, icon } = await c.req.json()

    if (!name || !type) {
      return c.json({ error: 'name y type son requeridos' }, 400)
    }

    const DB = c.env.DB
    const categoryId = generateId()

    await DB.prepare(`
      INSERT INTO categories (id, user_id, name, type, color, icon)
      VALUES (?, ?, ?, ?, ?, ?)
    `).bind(categoryId, user.userId, name, type, color || '#6B7280', icon || '').run()

    const category = await DB.prepare(
      'SELECT * FROM categories WHERE id = ?'
    ).bind(categoryId).first()

    return c.json({ success: true, category })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - DASHBOARD
// ============================================

// GET /api/dashboard/summary
app.get('/api/dashboard/summary', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const DB = c.env.DB

    // Obtener todas las cuentas con saldo
    const accounts = await DB.prepare(`
      SELECT
        a.*,
        c.name as company_name,
        c.color as company_color
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND a.active = 1
    `).bind(user.userId).all()

    const accountsWithBalance = []
    let totalBalance = 0

    for (const account of accounts.results) {
      const balance = await calculateBalance(DB, account.id as string)
      totalBalance += balance
      accountsWithBalance.push({
        ...account,
        current_balance: balance
      })
    }

    // Obtener movimientos recientes
    const recentMovements = await DB.prepare(`
      SELECT
        m.*,
        a.name as account_name,
        c.name as company_name
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND m.status != 'cancelled'
      ORDER BY m.date DESC, m.created_at DESC
      LIMIT 10
    `).bind(user.userId).all()

    // Estadísticas del mes actual
    const now = new Date()
    const firstDayOfMonth = new Date(now.getFullYear(), now.getMonth(), 1)
      .toISOString().split('T')[0]
    const lastDayOfMonth = new Date(now.getFullYear(), now.getMonth() + 1, 0)
      .toISOString().split('T')[0]

    const monthStats = await DB.prepare(`
      SELECT
        SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as total_income,
        SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as total_expense
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND m.status != 'cancelled'
        AND m.date >= ? AND m.date <= ?
    `).bind(user.userId, firstDayOfMonth, lastDayOfMonth).first() as any

    const income = parseFloat(monthStats?.total_income || '0')
    const expense = parseFloat(monthStats?.total_expense || '0')

    return c.json({
      accounts: accountsWithBalance,
      totalBalance,
      monthStats: {
        income,
        expense,
        balance: income - expense
      },
      recentMovements: recentMovements.results
    })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - IMPORTACIÓN/EXPORTACIÓN EXCEL
// ============================================

// Mapeo de columnas posibles
const COLUMN_MAPPINGS: Record<string, string> = {
  'Fecha': 'date',
  'FECHA': 'date',
  'Date': 'date',
  'Dia': 'date',
  'día': 'date',
  'No. Cheque': 'reference',
  'No.Cheque': 'reference',
  'Cheque': 'reference',
  'Referencia': 'reference',
  'Ref': 'reference',
  'REF': 'reference',
  'Nombre': 'name',
  'NOMBRE': 'name',
  'Beneficiario': 'name',
  'Cliente': 'name',
  'Proveedor': 'name',
  'Descripción': 'description',
  'Descripcion': 'description',
  'DESCRIPCIÓN': 'description',
  'Concepto': 'description',
  'Detalle': 'description',
  'Entrada': 'income',
  'ENTRADA': 'income',
  'Ingreso': 'income',
  'Ingresos': 'income',
  'Depósito': 'income',
  'Deposito': 'income',
  'Cargo': 'income',
  'Salida': 'expense',
  'SALIDA': 'expense',
  'Egreso': 'expense',
  'Egresos': 'expense',
  'Retiro': 'expense',
  'Pago': 'expense',
  'Abono': 'expense',
  'Saldo': 'balance',
  'SALDO': 'balance',
  'Balance': 'balance',
  'Comentarios': 'comments',
  'COMENTARIOS': 'comments',
  'Notas': 'comments',
  'Observaciones': 'comments'
}

// Función helper: Parsear número
function parseNumber(value: any): number {
  if (typeof value === 'number') return value
  if (!value) return 0

  const cleaned = value.toString()
    .replace(/[$,]/g, '')
    .trim()

  return parseFloat(cleaned) || 0
}

// Función helper: Parsear fecha
function parseDate(value: any): string {
  if (!value) return ''

  // Si ya es un Date de Excel (número de serie)
  if (typeof value === 'number') {
    const date = XLSX.SSF.parse_date_code(value)
    return `${date.y}-${String(date.m).padStart(2, '0')}-${String(date.d).padStart(2, '0')}`
  }

  // Si es string, intentar parsear
  const str = value.toString().trim()

  // Formato DD/MM/YYYY
  if (/^\d{1,2}\/\d{1,2}\/\d{4}$/.test(str)) {
    const [day, month, year] = str.split('/')
    return `${year}-${month.padStart(2, '0')}-${day.padStart(2, '0')}`
  }

  // Formato YYYY-MM-DD (ya está bien)
  if (/^\d{4}-\d{2}-\d{2}$/.test(str)) {
    return str
  }

  // Intentar con Date nativo
  const date = new Date(str)
  if (!isNaN(date.getTime())) {
    return date.toISOString().split('T')[0]
  }

  return str
}

// Función helper: Encontrar mejor coincidencia de columna
function findBestMatch(header: string, mappings: Record<string, string>): string | null {
  // Coincidencia exacta
  if (mappings[header]) return mappings[header]

  // Sin case
  const lower = header.toLowerCase().trim()
  for (const [key, value] of Object.entries(mappings)) {
    if (key.toLowerCase() === lower) return value
  }

  // Contiene
  for (const [key, value] of Object.entries(mappings)) {
    if (lower.includes(key.toLowerCase()) || key.toLowerCase().includes(lower)) {
      return value
    }
  }

  return null
}

// Función helper: Obtener valor desde mapeo
function getValueFromMapping(row: any, mapping: Record<string, string>, field: string): any {
  for (const [excelCol, mappedField] of Object.entries(mapping)) {
    if (mappedField === field) {
      return row[excelCol]
    }
  }
  return null
}

// Función: Detectar estructura del Excel
function detectStructure(data: any[]) {
  if (data.length === 0) {
    throw new Error('Excel vacío')
  }

  const firstRow = data[0]
  const headers = Object.keys(firstRow)

  // Detectar mapeo de columnas
  const columnMapping: Record<string, string> = {}

  for (const header of headers) {
    const mapped = findBestMatch(header, COLUMN_MAPPINGS)
    if (mapped) {
      columnMapping[header] = mapped
    }
  }

  // Validar que tenga columnas mínimas
  const hasDate = Object.values(columnMapping).includes('date')
  const hasName = Object.values(columnMapping).includes('name')
  const hasAmount = Object.values(columnMapping).includes('income') ||
                    Object.values(columnMapping).includes('expense')

  if (!hasDate || !hasName || !hasAmount) {
    throw new Error('Excel no tiene las columnas requeridas (Fecha, Nombre, Entrada/Salida)')
  }

  // Detectar saldo inicial
  let initialBalance = 0
  const hasBalance = Object.values(columnMapping).includes('balance')

  if (hasBalance && data[0]) {
    const firstSaldo = parseNumber(getValueFromMapping(data[0], columnMapping, 'balance'))
    const firstIncome = parseNumber(getValueFromMapping(data[0], columnMapping, 'income'))
    const firstExpense = parseNumber(getValueFromMapping(data[0], columnMapping, 'expense'))

    if (firstIncome) {
      initialBalance = firstSaldo - firstIncome
    } else if (firstExpense) {
      initialBalance = firstSaldo + firstExpense
    } else {
      initialBalance = firstSaldo
    }
  }

  return {
    columnMapping,
    initialBalance,
    totalRows: data.length,
    hasBalance
  }
}

// Función: Validar datos del Excel
function validateData(data: any[], structure: any) {
  const errors: string[] = []
  const warnings: string[] = []
  let validRows = 0

  for (let i = 0; i < data.length; i++) {
    const row = data[i]
    const rowNum = i + 2 // Excel empieza en 1 + header

    // Validar fecha
    const fecha = getValueFromMapping(row, structure.columnMapping, 'date')
    if (!fecha) {
      errors.push(`Fila ${rowNum}: Fecha vacía`)
      continue
    }

    const fechaParsed = parseDate(fecha)
    if (!fechaParsed || fechaParsed === fecha.toString()) {
      errors.push(`Fila ${rowNum}: Fecha inválida (${fecha})`)
      continue
    }

    // Validar que tenga entrada O salida
    const entrada = parseNumber(getValueFromMapping(row, structure.columnMapping, 'income'))
    const salida = parseNumber(getValueFromMapping(row, structure.columnMapping, 'expense'))

    if (!entrada && !salida) {
      errors.push(`Fila ${rowNum}: No tiene entrada ni salida`)
      continue
    }

    if (entrada && salida) {
      errors.push(`Fila ${rowNum}: Tiene entrada Y salida (debe ser solo una)`)
      continue
    }

    // Validar nombre
    const nombre = getValueFromMapping(row, structure.columnMapping, 'name')
    if (!nombre?.toString().trim()) {
      warnings.push(`Fila ${rowNum}: Sin nombre`)
    }

    validRows++
  }

  // Calcular saldo final
  let calculatedBalance = structure.initialBalance
  for (const row of data) {
    const income = parseNumber(getValueFromMapping(row, structure.columnMapping, 'income'))
    const expense = parseNumber(getValueFromMapping(row, structure.columnMapping, 'expense'))
    calculatedBalance += income - expense
  }

  // Validar saldo final si existe columna de saldo
  let balanceMatches = true
  if (structure.hasBalance && data.length > 0) {
    const lastBalance = parseNumber(getValueFromMapping(data[data.length - 1], structure.columnMapping, 'balance'))
    const diff = Math.abs(calculatedBalance - lastBalance)
    balanceMatches = diff < 1

    if (!balanceMatches) {
      errors.push(
        `Saldo no cuadra. Calculado: $${calculatedBalance.toFixed(2)}, ` +
        `Excel: $${lastBalance.toFixed(2)} (diferencia: $${diff.toFixed(2)})`
      )
    }
  }

  return {
    valid: errors.length === 0,
    errors,
    warnings,
    validRows,
    balanceMatches,
    calculatedBalance
  }
}

// POST /api/import/preview
app.post('/api/import/preview', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const body = await c.req.parseBody()

    const file = body['file'] as File
    const accountId = body['account_id'] as string

    if (!file) {
      return c.json({ error: 'No se proporcionó archivo' }, 400)
    }

    if (!accountId) {
      return c.json({ error: 'account_id es requerido' }, 400)
    }

    const DB = c.env.DB

    // Verificar que la cuenta pertenece al usuario
    const account = await DB.prepare(`
      SELECT a.id, a.name, a.initial_saldo, c.name as company_name
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(accountId, user.userId).first()

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    // Leer Excel
    const arrayBuffer = await file.arrayBuffer()
    const workbook = XLSX.read(arrayBuffer, { type: 'array' })
    const sheetName = workbook.SheetNames[0]
    const worksheet = workbook.Sheets[sheetName]
    const data = XLSX.utils.sheet_to_json(worksheet)

    if (data.length === 0) {
      return c.json({ error: 'Excel vacío' }, 400)
    }

    // Detectar estructura
    const structure = detectStructure(data)

    // Validar datos
    const validation = validateData(data, structure)

    // Calcular estadísticas
    let totalIncome = 0
    let totalExpense = 0

    for (const row of data) {
      const income = parseNumber(getValueFromMapping(row, structure.columnMapping, 'income'))
      const expense = parseNumber(getValueFromMapping(row, structure.columnMapping, 'expense'))
      totalIncome += income
      totalExpense += expense
    }

    const finalBalance = structure.initialBalance + totalIncome - totalExpense

    return c.json({
      success: true,
      account: {
        id: account.id,
        name: account.name,
        company_name: account.company_name
      },
      structure: {
        columnMapping: structure.columnMapping,
        totalRows: structure.totalRows,
        hasBalance: structure.hasBalance
      },
      validation: {
        valid: validation.valid,
        errors: validation.errors,
        warnings: validation.warnings,
        validRows: validation.validRows,
        balanceMatches: validation.balanceMatches
      },
      stats: {
        initialBalance: structure.initialBalance,
        totalIncome,
        totalExpense,
        finalBalance,
        expectedFinalBalance: validation.calculatedBalance
      },
      sampleRows: data.slice(0, 5).map((row: any) => ({
        date: parseDate(getValueFromMapping(row, structure.columnMapping, 'date')),
        name: getValueFromMapping(row, structure.columnMapping, 'name'),
        income: parseNumber(getValueFromMapping(row, structure.columnMapping, 'income')),
        expense: parseNumber(getValueFromMapping(row, structure.columnMapping, 'expense')),
        balance: parseNumber(getValueFromMapping(row, structure.columnMapping, 'balance')),
        reference: getValueFromMapping(row, structure.columnMapping, 'reference'),
        description: getValueFromMapping(row, structure.columnMapping, 'description')
      }))
    })

  } catch (error: any) {
    console.error('Error en preview:', error)
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/import/execute
app.post('/api/import/execute', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const body = await c.req.parseBody()

    const file = body['file'] as File
    const accountId = body['account_id'] as string
    const skipDuplicates = body['skip_duplicates'] === 'true'
    const updateInitialBalance = body['update_initial_balance'] === 'true'

    if (!file || !accountId) {
      return c.json({ error: 'Faltan parámetros' }, 400)
    }

    const DB = c.env.DB

    // Verificar cuenta
    const account = await DB.prepare(`
      SELECT a.id
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(accountId, user.userId).first()

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    // Leer Excel
    const arrayBuffer = await file.arrayBuffer()
    const workbook = XLSX.read(arrayBuffer, { type: 'array' })
    const data = XLSX.utils.sheet_to_json(workbook.Sheets[workbook.SheetNames[0]])

    // Detectar estructura y validar
    const structure = detectStructure(data)
    const validation = validateData(data, structure)

    if (!validation.valid) {
      return c.json({
        error: 'Datos inválidos',
        errors: validation.errors
      }, 400)
    }

    // Crear registro de importación
    const importId = generateId()

    await DB.prepare(`
      INSERT INTO imports (
        id, user_id, account_id, file_name, file_url, file_size,
        import_type, status, total_rows, initial_balance,
        column_mapping, started_at
      ) VALUES (?, ?, ?, ?, '', ?, 'initial', 'processing', ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      importId,
      user.userId,
      accountId,
      file.name,
      file.size || 0,
      data.length,
      structure.initialBalance,
      JSON.stringify(structure.columnMapping)
    ).run()

    // Actualizar saldo inicial si se solicitó
    if (updateInitialBalance && structure.initialBalance !== 0) {
      await DB.prepare(
        'UPDATE bank_accounts SET initial_saldo = ? WHERE id = ?'
      ).bind(structure.initialBalance, accountId).run()
    }

    // Procesar cada fila
    let imported = 0, updated = 0, skipped = 0, errors = 0
    const errorDetails: any[] = []

    for (let i = 0; i < data.length; i++) {
      const row = data[i]
      const rowNum = i + 2

      try {
        const fecha = parseDate(getValueFromMapping(row, structure.columnMapping, 'date'))
        const entrada = parseNumber(getValueFromMapping(row, structure.columnMapping, 'income'))
        const salida = parseNumber(getValueFromMapping(row, structure.columnMapping, 'expense'))

        if (!entrada && !salida) {
          skipped++
          continue
        }

        const movement = {
          account_id: accountId,
          date: fecha,
          type: entrada ? 'income' : 'expense',
          amount: entrada || salida,
          reference: getValueFromMapping(row, structure.columnMapping, 'reference') || '',
          name: getValueFromMapping(row, structure.columnMapping, 'name') || '',
          description: getValueFromMapping(row, structure.columnMapping, 'description') || '',
          comments: getValueFromMapping(row, structure.columnMapping, 'comments') || '',
          status: 'completed',
          import_id: importId,
          created_by: user.userId
        }

        // Verificar duplicados
        if (skipDuplicates) {
          const existing = await DB.prepare(`
            SELECT id FROM movements
            WHERE account_id = ? AND date = ? AND amount = ? AND type = ?
              AND name LIKE ?
            LIMIT 1
          `).bind(
            movement.account_id,
            movement.date,
            movement.amount,
            movement.type,
            `%${movement.name}%`
          ).first()

          if (existing) {
            skipped++
            continue
          }
        }

        // Crear movimiento
        const movementId = generateId()
        await DB.prepare(`
          INSERT INTO movements (
            id, account_id, date, type, amount, reference, name,
            description, comments, status, import_id, created_by
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          movementId,
          movement.account_id,
          movement.date,
          movement.type,
          movement.amount,
          movement.reference,
          movement.name,
          movement.description,
          movement.comments,
          movement.status,
          movement.import_id,
          movement.created_by
        ).run()

        // Crear import_row
        await DB.prepare(`
          INSERT INTO import_rows (
            id, import_id, row_number, original_data, status, movement_id
          ) VALUES (?, ?, ?, ?, 'imported', ?)
        `).bind(
          generateId(),
          importId,
          rowNum,
          JSON.stringify(row),
          movementId
        ).run()

        imported++

      } catch (error: any) {
        errors++
        errorDetails.push({ row: rowNum, error: error.message })

        await DB.prepare(`
          INSERT INTO import_rows (
            id, import_id, row_number, original_data, status, error_message
          ) VALUES (?, ?, ?, ?, 'error', ?)
        `).bind(
          generateId(),
          importId,
          rowNum,
          JSON.stringify(row),
          error.message
        ).run()
      }
    }

    // Calcular saldo final
    const finalBalance = await calculateBalance(DB, accountId)

    // Actualizar import record
    await DB.prepare(`
      UPDATE imports
      SET status = ?, rows_imported = ?, rows_updated = ?, rows_skipped = ?,
          rows_error = ?, final_balance = ?, expected_final_balance = ?,
          balance_matches = ?, errors = ?, completed_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      errors > 0 ? 'partial' : 'completed',
      imported,
      updated,
      skipped,
      errors,
      finalBalance,
      validation.calculatedBalance,
      Math.abs(finalBalance - validation.calculatedBalance) < 1 ? 1 : 0,
      JSON.stringify(errorDetails),
      importId
    ).run()

    return c.json({
      success: true,
      import_id: importId,
      results: {
        total: data.length,
        imported,
        updated,
        skipped,
        errors,
        finalBalance,
        expectedFinalBalance: validation.calculatedBalance,
        balanceMatches: Math.abs(finalBalance - validation.calculatedBalance) < 1
      },
      errorDetails: errors > 0 ? errorDetails : undefined
    })

  } catch (error: any) {
    console.error('Error en execute:', error)
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/export
app.post('/api/export', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { account_id, from, to } = await c.req.json()

    if (!account_id) {
      return c.json({ error: 'account_id es requerido' }, 400)
    }

    const DB = c.env.DB

    // Obtener cuenta
    const account = await DB.prepare(`
      SELECT a.*, c.name as company_name
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(account_id, user.userId).first() as any

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    // Obtener movimientos
    let query = `
      SELECT * FROM movements
      WHERE account_id = ? AND status != 'cancelled'
    `
    const params: any[] = [account_id]

    if (from) {
      query += ' AND date >= ?'
      params.push(from)
    }

    if (to) {
      query += ' AND date <= ?'
      params.push(to)
    }

    query += ' ORDER BY date ASC, created_at ASC'

    const movements = await DB.prepare(query).bind(...params).all()

    // Crear Excel
    const data: any[] = []
    let saldo = parseFloat(account.initial_saldo)

    for (const mov of movements.results as any[]) {
      if (mov.type === 'income') {
        saldo += parseFloat(mov.amount)
      } else {
        saldo -= parseFloat(mov.amount)
      }

      data.push({
        'Fecha': mov.date,
        'No. Cheque': mov.reference || '',
        'Nombre': mov.name,
        'Descripción': mov.description || '',
        'Entrada': mov.type === 'income' ? parseFloat(mov.amount) : '',
        'Salida': mov.type === 'expense' ? parseFloat(mov.amount) : '',
        'Saldo': saldo,
        'Comentarios': mov.comments || ''
      })
    }

    // Generar archivo Excel
    const worksheet = XLSX.utils.json_to_sheet(data)
    const workbook = XLSX.utils.book_new()
    XLSX.utils.book_append_sheet(workbook, worksheet, 'Movimientos')

    // Convertir a buffer
    const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' })

    const fileName = `${account.company_name}_${account.name}_${new Date().toISOString().split('T')[0]}.xlsx`

    return new Response(excelBuffer, {
      headers: {
        'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'Content-Disposition': `attachment; filename="${fileName}"`
      }
    })

  } catch (error: any) {
    console.error('Error en export:', error)
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/export/template
app.get('/api/export/template', (c) => {
  const data = [
    {
      'Fecha': '2025-10-14',
      'No. Cheque': '001',
      'Nombre': 'Cliente Ejemplo',
      'Descripción': 'Pago de factura',
      'Entrada': 5000,
      'Salida': '',
      'Saldo': 105000,
      'Comentarios': 'Ejemplo de ingreso'
    },
    {
      'Fecha': '2025-10-15',
      'No. Cheque': '002',
      'Nombre': 'Proveedor Ejemplo',
      'Descripción': 'Compra de materiales',
      'Entrada': '',
      'Salida': 2500,
      'Saldo': 102500,
      'Comentarios': 'Ejemplo de egreso'
    }
  ]

  const worksheet = XLSX.utils.json_to_sheet(data)
  const workbook = XLSX.utils.book_new()
  XLSX.utils.book_append_sheet(workbook, worksheet, 'Plantilla')

  const excelBuffer = XLSX.write(workbook, { type: 'buffer', bookType: 'xlsx' })

  return new Response(excelBuffer, {
    headers: {
      'Content-Type': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'Content-Disposition': 'attachment; filename="plantilla_lyra.xlsx"'
    }
  })
})

// GET /api/imports/history
app.get('/api/imports/history', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const accountId = c.req.query('account_id')

    const DB = c.env.DB

    let query = `
      SELECT i.*, a.name as account_name, c.name as company_name
      FROM imports i
      JOIN bank_accounts a ON i.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE i.user_id = ?
    `
    const params: any[] = [user.userId]

    if (accountId) {
      query += ' AND i.account_id = ?'
      params.push(accountId)
    }

    query += ' ORDER BY i.started_at DESC LIMIT 50'

    const imports = await DB.prepare(query).bind(...params).all()

    return c.json({ imports: imports.results })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - ESTADOS DE CUENTA BANCARIOS
// ============================================

// Función helper: Calcular saldos del sistema para un período
async function calculateSystemBalanceForPeriod(
  DB: D1Database,
  accountId: string,
  periodStart: string,
  periodEnd: string
) {
  // Saldo inicial del sistema (hasta el día anterior al inicio del período)
  const previousDayQuery = await DB.prepare(`
    SELECT
      SUM(CASE WHEN type = 'income' AND status != 'cancelled' THEN amount ELSE 0 END) as total_income,
      SUM(CASE WHEN type = 'expense' AND status != 'cancelled' THEN amount ELSE 0 END) as total_expense
    FROM movements
    WHERE account_id = ? AND date < ?
  `).bind(accountId, periodStart).first() as any

  const account = await DB.prepare(
    'SELECT initial_saldo FROM bank_accounts WHERE id = ?'
  ).bind(accountId).first() as any

  const initialSaldo = parseFloat(account?.initial_saldo || '0')
  const prevIncome = parseFloat(previousDayQuery?.total_income || '0')
  const prevExpense = parseFloat(previousDayQuery?.total_expense || '0')

  const systemInitialBalance = initialSaldo + prevIncome - prevExpense

  // Movimientos dentro del período
  const periodQuery = await DB.prepare(`
    SELECT
      SUM(CASE WHEN type = 'income' AND status != 'cancelled' THEN amount ELSE 0 END) as total_income,
      SUM(CASE WHEN type = 'expense' AND status != 'cancelled' THEN amount ELSE 0 END) as total_expense
    FROM movements
    WHERE account_id = ? AND date >= ? AND date <= ?
  `).bind(accountId, periodStart, periodEnd).first() as any

  const systemTotalIncome = parseFloat(periodQuery?.total_income || '0')
  const systemTotalExpense = parseFloat(periodQuery?.total_expense || '0')

  const systemFinalBalance = systemInitialBalance + systemTotalIncome - systemTotalExpense

  return {
    systemInitialBalance,
    systemTotalIncome,
    systemTotalExpense,
    systemFinalBalance
  }
}

// Función helper: Generar sugerencias de conciliación
function generateReconciliationSuggestions(
  balanceDiff: number,
  incomeDiff: number,
  expenseDiff: number
): string[] {
  const suggestions: string[] = []

  if (Math.abs(balanceDiff) < 1) {
    suggestions.push('✅ Estado de cuenta conciliado correctamente')
    return suggestions
  }

  if (Math.abs(balanceDiff) > 1) {
    suggestions.push(`⚠️ Diferencia de saldo: $${Math.abs(balanceDiff).toFixed(2)}`)
  }

  if (Math.abs(incomeDiff) > 1) {
    if (incomeDiff > 0) {
      suggestions.push(
        `💡 El banco reporta $${incomeDiff.toFixed(2)} MÁS en ingresos - ` +
        `Revisa si falta registrar algún depósito`
      )
    } else {
      suggestions.push(
        `💡 El sistema tiene $${Math.abs(incomeDiff).toFixed(2)} MÁS en ingresos - ` +
        `Revisa si hay movimientos duplicados`
      )
    }
  }

  if (Math.abs(expenseDiff) > 1) {
    if (expenseDiff > 0) {
      suggestions.push(
        `💡 El banco reporta $${expenseDiff.toFixed(2)} MÁS en egresos - ` +
        `Revisa si falta registrar algún cargo`
      )
    } else {
      suggestions.push(
        `💡 El sistema tiene $${Math.abs(expenseDiff).toFixed(2)} MÁS en egresos - ` +
        `Revisa si hay movimientos duplicados`
      )
    }
  }

  return suggestions
}

// POST /api/bank-statements/upload
app.post('/api/bank-statements/upload', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const body = await c.req.parseBody()

    const file = body['file'] as File
    const accountId = body['account_id'] as string
    const year = parseInt(body['year'] as string)
    const month = parseInt(body['month'] as string)
    const periodStart = body['period_start'] as string
    const periodEnd = body['period_end'] as string

    // Datos del banco (opcionales - pueden ingresarse después)
    const bankInitialBalance = body['bank_initial_balance'] ?
      parseFloat(body['bank_initial_balance'] as string) : null
    const bankFinalBalance = body['bank_final_balance'] ?
      parseFloat(body['bank_final_balance'] as string) : null
    const bankTotalIncome = body['bank_total_income'] ?
      parseFloat(body['bank_total_income'] as string) : null
    const bankTotalExpense = body['bank_total_expense'] ?
      parseFloat(body['bank_total_expense'] as string) : null

    if (!file || !accountId || !year || !month || !periodStart || !periodEnd) {
      return c.json({ error: 'Faltan parámetros requeridos' }, 400)
    }

    if (month < 1 || month > 12) {
      return c.json({ error: 'Mes debe estar entre 1 y 12' }, 400)
    }

    const DB = c.env.DB

    // Verificar que la cuenta pertenece al usuario
    const account = await DB.prepare(`
      SELECT a.id, a.name, c.name as company_name
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(accountId, user.userId).first()

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    // Verificar si ya existe un estado de cuenta para ese mes
    const existing = await DB.prepare(
      'SELECT id FROM bank_statements WHERE account_id = ? AND year = ? AND month = ?'
    ).bind(accountId, year, month).first()

    if (existing) {
      return c.json({
        error: `Ya existe un estado de cuenta para ${month}/${year}`
      }, 400)
    }

    // Por ahora guardamos la URL como el nombre del archivo
    // En producción, esto subiría a R2/S3
    const fileUrl = `/uploads/bank-statements/${accountId}/${year}/${month}/${file.name}`
    const statementId = generateId()

    // Calcular saldos del sistema para ese período
    const systemData = await calculateSystemBalanceForPeriod(
      DB,
      accountId,
      periodStart,
      periodEnd
    )

    // Calcular diferencias si se proporcionaron datos del banco
    let balanceDifference = null
    let isReconciled = 0

    if (bankFinalBalance !== null && systemData.systemFinalBalance !== null) {
      balanceDifference = bankFinalBalance - systemData.systemFinalBalance
      isReconciled = Math.abs(balanceDifference) < 1 ? 1 : 0
    }

    // Crear registro de estado de cuenta
    await DB.prepare(`
      INSERT INTO bank_statements (
        id, account_id, year, month, period_start, period_end,
        file_name, file_url, file_type, file_size,
        bank_initial_balance, bank_final_balance,
        bank_total_income, bank_total_expense,
        system_initial_balance, system_final_balance,
        system_total_income, system_total_expense,
        is_reconciled, balance_difference,
        uploaded_by, uploaded_at
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
    `).bind(
      statementId,
      accountId,
      year,
      month,
      periodStart,
      periodEnd,
      file.name,
      fileUrl,
      file.type || 'application/pdf',
      file.size || 0,
      bankInitialBalance,
      bankFinalBalance,
      bankTotalIncome,
      bankTotalExpense,
      systemData.systemInitialBalance,
      systemData.systemFinalBalance,
      systemData.systemTotalIncome,
      systemData.systemTotalExpense,
      isReconciled,
      balanceDifference,
      user.userId
    ).run()

    const statement = await DB.prepare(
      'SELECT * FROM bank_statements WHERE id = ?'
    ).bind(statementId).first()

    return c.json({
      success: true,
      statement,
      is_reconciled: isReconciled === 1,
      balance_difference: balanceDifference
    })

  } catch (error: any) {
    console.error('Error en upload:', error)
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/bank-statements
app.get('/api/bank-statements', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const accountId = c.req.query('account_id')
    const year = c.req.query('year')
    const month = c.req.query('month')

    const DB = c.env.DB

    let query = `
      SELECT
        bs.*,
        a.name as account_name,
        c.name as company_name
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ?
    `
    const params: any[] = [user.userId]

    if (accountId) {
      query += ' AND bs.account_id = ?'
      params.push(accountId)
    }

    if (year) {
      query += ' AND bs.year = ?'
      params.push(parseInt(year))
    }

    if (month) {
      query += ' AND bs.month = ?'
      params.push(parseInt(month))
    }

    query += ' ORDER BY bs.year DESC, bs.month DESC'

    const statements = await DB.prepare(query).bind(...params).all()

    return c.json({ statements: statements.results })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/bank-statements/:id
app.get('/api/bank-statements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const statementId = c.req.param('id')
    const DB = c.env.DB

    const statement = await DB.prepare(`
      SELECT
        bs.*,
        a.name as account_name,
        c.name as company_name
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE bs.id = ? AND c.user_id = ?
    `).bind(statementId, user.userId).first()

    if (!statement) {
      return c.json({ error: 'Estado de cuenta no encontrado' }, 404)
    }

    return c.json({ statement })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/bank-statements/:id/comparison
app.get('/api/bank-statements/:id/comparison', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const statementId = c.req.param('id')
    const DB = c.env.DB

    const statement = await DB.prepare(`
      SELECT
        bs.*,
        a.name as account_name,
        c.name as company_name
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE bs.id = ? AND c.user_id = ?
    `).bind(statementId, user.userId).first() as any

    if (!statement) {
      return c.json({ error: 'Estado de cuenta no encontrado' }, 404)
    }

    // Calcular diferencias
    const initialDiff = statement.bank_initial_balance !== null && statement.system_initial_balance !== null
      ? parseFloat(statement.bank_initial_balance) - parseFloat(statement.system_initial_balance)
      : null

    const finalDiff = statement.bank_final_balance !== null && statement.system_final_balance !== null
      ? parseFloat(statement.bank_final_balance) - parseFloat(statement.system_final_balance)
      : null

    const incomeDiff = statement.bank_total_income !== null && statement.system_total_income !== null
      ? parseFloat(statement.bank_total_income) - parseFloat(statement.system_total_income)
      : null

    const expenseDiff = statement.bank_total_expense !== null && statement.system_total_expense !== null
      ? parseFloat(statement.bank_total_expense) - parseFloat(statement.system_total_expense)
      : null

    // Generar sugerencias
    const suggestions = generateReconciliationSuggestions(
      finalDiff || 0,
      incomeDiff || 0,
      expenseDiff || 0
    )

    // Obtener movimientos no conciliados del período
    const unreconciled = await DB.prepare(`
      SELECT * FROM movements
      WHERE account_id = ?
        AND date >= ?
        AND date <= ?
        AND (is_bank_matched = 0 OR bank_statement_id IS NULL)
        AND status != 'cancelled'
      ORDER BY date ASC
    `).bind(
      statement.account_id,
      statement.period_start,
      statement.period_end
    ).all()

    return c.json({
      statement,
      comparison: {
        initial_balance: {
          bank: statement.bank_initial_balance,
          system: statement.system_initial_balance,
          difference: initialDiff,
          matches: initialDiff !== null && Math.abs(initialDiff) < 1
        },
        final_balance: {
          bank: statement.bank_final_balance,
          system: statement.system_final_balance,
          difference: finalDiff,
          matches: finalDiff !== null && Math.abs(finalDiff) < 1
        },
        income: {
          bank: statement.bank_total_income,
          system: statement.system_total_income,
          difference: incomeDiff,
          matches: incomeDiff !== null && Math.abs(incomeDiff) < 1
        },
        expense: {
          bank: statement.bank_total_expense,
          system: statement.system_total_expense,
          difference: expenseDiff,
          matches: expenseDiff !== null && Math.abs(expenseDiff) < 1
        }
      },
      suggestions,
      unreconciled_movements: unreconciled.results,
      unreconciled_count: unreconciled.results.length
    })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/bank-statements/:id/reconcile
app.post('/api/bank-statements/:id/reconcile', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const statementId = c.req.param('id')
    const { force } = await c.req.json()

    const DB = c.env.DB

    const statement = await DB.prepare(`
      SELECT bs.*, a.id as account_id
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE bs.id = ? AND c.user_id = ?
    `).bind(statementId, user.userId).first() as any

    if (!statement) {
      return c.json({ error: 'Estado de cuenta no encontrado' }, 404)
    }

    // Si force=true, marcar como conciliado aunque haya diferencias
    // Si no, solo marcar si la diferencia es < $1
    const canReconcile = force || (
      statement.balance_difference !== null &&
      Math.abs(parseFloat(statement.balance_difference)) < 1
    )

    if (!canReconcile) {
      return c.json({
        error: 'No se puede conciliar. Hay diferencias mayores a $1. Use force=true para forzar.'
      }, 400)
    }

    await DB.prepare(`
      UPDATE bank_statements
      SET is_reconciled = 1,
          reconciled_at = CURRENT_TIMESTAMP,
          reconciled_by = ?
      WHERE id = ?
    `).bind(user.userId, statementId).run()

    // Marcar movimientos del período como conciliados
    await DB.prepare(`
      UPDATE movements
      SET bank_statement_id = ?,
          is_bank_matched = 1
      WHERE account_id = ?
        AND date >= ?
        AND date <= ?
        AND status != 'cancelled'
    `).bind(
      statementId,
      statement.account_id,
      statement.period_start,
      statement.period_end
    ).run()

    return c.json({ success: true, message: 'Estado de cuenta conciliado' })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// PUT /api/bank-statements/:id
app.put('/api/bank-statements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const statementId = c.req.param('id')
    const {
      bank_initial_balance,
      bank_final_balance,
      bank_total_income,
      bank_total_expense,
      notes
    } = await c.req.json()

    const DB = c.env.DB

    const statement = await DB.prepare(`
      SELECT bs.*, a.id as account_id
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE bs.id = ? AND c.user_id = ?
    `).bind(statementId, user.userId).first() as any

    if (!statement) {
      return c.json({ error: 'Estado de cuenta no encontrado' }, 404)
    }

    // Recalcular diferencia de saldo
    let balanceDifference = null
    let isReconciled = 0

    if (bank_final_balance !== undefined && statement.system_final_balance !== null) {
      balanceDifference = parseFloat(bank_final_balance) - parseFloat(statement.system_final_balance)
      isReconciled = Math.abs(balanceDifference) < 1 ? 1 : 0
    }

    await DB.prepare(`
      UPDATE bank_statements
      SET bank_initial_balance = ?,
          bank_final_balance = ?,
          bank_total_income = ?,
          bank_total_expense = ?,
          balance_difference = ?,
          is_reconciled = ?,
          notes = ?
      WHERE id = ?
    `).bind(
      bank_initial_balance !== undefined ? bank_initial_balance : statement.bank_initial_balance,
      bank_final_balance !== undefined ? bank_final_balance : statement.bank_final_balance,
      bank_total_income !== undefined ? bank_total_income : statement.bank_total_income,
      bank_total_expense !== undefined ? bank_total_expense : statement.bank_total_expense,
      balanceDifference,
      isReconciled,
      notes !== undefined ? notes : statement.notes,
      statementId
    ).run()

    const updated = await DB.prepare(
      'SELECT * FROM bank_statements WHERE id = ?'
    ).bind(statementId).first()

    return c.json({ success: true, statement: updated })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/bank-statements/calendar/:year
app.get('/api/bank-statements/calendar/:year', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const year = parseInt(c.req.param('year'))
    const accountId = c.req.query('account_id')

    if (!accountId) {
      return c.json({ error: 'account_id es requerido' }, 400)
    }

    const DB = c.env.DB

    // Verificar que la cuenta pertenece al usuario
    const account = await DB.prepare(`
      SELECT a.id
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE a.id = ? AND c.user_id = ?
    `).bind(accountId, user.userId).first()

    if (!account) {
      return c.json({ error: 'Cuenta no encontrada' }, 404)
    }

    // Obtener todos los estados de cuenta del año
    const statements = await DB.prepare(`
      SELECT * FROM bank_statements
      WHERE account_id = ? AND year = ?
      ORDER BY month ASC
    `).bind(accountId, year).all()

    // Crear calendario de 12 meses
    const calendar = []
    for (let month = 1; month <= 12; month++) {
      const statement = (statements.results as any[]).find(s => s.month === month)

      if (statement) {
        calendar.push({
          month,
          has_statement: true,
          is_reconciled: statement.is_reconciled === 1,
          has_differences: statement.balance_difference !== null &&
            Math.abs(parseFloat(statement.balance_difference)) >= 1,
          balance_difference: statement.balance_difference,
          statement_id: statement.id
        })
      } else {
        calendar.push({
          month,
          has_statement: false,
          is_reconciled: false,
          has_differences: false,
          balance_difference: null,
          statement_id: null
        })
      }
    }

    return c.json({ year, account_id: accountId, calendar })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/bank-statements/:id
app.delete('/api/bank-statements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const statementId = c.req.param('id')
    const DB = c.env.DB

    const statement = await DB.prepare(`
      SELECT bs.id
      FROM bank_statements bs
      JOIN bank_accounts a ON bs.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE bs.id = ? AND c.user_id = ?
    `).bind(statementId, user.userId).first()

    if (!statement) {
      return c.json({ error: 'Estado de cuenta no encontrado' }, 404)
    }

    // Desmarcar movimientos vinculados
    await DB.prepare(`
      UPDATE movements
      SET bank_statement_id = NULL,
          is_bank_matched = 0
      WHERE bank_statement_id = ?
    `).bind(statementId).run()

    // Eliminar estado de cuenta
    await DB.prepare(
      'DELETE FROM bank_statements WHERE id = ?'
    ).bind(statementId).run()

    return c.json({ success: true })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// FRONTEND - HTML
// ============================================

app.get('/', (c) => {
  return c.html(`
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Lyra Financial System</title>
  <link rel="stylesheet" href="/static/styles.css">
</head>
<body class="bg-gray-50">
  <div id="app" class="min-h-screen">
    <div class="max-w-7xl mx-auto px-4 py-8">
      <div class="text-center">
        <h1 class="text-4xl font-bold text-gray-900 mb-4">
          💼 Lyra Financial System
        </h1>
        <p class="text-xl text-gray-600 mb-8">
          Sistema de gestión financiera multi-empresa
        </p>

        <div class="bg-white rounded-lg shadow-lg p-8 max-w-md mx-auto">
          <h2 class="text-2xl font-bold mb-6">Iniciar Sesión</h2>

          <form id="loginForm" class="space-y-4">
            <div>
              <label class="label">Email</label>
              <input type="email" id="email" class="input" required>
            </div>

            <div>
              <label class="label">Contraseña</label>
              <input type="password" id="password" class="input" required>
            </div>

            <button type="submit" class="w-full btn btn-primary">
              Entrar
            </button>
          </form>

          <div class="mt-4">
            <a href="/register" class="text-blue-600 hover:underline">
              ¿No tienes cuenta? Regístrate
            </a>
          </div>

          <div id="message" class="mt-4"></div>
        </div>

        <div class="mt-12 bg-blue-50 rounded-lg p-6">
          <h3 class="text-lg font-bold mb-2">Estado del Proyecto</h3>
          <p class="text-sm text-gray-700">
            ✅ Setup inicial completo<br>
            ✅ Base de datos configurada<br>
            ✅ Autenticación JWT<br>
            ✅ CRUD Empresas<br>
            ✅ CRUD Cuentas Bancarias<br>
            ✅ CRUD Movimientos<br>
            ✅ Sistema de Transferencias<br>
            ⏳ Importación Excel (próximamente)<br>
            ⏳ Estados de Cuenta (próximamente)
          </p>
        </div>
      </div>
    </div>
  </div>

  <script>
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
      e.preventDefault()

      const email = document.getElementById('email').value
      const password = document.getElementById('password').value

      try {
        const res = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password })
        })

        const data = await res.json()

        if (data.success) {
          document.getElementById('message').innerHTML =
            '<div class="text-green-600">✅ Login exitoso. Redirigiendo...</div>'
          setTimeout(() => window.location.href = '/dashboard', 1000)
        } else {
          document.getElementById('message').innerHTML =
            '<div class="text-red-600">❌ ' + data.error + '</div>'
        }
      } catch (error) {
        document.getElementById('message').innerHTML =
          '<div class="text-red-600">❌ Error: ' + error.message + '</div>'
      }
    })
  </script>
</body>
</html>
  `)
})

// Servir archivos estáticos
app.use('/static/*', serveStatic({ root: './public' }))

export default app
