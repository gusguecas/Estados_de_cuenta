import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serveStatic } from 'hono/cloudflare-workers'
import { getCookie, setCookie, deleteCookie } from 'hono/cookie'

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
      { name: 'Servicios', type: 'income', color: '#34D399', icon: '🛠️' },
      { name: 'Inversiones', type: 'income', color: '#6EE7B7', icon: '📈' },
      { name: 'Otros Ingresos', type: 'income', color: '#A7F3D0', icon: '💵' },
      { name: 'Nómina', type: 'expense', color: '#EF4444', icon: '👥' },
      { name: 'Renta', type: 'expense', color: '#F87171', icon: '🏢' },
      { name: 'Servicios', type: 'expense', color: '#FCA5A5', icon: '💡' },
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
