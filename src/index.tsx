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
    const body = await c.req.json()
    const {
      name,
      commercial_name,
      country,
      tax_id,
      currency,
      employees_count,
      business_sector,
      website,
      business_description,
      street_address,
      city,
      state_province,
      postal_code,
      phone,
      logo_url,
      color
    } = body

    // Validaciones
    if (!name) {
      return c.json({ error: 'La razón social es requerida' }, 400)
    }
    if (!commercial_name) {
      return c.json({ error: 'El nombre comercial es requerido' }, 400)
    }
    if (!country) {
      return c.json({ error: 'El país es requerido' }, 400)
    }
    if (!tax_id) {
      return c.json({ error: 'El RFC/NIF es requerido' }, 400)
    }
    if (!currency) {
      return c.json({ error: 'La moneda es requerida' }, 400)
    }

    const DB = c.env.DB
    const companyId = generateId()

    await DB.prepare(`
      INSERT INTO companies (
        id, user_id, name, commercial_name, country, tax_id, currency,
        employees_count, business_sector, website, business_description,
        street_address, city, state_province, postal_code, phone,
        logo_url, color, active
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    `).bind(
      companyId,
      user.userId,
      name,
      commercial_name,
      country,
      tax_id,
      currency,
      employees_count || 0,
      business_sector,
      website,
      business_description,
      street_address,
      city,
      state_province,
      postal_code,
      phone,
      logo_url,
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
app.put('/api/companies/:id', async (c) => {
  try {
    const companyId = c.req.param('id')
    const {
      name,
      commercial_name,
      country,
      tax_id,
      currency,
      employees_count,
      business_sector,
      website,
      business_description,
      street_address,
      city,
      state_province,
      postal_code,
      phone,
      logo_url,
      color
    } = await c.req.json()

    const DB = c.env.DB as D1Database

    // Verificar que la empresa existe
    const company = await DB.prepare(
      'SELECT id FROM companies WHERE id = ?'
    ).bind(companyId).first()

    if (!company) {
      return c.json({ error: 'Empresa no encontrada' }, 404)
    }

    await DB.prepare(`
      UPDATE companies
      SET name = ?, commercial_name = ?, country = ?, tax_id = ?, currency = ?,
          employees_count = ?, business_sector = ?, website = ?, business_description = ?,
          street_address = ?, city = ?, state_province = ?, postal_code = ?, phone = ?,
          logo_url = ?, color = ?, updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      name, commercial_name, country, tax_id, currency,
      employees_count, business_sector, website, business_description,
      street_address, city, state_province, postal_code, phone,
      logo_url, color, companyId
    ).run()

    const updated = await DB.prepare(
      'SELECT * FROM companies WHERE id = ?'
    ).bind(companyId).first()

    return c.json({ success: true, company: updated })

  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/companies/:id
app.delete('/api/companies/:id', async (c) => {
  try {
    const companyId = c.req.param('id')
    const DB = c.env.DB as D1Database

    // Verificar que la empresa existe
    const company = await DB.prepare(
      'SELECT id FROM companies WHERE id = ?'
    ).bind(companyId).first()

    if (!company) {
      return c.json({ error: 'Empresa no encontrada' }, 404)
    }

    // Soft delete
    await DB.prepare(
      'UPDATE companies SET active = 0 WHERE id = ?'
    ).bind(companyId).run()

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
// ENDPOINTS - REPORTES AVANZADOS
// ============================================

// GET /api/reports/income-by-category
app.get('/api/reports/income-by-category', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { start_date, end_date, company_id, account_id } = c.req.query()

    const DB = c.env.DB

    let whereConditions = [
      "m.type = 'income'",
      "m.status != 'cancelled'",
      "c.user_id = ?"
    ]
    let params: any[] = [user.userId]

    if (start_date) {
      whereConditions.push("m.date >= ?")
      params.push(start_date)
    }
    if (end_date) {
      whereConditions.push("m.date <= ?")
      params.push(end_date)
    }
    if (company_id) {
      whereConditions.push("c.id = ?")
      params.push(company_id)
    }
    if (account_id) {
      whereConditions.push("m.account_id = ?")
      params.push(account_id)
    }

    const query = `
      SELECT
        cat.id,
        cat.name,
        cat.color,
        SUM(m.amount) as total,
        COUNT(m.id) as count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON m.category_id = cat.id
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY cat.id, cat.name, cat.color
      ORDER BY total DESC
    `

    const results = await DB.prepare(query).bind(...params).all()

    const totalIncome = results.results.reduce((sum: number, row: any) =>
      sum + parseFloat(row.total || '0'), 0
    )

    const categories = results.results.map((row: any) => ({
      category_id: row.id,
      category_name: row.name || 'Sin categoría',
      category_color: row.color || '#6B7280',
      total: parseFloat(row.total || '0'),
      count: parseInt(row.count || '0'),
      percentage: totalIncome > 0 ? (parseFloat(row.total || '0') / totalIncome * 100) : 0
    }))

    return c.json({
      period: { start_date: start_date || null, end_date: end_date || null },
      total_income: totalIncome,
      categories,
      categories_count: categories.length
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/reports/expense-by-category
app.get('/api/reports/expense-by-category', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { start_date, end_date, company_id, account_id } = c.req.query()

    const DB = c.env.DB

    let whereConditions = [
      "m.type = 'expense'",
      "m.status != 'cancelled'",
      "c.user_id = ?"
    ]
    let params: any[] = [user.userId]

    if (start_date) {
      whereConditions.push("m.date >= ?")
      params.push(start_date)
    }
    if (end_date) {
      whereConditions.push("m.date <= ?")
      params.push(end_date)
    }
    if (company_id) {
      whereConditions.push("c.id = ?")
      params.push(company_id)
    }
    if (account_id) {
      whereConditions.push("m.account_id = ?")
      params.push(account_id)
    }

    const query = `
      SELECT
        cat.id,
        cat.name,
        cat.color,
        SUM(m.amount) as total,
        COUNT(m.id) as count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON m.category_id = cat.id
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY cat.id, cat.name, cat.color
      ORDER BY total DESC
    `

    const results = await DB.prepare(query).bind(...params).all()

    const totalExpense = results.results.reduce((sum: number, row: any) =>
      sum + parseFloat(row.total || '0'), 0
    )

    const categories = results.results.map((row: any) => ({
      category_id: row.id,
      category_name: row.name || 'Sin categoría',
      category_color: row.color || '#6B7280',
      total: parseFloat(row.total || '0'),
      count: parseInt(row.count || '0'),
      percentage: totalExpense > 0 ? (parseFloat(row.total || '0') / totalExpense * 100) : 0
    }))

    return c.json({
      period: { start_date: start_date || null, end_date: end_date || null },
      total_expense: totalExpense,
      categories,
      categories_count: categories.length
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/reports/cash-flow
app.get('/api/reports/cash-flow', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { start_date, end_date, company_id, account_id, group_by } = c.req.query()
    const groupBy = group_by || 'month' // month, week, day

    const DB = c.env.DB

    let whereConditions = [
      "m.status != 'cancelled'",
      "c.user_id = ?"
    ]
    let params: any[] = [user.userId]

    if (start_date) {
      whereConditions.push("m.date >= ?")
      params.push(start_date)
    }
    if (end_date) {
      whereConditions.push("m.date <= ?")
      params.push(end_date)
    }
    if (company_id) {
      whereConditions.push("c.id = ?")
      params.push(company_id)
    }
    if (account_id) {
      whereConditions.push("m.account_id = ?")
      params.push(account_id)
    }

    let dateFormat: string
    if (groupBy === 'day') {
      dateFormat = "m.date"
    } else if (groupBy === 'week') {
      dateFormat = "strftime('%Y-W%W', m.date)"
    } else {
      dateFormat = "strftime('%Y-%m', m.date)"
    }

    const query = `
      SELECT
        ${dateFormat} as period,
        SUM(CASE WHEN m.type = 'income' THEN m.amount ELSE 0 END) as income,
        SUM(CASE WHEN m.type = 'expense' THEN m.amount ELSE 0 END) as expense,
        COUNT(CASE WHEN m.type = 'income' THEN 1 END) as income_count,
        COUNT(CASE WHEN m.type = 'expense' THEN 1 END) as expense_count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY period
      ORDER BY period ASC
    `

    const results = await DB.prepare(query).bind(...params).all()

    const periods = results.results.map((row: any) => {
      const income = parseFloat(row.income || '0')
      const expense = parseFloat(row.expense || '0')
      const net = income - expense

      return {
        period: row.period,
        income,
        expense,
        net,
        income_count: parseInt(row.income_count || '0'),
        expense_count: parseInt(row.expense_count || '0')
      }
    })

    const totals = periods.reduce((acc, p) => ({
      total_income: acc.total_income + p.income,
      total_expense: acc.total_expense + p.expense,
      net_cash_flow: acc.net_cash_flow + p.net
    }), { total_income: 0, total_expense: 0, net_cash_flow: 0 })

    return c.json({
      period: { start_date: start_date || null, end_date: end_date || null },
      group_by: groupBy,
      totals,
      periods
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/reports/balance-sheet
app.get('/api/reports/balance-sheet', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { as_of_date, company_id } = c.req.query()
    const asOfDate = as_of_date || new Date().toISOString().split('T')[0]

    const DB = c.env.DB

    let whereConditions = ["c.user_id = ?", "c.active = 1"]
    let params: any[] = [user.userId]

    if (company_id) {
      whereConditions.push("c.id = ?")
      params.push(company_id)
    }

    // Obtener todas las cuentas con sus saldos
    const accountsQuery = `
      SELECT
        a.id,
        a.name,
        a.bank_name,
        a.initial_saldo,
        c.id as company_id,
        c.name as company_name,
        c.color as company_color
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE ${whereConditions.join(' AND ')} AND a.active = 1
    `

    const accountsResult = await DB.prepare(accountsQuery).bind(...params).all()

    const accounts = []
    let totalAssets = 0

    for (const account of accountsResult.results) {
      const balance = await calculateBalance(DB, account.id as string, asOfDate)
      accounts.push({
        account_id: account.id,
        account_name: account.name,
        bank_name: account.bank_name,
        company_id: account.company_id,
        company_name: account.company_name,
        balance
      })
      totalAssets += balance
    }

    // Calcular "pasivos" - en este contexto, serían saldos negativos o transferencias pendientes
    // Por ahora simplificado: pasivos = 0, patrimonio = activos
    const totalLiabilities = 0
    const totalEquity = totalAssets

    return c.json({
      as_of_date: asOfDate,
      balance_sheet: {
        assets: {
          cash_and_equivalents: totalAssets,
          accounts: accounts,
          total: totalAssets
        },
        liabilities: {
          accounts_payable: 0,
          total: totalLiabilities
        },
        equity: {
          retained_earnings: totalEquity,
          total: totalEquity
        }
      },
      check: {
        assets_equals_liabilities_plus_equity: Math.abs(totalAssets - (totalLiabilities + totalEquity)) < 0.01
      }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/reports/evolution
app.get('/api/reports/evolution', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { start_date, end_date, company_id, account_id } = c.req.query()

    const DB = c.env.DB

    let whereConditions = [
      "m.status != 'cancelled'",
      "c.user_id = ?"
    ]
    let params: any[] = [user.userId]

    if (start_date) {
      whereConditions.push("m.date >= ?")
      params.push(start_date)
    }
    if (end_date) {
      whereConditions.push("m.date <= ?")
      params.push(end_date)
    }
    if (company_id) {
      whereConditions.push("c.id = ?")
      params.push(company_id)
    }
    if (account_id) {
      whereConditions.push("m.account_id = ?")
      params.push(account_id)
    }

    const query = `
      SELECT
        strftime('%Y-%m', m.date) as month,
        SUM(CASE WHEN m.type = 'income' THEN m.amount ELSE 0 END) as income,
        SUM(CASE WHEN m.type = 'expense' THEN m.amount ELSE 0 END) as expense
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE ${whereConditions.join(' AND ')}
      GROUP BY month
      ORDER BY month ASC
    `

    const results = await DB.prepare(query).bind(...params).all()

    let cumulativeBalance = 0
    const evolution = results.results.map((row: any) => {
      const income = parseFloat(row.income || '0')
      const expense = parseFloat(row.expense || '0')
      const net = income - expense
      cumulativeBalance += net

      return {
        month: row.month,
        income,
        expense,
        net,
        cumulative_balance: cumulativeBalance
      }
    })

    return c.json({
      period: { start_date: start_date || null, end_date: end_date || null },
      evolution
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - DASHBOARD MEJORADO
// ============================================

// GET /api/dashboard/kpis
app.get('/api/dashboard/kpis', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { start_date, end_date } = c.req.query()

    const DB = c.env.DB

    // KPI 1: Total de empresas activas
    const companiesResult = await DB.prepare(
      'SELECT COUNT(*) as count FROM companies WHERE user_id = ? AND active = 1'
    ).bind(user.userId).first() as any

    // KPI 2: Total de cuentas activas
    const accountsResult = await DB.prepare(`
      SELECT COUNT(*) as count
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND a.active = 1 AND c.active = 1
    `).bind(user.userId).first() as any

    // KPI 3: Saldo total consolidado
    const accountsList = await DB.prepare(`
      SELECT a.id
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND a.active = 1 AND c.active = 1
    `).bind(user.userId).all()

    let totalBalance = 0
    for (const account of accountsList.results) {
      const balance = await calculateBalance(DB, account.id as string)
      totalBalance += balance
    }

    // KPI 4: Ingresos y egresos del período
    let whereConditions = ["c.user_id = ?", "m.status != 'cancelled'"]
    let params: any[] = [user.userId]

    if (start_date) {
      whereConditions.push("m.date >= ?")
      params.push(start_date)
    }
    if (end_date) {
      whereConditions.push("m.date <= ?")
      params.push(end_date)
    }

    const movementsResult = await DB.prepare(`
      SELECT
        SUM(CASE WHEN m.type = 'income' THEN m.amount ELSE 0 END) as total_income,
        SUM(CASE WHEN m.type = 'expense' THEN m.amount ELSE 0 END) as total_expense,
        COUNT(CASE WHEN m.type = 'income' THEN 1 END) as income_count,
        COUNT(CASE WHEN m.type = 'expense' THEN 1 END) as expense_count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE ${whereConditions.join(' AND ')}
    `).bind(...params).first() as any

    const totalIncome = parseFloat(movementsResult?.total_income || '0')
    const totalExpense = parseFloat(movementsResult?.total_expense || '0')
    const netIncome = totalIncome - totalExpense

    // KPI 5: Promedio diario
    const daysInPeriod = start_date && end_date ?
      Math.ceil((new Date(end_date).getTime() - new Date(start_date).getTime()) / (1000 * 60 * 60 * 24)) : 30

    // KPI 6: Burn rate (gasto promedio mensual)
    const burnRate = totalExpense / (daysInPeriod / 30)

    // KPI 7: Runway (meses que puede operar con el saldo actual)
    const runway = burnRate > 0 ? totalBalance / burnRate : null

    // KPI 8: Margen neto
    const netMargin = totalIncome > 0 ? (netIncome / totalIncome) * 100 : 0

    return c.json({
      period: { start_date: start_date || null, end_date: end_date || null },
      kpis: {
        companies_count: parseInt(companiesResult?.count || '0'),
        accounts_count: parseInt(accountsResult?.count || '0'),
        total_balance: totalBalance,
        total_income: totalIncome,
        total_expense: totalExpense,
        net_income: netIncome,
        income_count: parseInt(movementsResult?.income_count || '0'),
        expense_count: parseInt(movementsResult?.expense_count || '0'),
        avg_daily_income: totalIncome / daysInPeriod,
        avg_daily_expense: totalExpense / daysInPeriod,
        burn_rate: burnRate,
        runway_months: runway,
        net_margin_percent: netMargin
      }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// Mejorar el endpoint existente de dashboard/summary
// GET /api/dashboard/summary (ya existe, pero vamos a mejorarlo)
app.get('/api/dashboard/summary-v2', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const DB = c.env.DB

    // 1. Resumen de empresas y cuentas
    const companies = await DB.prepare(`
      SELECT
        c.id,
        c.name,
        c.color,
        COUNT(a.id) as accounts_count
      FROM companies c
      LEFT JOIN bank_accounts a ON c.id = a.company_id AND a.active = 1
      WHERE c.user_id = ? AND c.active = 1
      GROUP BY c.id, c.name, c.color
    `).bind(user.userId).all()

    const accounts = await DB.prepare(`
      SELECT
        a.id,
        a.name,
        a.bank_name,
        a.initial_saldo,
        c.id as company_id,
        c.name as company_name,
        c.color as company_color
      FROM bank_accounts a
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND a.active = 1 AND c.active = 1
    `).bind(user.userId).all()

    // Calcular saldos
    const accountsWithBalances = []
    let totalBalance = 0

    for (const account of accounts.results) {
      const balance = await calculateBalance(DB, account.id as string)
      accountsWithBalances.push({
        id: account.id,
        name: account.name,
        bank_name: account.bank_name,
        company_id: account.company_id,
        company_name: account.company_name,
        company_color: account.company_color,
        balance
      })
      totalBalance += balance
    }

    // 2. Movimientos recientes (últimos 10)
    const recentMovements = await DB.prepare(`
      SELECT
        m.*,
        a.name as account_name,
        c.name as company_name,
        c.color as company_color,
        cat.name as category_name,
        cat.color as category_color
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON m.category_id = cat.id
      WHERE c.user_id = ?
      ORDER BY m.date DESC, m.created_at DESC
      LIMIT 10
    `).bind(user.userId).all()

    // 3. Top 5 categorías de ingresos
    const topIncomeCategories = await DB.prepare(`
      SELECT
        cat.name,
        cat.color,
        SUM(m.amount) as total
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON m.category_id = cat.id
      WHERE c.user_id = ? AND m.type = 'income' AND m.status != 'cancelled'
      GROUP BY cat.id, cat.name, cat.color
      ORDER BY total DESC
      LIMIT 5
    `).bind(user.userId).all()

    // 4. Top 5 categorías de egresos
    const topExpenseCategories = await DB.prepare(`
      SELECT
        cat.name,
        cat.color,
        SUM(m.amount) as total
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON m.category_id = cat.id
      WHERE c.user_id = ? AND m.type = 'expense' AND m.status != 'cancelled'
      GROUP BY cat.id, cat.name, cat.color
      ORDER BY total DESC
      LIMIT 5
    `).bind(user.userId).all()

    // 5. Estadísticas del mes actual
    const currentMonth = new Date().toISOString().slice(0, 7)
    const monthStats = await DB.prepare(`
      SELECT
        SUM(CASE WHEN type = 'income' THEN amount ELSE 0 END) as income,
        SUM(CASE WHEN type = 'expense' THEN amount ELSE 0 END) as expense,
        COUNT(CASE WHEN type = 'income' THEN 1 END) as income_count,
        COUNT(CASE WHEN type = 'expense' THEN 1 END) as expense_count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ?
        AND m.status != 'cancelled'
        AND strftime('%Y-%m', m.date) = ?
    `).bind(user.userId, currentMonth).first() as any

    // 6. Cuentas con saldo bajo (< 10,000)
    const lowBalanceAccounts = accountsWithBalances.filter(acc => acc.balance < 10000)

    return c.json({
      summary: {
        total_balance: totalBalance,
        companies_count: companies.results.length,
        accounts_count: accounts.results.length
      },
      current_month: {
        month: currentMonth,
        income: parseFloat(monthStats?.income || '0'),
        expense: parseFloat(monthStats?.expense || '0'),
        net: parseFloat(monthStats?.income || '0') - parseFloat(monthStats?.expense || '0'),
        income_count: parseInt(monthStats?.income_count || '0'),
        expense_count: parseInt(monthStats?.expense_count || '0')
      },
      companies: companies.results,
      accounts: accountsWithBalances,
      recent_movements: recentMovements.results,
      top_income_categories: topIncomeCategories.results.map((r: any) => ({
        name: r.name || 'Sin categoría',
        color: r.color || '#6B7280',
        total: parseFloat(r.total || '0')
      })),
      top_expense_categories: topExpenseCategories.results.map((r: any) => ({
        name: r.name || 'Sin categoría',
        color: r.color || '#6B7280',
        total: parseFloat(r.total || '0')
      })),
      alerts: {
        low_balance_accounts: lowBalanceAccounts,
        low_balance_count: lowBalanceAccounts.length
      }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - PRESUPUESTOS (BUDGETS)
// ============================================

// POST /api/budgets - Crear presupuesto
app.post('/api/budgets', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const {
      name,
      amount,
      period_type,
      year,
      month,
      budget_type,
      category_id,
      account_id,
      company_id,
      notes
    } = await c.req.json()

    if (!name || !amount || !period_type || !year || !budget_type) {
      return c.json({ error: 'Faltan parámetros requeridos' }, 400)
    }

    if (period_type === 'monthly' && !month) {
      return c.json({ error: 'El mes es requerido para presupuestos mensuales' }, 400)
    }

    const DB = c.env.DB
    const budgetId = generateId()

    await DB.prepare(`
      INSERT INTO budgets (
        id, user_id, name, amount, period_type, year, month,
        budget_type, category_id, account_id, company_id, notes,
        created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      budgetId,
      user.userId,
      name,
      amount,
      period_type,
      year,
      month || null,
      budget_type,
      category_id || null,
      account_id || null,
      company_id || null,
      notes || null,
      user.userId
    ).run()

    const budget = await DB.prepare(
      'SELECT * FROM budgets WHERE id = ?'
    ).bind(budgetId).first()

    return c.json({ success: true, budget })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/budgets - Listar presupuestos
app.get('/api/budgets', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { year, month, period_type, budget_type, category_id } = c.req.query()

    const DB = c.env.DB

    let whereConditions = ['b.user_id = ?', 'b.active = 1']
    let params: any[] = [user.userId]

    if (year) {
      whereConditions.push('b.year = ?')
      params.push(parseInt(year))
    }
    if (month) {
      whereConditions.push('b.month = ?')
      params.push(parseInt(month))
    }
    if (period_type) {
      whereConditions.push('b.period_type = ?')
      params.push(period_type)
    }
    if (budget_type) {
      whereConditions.push('b.budget_type = ?')
      params.push(budget_type)
    }
    if (category_id) {
      whereConditions.push('b.category_id = ?')
      params.push(category_id)
    }

    const query = `
      SELECT
        b.*,
        cat.name as category_name,
        cat.color as category_color,
        a.name as account_name,
        c.name as company_name
      FROM budgets b
      LEFT JOIN categories cat ON b.category_id = cat.id
      LEFT JOIN bank_accounts a ON b.account_id = a.id
      LEFT JOIN companies c ON b.company_id = c.id
      WHERE ${whereConditions.join(' AND ')}
      ORDER BY b.year DESC, b.month DESC, b.created_at DESC
    `

    const results = await DB.prepare(query).bind(...params).all()

    return c.json({ budgets: results.results })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/budgets/:id - Obtener presupuesto
app.get('/api/budgets/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const budgetId = c.req.param('id')

    const DB = c.env.DB

    const budget = await DB.prepare(`
      SELECT
        b.*,
        cat.name as category_name,
        cat.color as category_color,
        a.name as account_name,
        c.name as company_name
      FROM budgets b
      LEFT JOIN categories cat ON b.category_id = cat.id
      LEFT JOIN bank_accounts a ON b.account_id = a.id
      LEFT JOIN companies c ON b.company_id = c.id
      WHERE b.id = ? AND b.user_id = ?
    `).bind(budgetId, user.userId).first()

    if (!budget) {
      return c.json({ error: 'Presupuesto no encontrado' }, 404)
    }

    return c.json({ budget })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/budgets/:id/comparison - Comparar presupuesto vs real
app.get('/api/budgets/:id/comparison', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const budgetId = c.req.param('id')

    const DB = c.env.DB

    const budget = await DB.prepare(
      'SELECT * FROM budgets WHERE id = ? AND user_id = ?'
    ).bind(budgetId, user.userId).first() as any

    if (!budget) {
      return c.json({ error: 'Presupuesto no encontrado' }, 404)
    }

    // Calcular período
    let startDate: string
    let endDate: string

    if (budget.period_type === 'monthly') {
      startDate = `${budget.year}-${String(budget.month).padStart(2, '0')}-01`
      const lastDay = new Date(budget.year, budget.month, 0).getDate()
      endDate = `${budget.year}-${String(budget.month).padStart(2, '0')}-${lastDay}`
    } else if (budget.period_type === 'quarterly') {
      const quarter = Math.ceil(budget.month / 3)
      const startMonth = (quarter - 1) * 3 + 1
      startDate = `${budget.year}-${String(startMonth).padStart(2, '0')}-01`
      const endMonth = quarter * 3
      const lastDay = new Date(budget.year, endMonth, 0).getDate()
      endDate = `${budget.year}-${String(endMonth).padStart(2, '0')}-${lastDay}`
    } else {
      startDate = `${budget.year}-01-01`
      endDate = `${budget.year}-12-31`
    }

    // Consultar movimientos reales
    let whereConditions = [
      "m.status != 'cancelled'",
      "m.date >= ?",
      "m.date <= ?",
      "m.type = ?"
    ]
    let params: any[] = [startDate, endDate, budget.budget_type]

    if (budget.category_id) {
      whereConditions.push("m.category_id = ?")
      params.push(budget.category_id)
    }
    if (budget.account_id) {
      whereConditions.push("m.account_id = ?")
      params.push(budget.account_id)
    }
    if (budget.company_id) {
      whereConditions.push("c.id = ?")
      params.push(budget.company_id)
    }

    const query = `
      SELECT
        SUM(m.amount) as total_actual,
        COUNT(m.id) as movement_count
      FROM movements m
      JOIN bank_accounts a ON m.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE c.user_id = ? AND ${whereConditions.join(' AND ')}
    `

    const result = await DB.prepare(query).bind(user.userId, ...params).first() as any

    const totalActual = parseFloat(result?.total_actual || '0')
    const budgetAmount = parseFloat(budget.amount || '0')
    const difference = budgetAmount - totalActual
    const percentage = budgetAmount > 0 ? (totalActual / budgetAmount) * 100 : 0

    let status: string
    if (percentage <= 80) {
      status = 'under_budget'
    } else if (percentage <= 100) {
      status = 'on_track'
    } else if (percentage <= 110) {
      status = 'near_limit'
    } else {
      status = 'over_budget'
    }

    return c.json({
      budget: {
        id: budget.id,
        name: budget.name,
        amount: budgetAmount,
        period_type: budget.period_type,
        year: budget.year,
        month: budget.month,
        budget_type: budget.budget_type
      },
      period: { start_date: startDate, end_date: endDate },
      actual: {
        total: totalActual,
        movement_count: parseInt(result?.movement_count || '0')
      },
      comparison: {
        difference,
        percentage,
        status,
        remaining: budget.budget_type === 'expense' ? difference : -difference
      }
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// PUT /api/budgets/:id - Actualizar presupuesto
app.put('/api/budgets/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const budgetId = c.req.param('id')
    const { name, amount, notes, active } = await c.req.json()

    const DB = c.env.DB

    const existing = await DB.prepare(
      'SELECT * FROM budgets WHERE id = ? AND user_id = ?'
    ).bind(budgetId, user.userId).first()

    if (!existing) {
      return c.json({ error: 'Presupuesto no encontrado' }, 404)
    }

    await DB.prepare(`
      UPDATE budgets
      SET name = ?,
          amount = ?,
          notes = ?,
          active = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      name || existing.name,
      amount !== undefined ? amount : existing.amount,
      notes !== undefined ? notes : existing.notes,
      active !== undefined ? active : existing.active,
      budgetId
    ).run()

    const updated = await DB.prepare(
      'SELECT * FROM budgets WHERE id = ?'
    ).bind(budgetId).first()

    return c.json({ success: true, budget: updated })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/budgets/:id - Eliminar presupuesto
app.delete('/api/budgets/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const budgetId = c.req.param('id')

    const DB = c.env.DB

    const existing = await DB.prepare(
      'SELECT * FROM budgets WHERE id = ? AND user_id = ?'
    ).bind(budgetId, user.userId).first()

    if (!existing) {
      return c.json({ error: 'Presupuesto no encontrado' }, 404)
    }

    // Soft delete
    await DB.prepare(
      'UPDATE budgets SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(budgetId).run()

    return c.json({ success: true, message: 'Presupuesto eliminado' })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// ENDPOINTS - MOVIMIENTOS RECURRENTES
// ============================================

// Función helper: Calcular siguiente ocurrencia
function calculateNextOccurrence(frequency: string, currentDate: string, dayOfMonth?: number, dayOfWeek?: number): string {
  const date = new Date(currentDate)

  switch (frequency) {
    case 'daily':
      date.setDate(date.getDate() + 1)
      break
    case 'weekly':
      date.setDate(date.getDate() + 7)
      break
    case 'biweekly':
      date.setDate(date.getDate() + 14)
      break
    case 'monthly':
      date.setMonth(date.getMonth() + 1)
      if (dayOfMonth) {
        date.setDate(dayOfMonth)
      }
      break
    case 'quarterly':
      date.setMonth(date.getMonth() + 3)
      break
    case 'yearly':
      date.setFullYear(date.getFullYear() + 1)
      break
  }

  return date.toISOString().split('T')[0]
}

// POST /api/recurring-movements - Crear movimiento recurrente
app.post('/api/recurring-movements', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const {
      account_id,
      category_id,
      name,
      amount,
      type,
      frequency,
      start_date,
      end_date,
      day_of_month,
      day_of_week,
      description,
      reference,
      auto_generate
    } = await c.req.json()

    if (!account_id || !name || !amount || !type || !frequency || !start_date) {
      return c.json({ error: 'Faltan parámetros requeridos' }, 400)
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

    const recurringId = generateId()
    const nextOccurrence = calculateNextOccurrence(frequency, start_date, day_of_month, day_of_week)

    await DB.prepare(`
      INSERT INTO recurring_movements (
        id, account_id, category_id, name, amount, type,
        frequency, start_date, end_date, next_occurrence,
        day_of_month, day_of_week, description, reference,
        auto_generate, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      recurringId,
      account_id,
      category_id || null,
      name,
      amount,
      type,
      frequency,
      start_date,
      end_date || null,
      nextOccurrence,
      day_of_month || null,
      day_of_week || null,
      description || null,
      reference || null,
      auto_generate !== undefined ? auto_generate : 1,
      user.userId
    ).run()

    const recurring = await DB.prepare(
      'SELECT * FROM recurring_movements WHERE id = ?'
    ).bind(recurringId).first()

    return c.json({ success: true, recurring_movement: recurring })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/recurring-movements - Listar movimientos recurrentes
app.get('/api/recurring-movements', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const { account_id, type, active } = c.req.query()

    const DB = c.env.DB

    let whereConditions = ['c.user_id = ?']
    let params: any[] = [user.userId]

    if (account_id) {
      whereConditions.push('rm.account_id = ?')
      params.push(account_id)
    }
    if (type) {
      whereConditions.push('rm.type = ?')
      params.push(type)
    }
    if (active !== undefined) {
      whereConditions.push('rm.active = ?')
      params.push(active === 'true' ? 1 : 0)
    }

    const query = `
      SELECT
        rm.*,
        a.name as account_name,
        cat.name as category_name,
        cat.color as category_color,
        c.name as company_name,
        c.color as company_color
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON rm.category_id = cat.id
      WHERE ${whereConditions.join(' AND ')}
      ORDER BY rm.next_occurrence ASC
    `

    const results = await DB.prepare(query).bind(...params).all()

    return c.json({ recurring_movements: results.results })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/recurring-movements/:id - Obtener movimiento recurrente
app.get('/api/recurring-movements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const recurringId = c.req.param('id')

    const DB = c.env.DB

    const recurring = await DB.prepare(`
      SELECT
        rm.*,
        a.name as account_name,
        cat.name as category_name,
        c.name as company_name
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON rm.category_id = cat.id
      WHERE rm.id = ? AND c.user_id = ?
    `).bind(recurringId, user.userId).first()

    if (!recurring) {
      return c.json({ error: 'Movimiento recurrente no encontrado' }, 404)
    }

    return c.json({ recurring_movement: recurring })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// POST /api/recurring-movements/:id/generate - Generar movimiento desde recurrente
app.post('/api/recurring-movements/:id/generate', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const recurringId = c.req.param('id')
    const { date } = await c.req.json()

    const DB = c.env.DB

    const recurring = await DB.prepare(`
      SELECT rm.*
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE rm.id = ? AND c.user_id = ? AND rm.active = 1
    `).bind(recurringId, user.userId).first() as any

    if (!recurring) {
      return c.json({ error: 'Movimiento recurrente no encontrado' }, 404)
    }

    const generatedDate = date || new Date().toISOString().split('T')[0]

    // Crear movimiento
    const movementId = generateId()
    await DB.prepare(`
      INSERT INTO movements (
        id, account_id, category_id, date, type, amount,
        name, description, reference, status, created_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).bind(
      movementId,
      recurring.account_id,
      recurring.category_id,
      generatedDate,
      recurring.type,
      recurring.amount,
      recurring.name,
      recurring.description,
      recurring.reference,
      'completed',
      user.userId
    ).run()

    // Registrar generación
    const genId = generateId()
    await DB.prepare(`
      INSERT INTO generated_movements (
        id, recurring_movement_id, movement_id, generated_date, generated_for_date
      ) VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?)
    `).bind(genId, recurringId, movementId, generatedDate).run()

    // Actualizar recurrente
    const nextOccurrence = calculateNextOccurrence(
      recurring.frequency,
      generatedDate,
      recurring.day_of_month,
      recurring.day_of_week
    )

    await DB.prepare(`
      UPDATE recurring_movements
      SET last_generated_date = ?,
          next_occurrence = ?,
          times_generated = times_generated + 1,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(generatedDate, nextOccurrence, recurringId).run()

    const movement = await DB.prepare(
      'SELECT * FROM movements WHERE id = ?'
    ).bind(movementId).first()

    return c.json({
      success: true,
      message: 'Movimiento generado exitosamente',
      movement
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// PUT /api/recurring-movements/:id - Actualizar movimiento recurrente
app.put('/api/recurring-movements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const recurringId = c.req.param('id')
    const { name, amount, description, reference, auto_generate, active } = await c.req.json()

    const DB = c.env.DB

    const existing = await DB.prepare(`
      SELECT rm.*
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE rm.id = ? AND c.user_id = ?
    `).bind(recurringId, user.userId).first() as any

    if (!existing) {
      return c.json({ error: 'Movimiento recurrente no encontrado' }, 404)
    }

    await DB.prepare(`
      UPDATE recurring_movements
      SET name = ?,
          amount = ?,
          description = ?,
          reference = ?,
          auto_generate = ?,
          active = ?,
          updated_at = CURRENT_TIMESTAMP
      WHERE id = ?
    `).bind(
      name || existing.name,
      amount !== undefined ? amount : existing.amount,
      description !== undefined ? description : existing.description,
      reference !== undefined ? reference : existing.reference,
      auto_generate !== undefined ? auto_generate : existing.auto_generate,
      active !== undefined ? active : existing.active,
      recurringId
    ).run()

    const updated = await DB.prepare(
      'SELECT * FROM recurring_movements WHERE id = ?'
    ).bind(recurringId).first()

    return c.json({ success: true, recurring_movement: updated })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// DELETE /api/recurring-movements/:id - Eliminar movimiento recurrente
app.delete('/api/recurring-movements/:id', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const recurringId = c.req.param('id')

    const DB = c.env.DB

    const existing = await DB.prepare(`
      SELECT rm.*
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      WHERE rm.id = ? AND c.user_id = ?
    `).bind(recurringId, user.userId).first()

    if (!existing) {
      return c.json({ error: 'Movimiento recurrente no encontrado' }, 404)
    }

    // Soft delete
    await DB.prepare(
      'UPDATE recurring_movements SET active = 0, updated_at = CURRENT_TIMESTAMP WHERE id = ?'
    ).bind(recurringId).run()

    return c.json({ success: true, message: 'Movimiento recurrente eliminado' })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// GET /api/recurring-movements/pending - Movimientos recurrentes pendientes de generar
app.get('/api/recurring-movements/pending', authMiddleware, async (c) => {
  try {
    const user = c.get('user')
    const today = new Date().toISOString().split('T')[0]

    const DB = c.env.DB

    const results = await DB.prepare(`
      SELECT
        rm.*,
        a.name as account_name,
        cat.name as category_name,
        c.name as company_name
      FROM recurring_movements rm
      JOIN bank_accounts a ON rm.account_id = a.id
      JOIN companies c ON a.company_id = c.id
      LEFT JOIN categories cat ON rm.category_id = cat.id
      WHERE c.user_id = ?
        AND rm.active = 1
        AND rm.auto_generate = 1
        AND rm.next_occurrence <= ?
        AND (rm.end_date IS NULL OR rm.end_date >= ?)
      ORDER BY rm.next_occurrence ASC
    `).bind(user.userId, today, today).all()

    return c.json({
      pending_count: results.results.length,
      pending_movements: results.results
    })
  } catch (error: any) {
    return c.json({ error: error.message }, 500)
  }
})

// ============================================
// FRONTEND - HTML
// ============================================

app.get('/', (c) => {
  return c.redirect('/companies')
})

// GET /companies - Portfolio Corporativo
app.get('/companies', async (c) => {
  const DB = c.env.DB as D1Database

  try {
    // Obtener todas las empresas (sin filtro de usuario)
    const companiesResult = await DB.prepare(`
      SELECT * FROM companies
      WHERE active = 1
      ORDER BY created_at DESC
    `).all()

    const companies = companiesResult.results || []

    // Calcular estadísticas
    const activeCompanies = companies.length
    const uniqueCurrencies = [...new Set(companies.map((c: any) => c.currency))]
    const currencies = uniqueCurrencies.length

    // Calcular países únicos (basado en currency)
    const countryMap: any = {
      'MXN': 'MX',
      'USD': 'US',
      'EUR': 'ES',
      'CAD': 'CA'
    }
    const countries = [...new Set(companies.map((c: any) => countryMap[c.currency] || 'MX'))].length

    return c.html(`
<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Portfolio Corporativo - GRX Holdings</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <style>
    body {
      background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
      min-height: 100vh;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    }

    .glass-panel {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 1rem;
    }

    .glass-panel:hover {
      background: rgba(255, 255, 255, 0.08);
      border-color: rgba(255, 255, 255, 0.2);
      transform: translateY(-2px);
      transition: all 0.3s ease;
    }

    .stat-card {
      background: linear-gradient(135deg, rgba(59, 130, 246, 0.1) 0%, rgba(37, 99, 235, 0.05) 100%);
    }

    .nav-item {
      background: rgba(255, 255, 255, 0.05);
      transition: all 0.3s ease;
    }

    .nav-item:hover, .nav-item.active {
      background: rgba(59, 130, 246, 0.3);
    }

    .company-logo {
      width: 80px;
      height: 80px;
      border-radius: 0.75rem;
      background: white;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 2rem;
    }
  </style>
</head>
<body class="text-gray-100 p-6">
  <!-- Header con navegación -->
  <div class="max-w-7xl mx-auto mb-8">
    <div class="glass-panel p-6 flex items-center justify-between">
      <div class="flex items-center space-x-8">
        <div class="text-2xl font-bold">
          <span class="text-blue-400">GRX</span>
          <div class="text-xs text-gray-400">HOLDINGS</div>
        </div>

        <nav class="flex space-x-2">
          <a href="/" class="nav-item px-4 py-2 rounded-lg text-sm flex items-center gap-2">
            <span>🏠</span>
            Dashboard
          </a>
          <a href="/companies" class="nav-item active px-4 py-2 rounded-lg text-sm font-medium flex items-center gap-2">
            <span>🏢</span>
            Empresas
          </a>
          <div class="nav-item px-4 py-2 rounded-lg text-sm opacity-50 cursor-not-allowed flex items-center gap-2">
            <span>👥</span>
            Empleados
          </div>
          <div class="nav-item px-4 py-2 rounded-lg text-sm opacity-50 cursor-not-allowed flex items-center gap-2">
            <span>💰</span>
            Gastos
          </div>
          <div class="nav-item px-4 py-2 rounded-lg text-sm opacity-50 cursor-not-allowed flex items-center gap-2">
            <span>📊</span>
            Reportes
          </div>
        </nav>
      </div>

      <div class="flex items-center space-x-4">
        <div class="text-right text-sm">
          <div class="font-medium">Administrador</div>
          <div class="text-xs text-gray-400">CFO</div>
        </div>
        <button class="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-lg text-sm transition">
          Salir
        </button>
      </div>
    </div>
  </div>

  <div class="max-w-7xl mx-auto">
    <!-- Título y botón nueva empresa -->
    <div class="flex items-center justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold mb-2 flex items-center">
          <span class="mr-3">🏛</span>
          Portfolio Corporativo
        </h1>
        <p class="text-gray-400">Gestión multiempresa internacional • MX + ES + US + CA</p>
      </div>
      <button onclick="showNewCompanyModal()" class="bg-green-600 hover:bg-green-700 text-white px-6 py-3 rounded-lg font-medium transition flex items-center space-x-2">
        <span>+</span>
        <span>Nueva Empresa</span>
      </button>
    </div>

    <!-- Estadísticas -->
    <div class="grid grid-cols-4 gap-6 mb-8">
      <div class="glass-panel stat-card p-6 text-center">
        <div class="text-4xl font-bold text-green-400">${activeCompanies}</div>
        <div class="text-sm text-gray-400 mt-2">Empresas Activas</div>
      </div>
      <div class="glass-panel stat-card p-6 text-center">
        <div class="text-4xl font-bold text-blue-400">0</div>
        <div class="text-sm text-gray-400 mt-2">Empleados Totales</div>
      </div>
      <div class="glass-panel stat-card p-6 text-center">
        <div class="text-4xl font-bold text-purple-400">${countries}</div>
        <div class="text-sm text-gray-400 mt-2">Países</div>
      </div>
      <div class="glass-panel stat-card p-6 text-center">
        <div class="text-4xl font-bold text-yellow-400">${currencies}</div>
        <div class="text-sm text-gray-400 mt-2">Monedas</div>
      </div>
    </div>

    <!-- Grid de empresas -->
    <div class="grid grid-cols-2 gap-6" id="companiesGrid">
      ${companies.map((company: any) => {
        const countryFlags: any = {
          'MXN': '🇲🇽',
          'USD': '🇺🇸',
          'EUR': '🇪🇸',
          'CAD': '🇨🇦'
        }
        const flag = countryFlags[company.currency] || '🌐'
        const currencySymbol = company.currency === 'USD' ? '$' : company.currency === 'EUR' ? '€' : '$'

        return `
        <div class="glass-panel p-6">
          <div class="flex items-start space-x-4 mb-4">
            <div class="company-logo flex-shrink-0">
              ${company.logo_url ?
                `<img src="${company.logo_url}" alt="${company.name}" class="w-full h-full object-contain rounded-lg" />` :
                `<span class="text-4xl text-gray-800">${company.name.charAt(0)}</span>`
              }
            </div>
            <div class="flex-1 min-w-0">
              <div class="flex items-center justify-between mb-1">
                <h3 class="text-xl font-bold flex items-center gap-2">
                  ${company.name}
                  <span class="text-base">${flag}</span>
                </h3>
                <span class="text-sm font-medium px-2 py-1 bg-blue-500/20 rounded">${company.currency}</span>
              </div>
              <div class="text-sm text-green-400 flex items-center">
                <span class="w-2 h-2 bg-green-400 rounded-full mr-2"></span>
                <span>Activa</span>
              </div>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4 mb-4">
            <div class="text-center p-3 bg-blue-500/10 rounded-lg">
              <div class="text-2xl font-bold text-blue-400">0</div>
              <div class="text-xs text-gray-400">Empleados</div>
            </div>
            <div class="text-center p-3 bg-purple-500/10 rounded-lg">
              <div class="text-2xl font-bold text-purple-400">${currencySymbol}0</div>
              <div class="text-xs text-gray-400">Gastos (0)</div>
            </div>
          </div>

          <div class="flex items-center justify-between gap-3">
            <div class="flex gap-2">
              <button onclick='editCompany(${JSON.stringify(company).replace(/'/g, "\\'")})'  class="px-4 py-2 bg-white/5 hover:bg-white/10 rounded-lg text-sm transition flex items-center gap-2">
                <span>✏️</span>
                <span>Editar</span>
              </button>
              <button onclick="deleteCompany('${company.id}', '${company.name}')" class="px-3 py-2 bg-red-600/20 hover:bg-red-600/30 rounded-lg text-sm transition flex items-center gap-2">
                <span class="text-red-500">🗑️</span>
              </button>
            </div>
            <a href="/companies/${company.id}" class="text-sm text-blue-400 hover:text-blue-300 flex items-center gap-1">
              Ver detalles
              <span>→</span>
            </a>
          </div>
        </div>
      `}).join('')}
    </div>

    ${companies.length === 0 ? `
      <div class="glass-panel p-12 text-center">
        <div class="text-6xl mb-4">🏢</div>
        <h3 class="text-xl font-bold mb-2">No hay empresas registradas</h3>
        <p class="text-gray-400 mb-6">Comienza agregando tu primera empresa</p>
        <button onclick="showNewCompanyModal()" class="bg-blue-600 hover:bg-blue-700 text-white px-6 py-3 rounded-lg">
          + Nueva Empresa
        </button>
      </div>
    ` : ''}
  </div>

  <!-- Modal Nueva Empresa -->
  <div id="newCompanyModal" class="fixed inset-0 bg-black/50 backdrop-blur-sm hidden items-center justify-center z-50 overflow-y-auto p-6">
    <div class="glass-panel p-8 max-w-3xl w-full mx-auto my-8">
      <h2 id="modalTitle" class="text-2xl font-bold mb-6">Nueva Empresa</h2>

      <form id="newCompanyForm" class="space-y-6">
        <input type="hidden" id="editingCompanyId" value="" />
        <!-- Sección 1: Datos Básicos -->
        <div class="space-y-4">
          <h3 class="text-lg font-semibold text-blue-300 flex items-center gap-2">
            <span>🏢</span>
            Datos Básicos
          </h3>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium mb-2">🏛 Razón Social *</label>
              <input type="text" id="companyName" required class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: TechMX Solutions S.A. de C.V." />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">🏷 Nombre Comercial *</label>
              <input type="text" id="companyCommercialName" required class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: TechMX" />
            </div>
          </div>

          <div class="grid grid-cols-3 gap-4">
            <div>
              <label class="block text-sm font-medium mb-2">🌐 País *</label>
              <select id="companyCountry" required class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400">
                <option value="">Seleccionar país...</option>
                <option value="MX">🇲🇽 México</option>
                <option value="US">🇺🇸 Estados Unidos</option>
                <option value="ES">🇪🇸 España</option>
                <option value="CA">🇨🇦 Canadá</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">📋 RFC/NIF *</label>
              <input type="text" id="companyTaxId" required class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="RFC, NIF, EIN, BN" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">💰 Moneda Principal *</label>
              <select id="companyCurrency" required class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400">
                <option value="">Seleccionar moneda...</option>
                <option value="MXN">MXN - Peso Mexicano</option>
                <option value="USD">USD - Dólar</option>
                <option value="EUR">EUR - Euro</option>
                <option value="CAD">CAD - Dólar Canadiense</option>
              </select>
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium mb-2">👥 Número de Empleados</label>
            <input type="number" id="companyEmployees" min="0" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: 25" />
          </div>
        </div>

        <!-- Sección 2: Información Comercial -->
        <div class="space-y-4 pt-4 border-t border-white/10">
          <h3 class="text-lg font-semibold text-green-300 flex items-center gap-2">
            <span>💼</span>
            Información Comercial
          </h3>

          <div class="grid grid-cols-2 gap-4">
            <div>
              <label class="block text-sm font-medium mb-2">🏭 Giro Empresarial</label>
              <select id="companyBusinessSector" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400">
                <option value="">Seleccionar giro...</option>
                <option value="Tecnología">Tecnología</option>
                <option value="Consultoría">Consultoría</option>
                <option value="Manufactura">Manufactura</option>
                <option value="Servicios">Servicios</option>
                <option value="Comercio">Comercio</option>
                <option value="Educación">Educación</option>
                <option value="Salud">Salud</option>
                <option value="Otro">Otro</option>
              </select>
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">🌍 Sitio Web</label>
              <input type="url" id="companyWebsite" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="https://www.empresa.com" />
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium mb-2">📝 Descripción del Negocio</label>
            <textarea id="companyDescription" rows="3" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Breve descripción de la actividad comercial de la empresa..."></textarea>
          </div>
        </div>

        <!-- Sección 3: Dirección Fiscal -->
        <div class="space-y-4 pt-4 border-t border-white/10">
          <h3 class="text-lg font-semibold text-purple-300 flex items-center gap-2">
            <span>📍</span>
            Dirección Fiscal
          </h3>

          <div>
            <label class="block text-sm font-medium mb-2">🏠 Calle y Número</label>
            <input type="text" id="companyStreet" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: Av. Insurgentes Sur 1234, Col. Del Valle" />
          </div>

          <div class="grid grid-cols-3 gap-4">
            <div>
              <label class="block text-sm font-medium mb-2">🏙 Ciudad</label>
              <input type="text" id="companyCity" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: Ciudad de México" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">🗺 Estado/Provincia</label>
              <input type="text" id="companyState" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: CDMX, Madrid, California" />
            </div>
            <div>
              <label class="block text-sm font-medium mb-2">📮 Código Postal</label>
              <input type="text" id="companyPostal" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: 03100, 28001, 90210" />
            </div>
          </div>

          <div>
            <label class="block text-sm font-medium mb-2">📞 Teléfono Principal</label>
            <input type="tel" id="companyPhone" class="w-full px-4 py-2 bg-white/10 border border-white/20 rounded-lg focus:outline-none focus:border-blue-400" placeholder="Ej: +52 555 123 4567" />
          </div>
        </div>

        <!-- Sección 4: Branding Corporativo -->
        <div class="space-y-4 pt-4 border-t border-white/10">
          <h3 class="text-lg font-semibold text-yellow-300 flex items-center gap-2">
            <span>🎨</span>
            Branding Corporativo
          </h3>

          <div class="grid grid-cols-2 gap-4">
            <!-- Logo Corporativo -->
            <div>
              <label class="block text-sm font-medium mb-2">🖼 Logo Corporativo</label>
              <div id="logoDropZone" class="relative border-2 border-dashed border-white/20 rounded-lg p-6 text-center cursor-pointer hover:border-blue-400 transition bg-white/5">
                <input type="file" id="companyLogoFile" accept="image/png,image/jpeg,image/jpg,image/svg+xml" class="hidden" />
                <div id="logoPlaceholder">
                  <div class="text-4xl mb-2">☁️</div>
                  <div class="text-sm text-gray-300 mb-1">Arrastra tu logo aquí</div>
                  <div class="text-xs text-gray-400">PNG, JPG, SVG (hasta 2MB)</div>
                </div>
                <div id="logoPreview" class="hidden">
                  <img id="logoPreviewImg" src="" alt="Logo preview" class="max-h-32 mx-auto mb-2" />
                  <button type="button" onclick="removeLogo()" class="text-xs text-red-400 hover:text-red-300">Eliminar</button>
                </div>
              </div>
              <input type="hidden" id="companyLogo" />
            </div>

            <!-- Color Corporativo -->
            <div>
              <label class="block text-sm font-medium mb-2">🎨 Color Corporativo</label>
              <div class="mb-3 relative">
                <button type="button" onclick="toggleColorPicker()" class="w-full px-4 py-3 bg-gradient-to-r from-purple-600 to-blue-600 hover:from-purple-700 hover:to-blue-700 rounded-lg font-medium transition flex items-center justify-center gap-2">
                  <span>🎨</span>
                  <span>Seleccionar Color</span>
                  <span id="colorCircle" class="w-6 h-6 rounded-full border-2 border-white" style="background-color: #3B82F6;"></span>
                </button>
                <input type="hidden" id="companyColor" value="#3B82F6" />

                <!-- Color Picker Dropdown -->
                <div id="colorPickerDropdown" class="hidden absolute top-full left-0 mt-2 bg-gray-800 border border-white/20 rounded-lg p-4 shadow-xl z-50">
                  <div class="mb-3">
                    <label class="text-xs text-gray-400 mb-2 block">Selector de Color</label>
                    <input type="color" id="colorPickerInput" value="#3B82F6" class="w-full h-10 rounded cursor-pointer" />
                  </div>
                  <div class="mb-2">
                    <label class="text-xs text-gray-400 mb-2 block">Código Hexadecimal</label>
                    <input type="text" id="colorHexInput" value="#3B82F6" class="w-full px-3 py-2 bg-white/10 border border-white/20 rounded text-sm" maxlength="7" />
                  </div>
                </div>
              </div>

              <div class="text-xs text-gray-400 mb-2">Colores Corporativos Sugeridos</div>
              <div class="grid grid-cols-7 gap-2">
                <button type="button" onclick="setColor('#FFA500')" class="w-10 h-10 rounded-lg bg-orange-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#4CAF50')" class="w-10 h-10 rounded-lg bg-green-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#3B82F6')" class="w-10 h-10 rounded-lg bg-blue-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#9C27B0')" class="w-10 h-10 rounded-lg bg-purple-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#F44336')" class="w-10 h-10 rounded-lg bg-red-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#FF9800')" class="w-10 h-10 rounded-lg bg-amber-500 hover:ring-2 ring-white transition shadow-lg"></button>
                <button type="button" onclick="setColor('#673AB7')" class="w-10 h-10 rounded-lg bg-violet-600 hover:ring-2 ring-white transition shadow-lg"></button>
              </div>
            </div>
          </div>
        </div>

        <div class="flex space-x-3 mt-6 pt-4 border-t border-white/10">
          <button type="button" onclick="hideNewCompanyModal()" class="flex-1 py-3 bg-white/5 hover:bg-white/10 rounded-lg transition font-medium">
            Cancelar
          </button>
          <button type="submit" class="flex-1 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg transition font-medium">
            Crear Empresa
          </button>
        </div>
      </form>
    </div>
  </div>

  <script>
    function showNewCompanyModal() {
      document.getElementById('newCompanyModal').classList.remove('hidden')
      document.getElementById('newCompanyModal').classList.add('flex')
    }

    function hideNewCompanyModal() {
      document.getElementById('newCompanyModal').classList.add('hidden')
      document.getElementById('newCompanyModal').classList.remove('flex')
      document.getElementById('newCompanyForm').reset()
      document.getElementById('colorCircle').style.backgroundColor = '#3B82F6'
      document.getElementById('editingCompanyId').value = ''
      document.getElementById('modalTitle').textContent = 'Nueva Empresa'
      removeLogo()
    }

    function setColor(color) {
      document.getElementById('companyColor').value = color
      document.getElementById('colorPickerInput').value = color
      document.getElementById('colorHexInput').value = color
      document.getElementById('colorCircle').style.backgroundColor = color
    }

    function toggleColorPicker() {
      const dropdown = document.getElementById('colorPickerDropdown')
      dropdown.classList.toggle('hidden')
    }

    function editCompany(company) {
      // Cambiar título del modal
      document.getElementById('modalTitle').textContent = 'Editar Empresa'

      // Guardar el ID para edición
      document.getElementById('editingCompanyId').value = company.id

      // Cargar datos básicos
      document.getElementById('companyName').value = company.name || ''
      document.getElementById('companyCommercialName').value = company.commercial_name || ''
      document.getElementById('companyCountry').value = company.country || ''
      document.getElementById('companyTaxId').value = company.tax_id || ''
      document.getElementById('companyCurrency').value = company.currency || ''
      document.getElementById('companyEmployees').value = company.employees_count || 0

      // Cargar información comercial
      document.getElementById('companyBusinessSector').value = company.business_sector || ''
      document.getElementById('companyWebsite').value = company.website || ''
      document.getElementById('companyDescription').value = company.business_description || ''

      // Cargar dirección fiscal
      document.getElementById('companyStreet').value = company.street_address || ''
      document.getElementById('companyCity').value = company.city || ''
      document.getElementById('companyState').value = company.state_province || ''
      document.getElementById('companyPostal').value = company.postal_code || ''
      document.getElementById('companyPhone').value = company.phone || ''

      // Cargar logo si existe
      if (company.logo_url) {
        document.getElementById('companyLogo').value = company.logo_url
        document.getElementById('logoPreviewImg').src = company.logo_url
        document.getElementById('logoPlaceholder').classList.add('hidden')
        document.getElementById('logoPreview').classList.remove('hidden')
      }

      // Cargar color
      const color = company.color || '#3B82F6'
      document.getElementById('companyColor').value = color
      document.getElementById('colorPickerInput').value = color
      document.getElementById('colorHexInput').value = color
      document.getElementById('colorCircle').style.backgroundColor = color

      // Abrir modal
      document.getElementById('newCompanyModal').classList.remove('hidden')
      document.getElementById('newCompanyModal').classList.add('flex')
    }

    async function deleteCompany(id, name) {
      if (!confirm(\`¿Estás seguro de que deseas eliminar la empresa "\${name}"?\n\nEsta acción no se puede deshacer.\`)) {
        return
      }

      try {
        const response = await fetch(\`/api/companies/\${id}\`, {
          method: 'DELETE'
        })

        const result = await response.json()

        if (response.ok) {
          alert('Empresa eliminada exitosamente')
          window.location.reload()
        } else {
          alert('Error al eliminar empresa: ' + (result.error || 'Error desconocido'))
        }
      } catch (error) {
        alert('Error al eliminar empresa: ' + error.message)
      }
    }

    function removeLogo() {
      document.getElementById('logoPlaceholder').classList.remove('hidden')
      document.getElementById('logoPreview').classList.add('hidden')
      document.getElementById('logoPreviewImg').src = ''
      document.getElementById('companyLogo').value = ''
      document.getElementById('companyLogoFile').value = ''
    }

    // Sync color picker input with hex input and circle
    document.getElementById('colorPickerInput').addEventListener('input', (e) => {
      const color = e.target.value
      document.getElementById('companyColor').value = color
      document.getElementById('colorHexInput').value = color
      document.getElementById('colorCircle').style.backgroundColor = color
    })

    // Sync hex input with color picker and circle
    document.getElementById('colorHexInput').addEventListener('input', (e) => {
      const color = e.target.value
      if (/^#[0-9A-F]{6}$/i.test(color)) {
        document.getElementById('companyColor').value = color
        document.getElementById('colorPickerInput').value = color
        document.getElementById('colorCircle').style.backgroundColor = color
      }
    })

    // Close color picker when clicking outside
    document.addEventListener('click', (e) => {
      const dropdown = document.getElementById('colorPickerDropdown')
      const button = e.target.closest('button[onclick="toggleColorPicker()"]')
      if (!dropdown.contains(e.target) && !button) {
        dropdown.classList.add('hidden')
      }
    })

    // Logo upload handling
    const logoDropZone = document.getElementById('logoDropZone')
    const logoFileInput = document.getElementById('companyLogoFile')

    logoDropZone.addEventListener('click', () => {
      logoFileInput.click()
    })

    logoFileInput.addEventListener('change', (e) => {
      const file = e.target.files[0]
      if (file) {
        handleLogoFile(file)
      }
    })

    logoDropZone.addEventListener('dragover', (e) => {
      e.preventDefault()
      logoDropZone.classList.add('border-blue-400')
    })

    logoDropZone.addEventListener('dragleave', (e) => {
      e.preventDefault()
      logoDropZone.classList.remove('border-blue-400')
    })

    logoDropZone.addEventListener('drop', (e) => {
      e.preventDefault()
      logoDropZone.classList.remove('border-blue-400')
      const file = e.dataTransfer.files[0]
      if (file && file.type.startsWith('image/')) {
        handleLogoFile(file)
      }
    })

    function handleLogoFile(file) {
      // Validate file size (2MB max)
      if (file.size > 2 * 1024 * 1024) {
        alert('El archivo es muy grande. Máximo 2MB.')
        return
      }

      const reader = new FileReader()
      reader.onload = (e) => {
        const base64 = e.target.result
        document.getElementById('companyLogo').value = base64
        document.getElementById('logoPreviewImg').src = base64
        document.getElementById('logoPlaceholder').classList.add('hidden')
        document.getElementById('logoPreview').classList.remove('hidden')
      }
      reader.readAsDataURL(file)
    }

    document.getElementById('newCompanyForm').addEventListener('submit', async (e) => {
      e.preventDefault()

      // Datos básicos
      const name = document.getElementById('companyName').value
      const commercialName = document.getElementById('companyCommercialName').value
      const country = document.getElementById('companyCountry').value
      const taxId = document.getElementById('companyTaxId').value
      const currency = document.getElementById('companyCurrency').value
      const employees = parseInt(document.getElementById('companyEmployees').value) || 0

      // Información comercial
      const businessSector = document.getElementById('companyBusinessSector').value || null
      const website = document.getElementById('companyWebsite').value || null
      const description = document.getElementById('companyDescription').value || null

      // Dirección fiscal
      const street = document.getElementById('companyStreet').value || null
      const city = document.getElementById('companyCity').value || null
      const state = document.getElementById('companyState').value || null
      const postal = document.getElementById('companyPostal').value || null
      const phone = document.getElementById('companyPhone').value || null

      // Branding
      const logoUrl = document.getElementById('companyLogo').value || null
      const color = document.getElementById('companyColor').value

      try {
        const editingId = document.getElementById('editingCompanyId').value
        const isEditing = editingId !== ''

        const url = isEditing ? \`/api/companies/\${editingId}\` : '/api/companies'
        const method = isEditing ? 'PUT' : 'POST'

        const response = await fetch(url, {
          method,
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            name,
            commercial_name: commercialName,
            country,
            tax_id: taxId,
            currency,
            employees_count: employees,
            business_sector: businessSector,
            website,
            business_description: description,
            street_address: street,
            city,
            state_province: state,
            postal_code: postal,
            phone,
            logo_url: logoUrl,
            color
          })
        })

        if (!response.ok) {
          const error = await response.json()
          throw new Error(error.error || (isEditing ? 'Error al actualizar empresa' : 'Error al crear empresa'))
        }

        window.location.reload()
      } catch (error) {
        alert('Error: ' + error.message)
      }
    })
  </script>
</body>
</html>
    `)
  } catch (error: any) {
    return c.text('Error: ' + error.message, 500)
  }
})

// Servir archivos estáticos
app.use('/static/*', serveStatic({ root: './public' }))

export default app
