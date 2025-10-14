-- ============================================
-- LYRA FINANCIAL SYSTEM - INITIAL SCHEMA
-- Sistema de gestión financiera multi-empresa
-- ============================================

-- Tabla de usuarios
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT DEFAULT 'admin' CHECK (role IN ('admin', 'accountant', 'viewer')),
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  last_login DATETIME
);

-- Tabla de empresas
CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  initial_saldo REAL DEFAULT 0,
  currency TEXT DEFAULT 'MXN',
  logo_url TEXT,
  color TEXT DEFAULT '#3B82F6',
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Tabla de cuentas bancarias
CREATE TABLE IF NOT EXISTS bank_accounts (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  company_id TEXT NOT NULL,
  name TEXT NOT NULL,
  account_number TEXT,
  bank_name TEXT,
  initial_saldo REAL DEFAULT 0,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (company_id) REFERENCES companies(id) ON DELETE CASCADE
);

-- Tabla de categorías
CREATE TABLE IF NOT EXISTS categories (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  name TEXT NOT NULL,
  type TEXT CHECK (type IN ('income', 'expense', 'both')),
  color TEXT DEFAULT '#6B7280',
  icon TEXT,
  parent_id TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  FOREIGN KEY (parent_id) REFERENCES categories(id),
  UNIQUE(user_id, name)
);

-- Tabla de movimientos (CRÍTICA)
CREATE TABLE IF NOT EXISTS movements (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  account_id TEXT NOT NULL,

  -- Datos básicos del movimiento
  date DATE NOT NULL,
  type TEXT NOT NULL CHECK (type IN ('income', 'expense')),
  amount REAL NOT NULL CHECK (amount > 0),

  -- Información del movimiento
  reference TEXT, -- Número de cheque
  name TEXT NOT NULL, -- A quién se paga / quién paga
  category_id TEXT,
  description TEXT,
  comments TEXT,

  -- Estado
  status TEXT DEFAULT 'completed' CHECK (status IN ('pending', 'completed', 'reconciled', 'cancelled')),

  -- Transferencias internas (CRÍTICO)
  is_transfer INTEGER DEFAULT 0,
  transfer_id TEXT,

  -- Conciliación bancaria
  bank_statement_id TEXT,
  bank_transaction_id TEXT,
  is_bank_matched INTEGER DEFAULT 0,

  -- Importación
  import_id TEXT,

  -- Auditoría
  created_by TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_by TEXT,

  FOREIGN KEY (account_id) REFERENCES bank_accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (category_id) REFERENCES categories(id),
  FOREIGN KEY (transfer_id) REFERENCES transfers(id),
  FOREIGN KEY (bank_statement_id) REFERENCES bank_statements(id),
  FOREIGN KEY (import_id) REFERENCES imports(id),
  FOREIGN KEY (created_by) REFERENCES users(id),
  FOREIGN KEY (updated_by) REFERENCES users(id)
);

-- Tabla de transferencias internas (CRÍTICA)
CREATE TABLE IF NOT EXISTS transfers (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  from_account_id TEXT NOT NULL,
  to_account_id TEXT NOT NULL,
  amount REAL NOT NULL CHECK (amount > 0),
  date DATE NOT NULL,
  concept TEXT,

  from_movement_id TEXT,
  to_movement_id TEXT,

  created_by TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (from_account_id) REFERENCES bank_accounts(id),
  FOREIGN KEY (to_account_id) REFERENCES bank_accounts(id),
  FOREIGN KEY (from_movement_id) REFERENCES movements(id),
  FOREIGN KEY (to_movement_id) REFERENCES movements(id),
  FOREIGN KEY (created_by) REFERENCES users(id),
  CHECK (from_account_id != to_account_id)
);

-- Tabla de archivos adjuntos
CREATE TABLE IF NOT EXISTS attachments (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  movement_id TEXT NOT NULL,
  file_name TEXT NOT NULL,
  file_url TEXT NOT NULL,
  file_type TEXT,
  file_size INTEGER,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (movement_id) REFERENCES movements(id) ON DELETE CASCADE
);

-- Tabla de importaciones Excel (MUY IMPORTANTE)
CREATE TABLE IF NOT EXISTS imports (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT NOT NULL,
  account_id TEXT NOT NULL,

  -- Archivo
  file_name TEXT NOT NULL,
  file_url TEXT NOT NULL,
  file_size INTEGER,

  -- Tipo de importación
  import_type TEXT CHECK (import_type IN ('initial', 'incremental', 'update')),

  -- Resultados
  status TEXT DEFAULT 'processing' CHECK (status IN ('processing', 'completed', 'failed', 'partial')),
  total_rows INTEGER DEFAULT 0,
  rows_imported INTEGER DEFAULT 0,
  rows_updated INTEGER DEFAULT 0,
  rows_skipped INTEGER DEFAULT 0,
  rows_error INTEGER DEFAULT 0,

  -- Validación
  initial_balance REAL,
  final_balance REAL,
  expected_final_balance REAL,
  balance_matches INTEGER,

  -- Mapeo de columnas usado (JSON string)
  column_mapping TEXT,

  -- Errores (JSON string)
  errors TEXT,
  warnings TEXT,

  -- Auditoría
  started_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  completed_at DATETIME,

  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (account_id) REFERENCES bank_accounts(id)
);

-- Tabla de filas importadas
CREATE TABLE IF NOT EXISTS import_rows (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  import_id TEXT NOT NULL,

  row_number INTEGER NOT NULL,
  original_data TEXT, -- JSON string

  status TEXT CHECK (status IN ('pending', 'imported', 'updated', 'skipped', 'error')),
  error_message TEXT,

  movement_id TEXT,

  FOREIGN KEY (import_id) REFERENCES imports(id) ON DELETE CASCADE,
  FOREIGN KEY (movement_id) REFERENCES movements(id)
);

-- Tabla de estados de cuenta bancarios
CREATE TABLE IF NOT EXISTS bank_statements (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  account_id TEXT NOT NULL,

  -- Período
  year INTEGER NOT NULL,
  month INTEGER NOT NULL CHECK (month BETWEEN 1 AND 12),
  period_start DATE NOT NULL,
  period_end DATE NOT NULL,

  -- Archivo
  file_name TEXT NOT NULL,
  file_url TEXT NOT NULL,
  file_type TEXT,
  file_size INTEGER,

  -- Saldos según banco
  bank_initial_balance REAL,
  bank_final_balance REAL,
  bank_total_income REAL,
  bank_total_expense REAL,

  -- Saldos según sistema
  system_initial_balance REAL,
  system_final_balance REAL,
  system_total_income REAL,
  system_total_expense REAL,

  -- Conciliación
  is_reconciled INTEGER DEFAULT 0,
  balance_difference REAL,
  reconciled_at DATETIME,
  reconciled_by TEXT,

  notes TEXT,

  uploaded_by TEXT,
  uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (account_id) REFERENCES bank_accounts(id) ON DELETE CASCADE,
  FOREIGN KEY (reconciled_by) REFERENCES users(id),
  FOREIGN KEY (uploaded_by) REFERENCES users(id),
  UNIQUE(account_id, year, month)
);

-- Tabla de auditoría (log completo)
CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))),
  user_id TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  old_values TEXT, -- JSON string
  new_values TEXT, -- JSON string
  ip_address TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ============================================
-- ÍNDICES PARA PERFORMANCE
-- ============================================

-- Users
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- Companies
CREATE INDEX IF NOT EXISTS idx_companies_user_active ON companies(user_id, active);

-- Bank Accounts
CREATE INDEX IF NOT EXISTS idx_bank_accounts_company_active ON bank_accounts(company_id, active);

-- Categories
CREATE INDEX IF NOT EXISTS idx_categories_user_type ON categories(user_id, type);

-- Movements (MUY IMPORTANTES)
CREATE INDEX IF NOT EXISTS idx_movements_account_date ON movements(account_id, date DESC);
CREATE INDEX IF NOT EXISTS idx_movements_date ON movements(date DESC);
CREATE INDEX IF NOT EXISTS idx_movements_type ON movements(type);
CREATE INDEX IF NOT EXISTS idx_movements_category ON movements(category_id);
CREATE INDEX IF NOT EXISTS idx_movements_transfer ON movements(transfer_id);
CREATE INDEX IF NOT EXISTS idx_movements_status ON movements(status);
CREATE INDEX IF NOT EXISTS idx_movements_import ON movements(import_id);
CREATE INDEX IF NOT EXISTS idx_movements_bank_statement ON movements(bank_statement_id);

-- Transfers
CREATE INDEX IF NOT EXISTS idx_transfers_from_account ON transfers(from_account_id);
CREATE INDEX IF NOT EXISTS idx_transfers_to_account ON transfers(to_account_id);
CREATE INDEX IF NOT EXISTS idx_transfers_date ON transfers(date DESC);

-- Attachments
CREATE INDEX IF NOT EXISTS idx_attachments_movement ON attachments(movement_id);

-- Imports
CREATE INDEX IF NOT EXISTS idx_imports_user_account ON imports(user_id, account_id);
CREATE INDEX IF NOT EXISTS idx_imports_status ON imports(status);

-- Import Rows
CREATE INDEX IF NOT EXISTS idx_import_rows_import ON import_rows(import_id);
CREATE INDEX IF NOT EXISTS idx_import_rows_movement ON import_rows(movement_id);

-- Bank Statements
CREATE INDEX IF NOT EXISTS idx_bank_statements_account_period ON bank_statements(account_id, year, month);
CREATE INDEX IF NOT EXISTS idx_bank_statements_reconciliation ON bank_statements(is_reconciled);

-- Audit Log
CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_audit_log_user_date ON audit_log(user_id, created_at DESC);
