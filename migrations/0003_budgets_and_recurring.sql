-- Migration 0003: Presupuestos y Movimientos Recurrentes
-- Created: 2025-10-14

-- ============================================
-- Tabla: budgets (presupuestos)
-- ============================================
CREATE TABLE IF NOT EXISTS budgets (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  category_id TEXT,
  account_id TEXT,
  company_id TEXT,

  name TEXT NOT NULL,
  amount REAL NOT NULL,
  period_type TEXT NOT NULL CHECK(period_type IN ('monthly', 'quarterly', 'yearly')),
  year INTEGER NOT NULL,
  month INTEGER,  -- Para presupuestos mensuales

  budget_type TEXT NOT NULL CHECK(budget_type IN ('income', 'expense')),
  active INTEGER DEFAULT 1,

  notes TEXT,
  created_by TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (category_id) REFERENCES categories(id),
  FOREIGN KEY (account_id) REFERENCES bank_accounts(id),
  FOREIGN KEY (company_id) REFERENCES companies(id)
);

CREATE INDEX IF NOT EXISTS idx_budgets_user ON budgets(user_id);
CREATE INDEX IF NOT EXISTS idx_budgets_period ON budgets(year, month);
CREATE INDEX IF NOT EXISTS idx_budgets_category ON budgets(category_id);

-- ============================================
-- Tabla: recurring_movements (movimientos recurrentes)
-- ============================================
CREATE TABLE IF NOT EXISTS recurring_movements (
  id TEXT PRIMARY KEY,
  account_id TEXT NOT NULL,
  category_id TEXT,

  name TEXT NOT NULL,
  amount REAL NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('income', 'expense')),

  frequency TEXT NOT NULL CHECK(frequency IN ('daily', 'weekly', 'biweekly', 'monthly', 'quarterly', 'yearly')),
  start_date TEXT NOT NULL,
  end_date TEXT,  -- NULL = sin fecha de fin

  next_occurrence TEXT NOT NULL,
  day_of_month INTEGER,  -- Para mensuales: día del mes (1-31)
  day_of_week INTEGER,   -- Para semanales: día de la semana (0=domingo, 6=sábado)

  description TEXT,
  reference TEXT,

  active INTEGER DEFAULT 1,
  auto_generate INTEGER DEFAULT 1,  -- Generar automáticamente?

  last_generated_date TEXT,
  times_generated INTEGER DEFAULT 0,

  created_by TEXT NOT NULL,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP,

  FOREIGN KEY (account_id) REFERENCES bank_accounts(id),
  FOREIGN KEY (category_id) REFERENCES categories(id)
);

CREATE INDEX IF NOT EXISTS idx_recurring_account ON recurring_movements(account_id);
CREATE INDEX IF NOT EXISTS idx_recurring_next ON recurring_movements(next_occurrence);
CREATE INDEX IF NOT EXISTS idx_recurring_active ON recurring_movements(active);

-- ============================================
-- Tabla: generated_movements (log de generación)
-- ============================================
CREATE TABLE IF NOT EXISTS generated_movements (
  id TEXT PRIMARY KEY,
  recurring_movement_id TEXT NOT NULL,
  movement_id TEXT NOT NULL,
  generated_date TEXT NOT NULL,
  generated_for_date TEXT NOT NULL,

  FOREIGN KEY (recurring_movement_id) REFERENCES recurring_movements(id),
  FOREIGN KEY (movement_id) REFERENCES movements(id)
);

CREATE INDEX IF NOT EXISTS idx_generated_recurring ON generated_movements(recurring_movement_id);
CREATE INDEX IF NOT EXISTS idx_generated_movement ON generated_movements(movement_id);
