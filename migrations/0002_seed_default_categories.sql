-- ============================================
-- Categorías predefinidas por defecto
-- Se insertarán para el primer usuario
-- ============================================

-- NOTA: Este seed se ejecutará manualmente o desde el código
-- cuando el primer usuario se registre

-- Categorías de INGRESOS
-- INSERT INTO categories (id, user_id, name, type, color, icon) VALUES
--   ('cat-income-sales', 'USER_ID', 'Ventas', 'income', '#10B981', '💰'),
--   ('cat-income-services', 'USER_ID', 'Servicios', 'income', '#34D399', '🛠️'),
--   ('cat-income-investments', 'USER_ID', 'Inversiones', 'income', '#6EE7B7', '📈'),
--   ('cat-income-other', 'USER_ID', 'Otros Ingresos', 'income', '#A7F3D0', '💵');

-- Categorías de EGRESOS
-- INSERT INTO categories (id, user_id, name, type, color, icon) VALUES
--   ('cat-expense-payroll', 'USER_ID', 'Nómina', 'expense', '#EF4444', '👥'),
--   ('cat-expense-rent', 'USER_ID', 'Renta', 'expense', '#F87171', '🏢'),
--   ('cat-expense-utilities', 'USER_ID', 'Servicios', 'expense', '#FCA5A5', '💡'),
--   ('cat-expense-purchases', 'USER_ID', 'Compras', 'expense', '#FEE2E2', '🛒'),
--   ('cat-expense-taxes', 'USER_ID', 'Impuestos', 'expense', '#DC2626', '🏛️'),
--   ('cat-expense-marketing', 'USER_ID', 'Marketing', 'expense', '#FB923C', '📢'),
--   ('cat-expense-maintenance', 'USER_ID', 'Mantenimiento', 'expense', '#FDBA74', '🔧'),
--   ('cat-expense-other', 'USER_ID', 'Otros Gastos', 'expense', '#FED7AA', '💸');

-- Este SQL es solo referencia. Las categorías se crearán desde el código
-- cuando un usuario se registre por primera vez.
