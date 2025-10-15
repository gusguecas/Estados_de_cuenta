-- ============================================
-- LYRA FINANCIAL SYSTEM - ADD COMPANY FIELDS
-- Campos adicionales para información completa de empresas
-- ============================================

-- Agregar campos comerciales y fiscales
ALTER TABLE companies ADD COLUMN commercial_name TEXT;
ALTER TABLE companies ADD COLUMN country TEXT DEFAULT 'MX';
ALTER TABLE companies ADD COLUMN tax_id TEXT; -- RFC, NIF, EIN, BN
ALTER TABLE companies ADD COLUMN employees_count INTEGER DEFAULT 0;

-- Información comercial
ALTER TABLE companies ADD COLUMN business_sector TEXT; -- Giro empresarial
ALTER TABLE companies ADD COLUMN website TEXT;
ALTER TABLE companies ADD COLUMN business_description TEXT;

-- Dirección fiscal
ALTER TABLE companies ADD COLUMN street_address TEXT;
ALTER TABLE companies ADD COLUMN city TEXT;
ALTER TABLE companies ADD COLUMN state_province TEXT;
ALTER TABLE companies ADD COLUMN postal_code TEXT;
ALTER TABLE companies ADD COLUMN phone TEXT;
