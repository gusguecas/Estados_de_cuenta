# 💼 Lyra Financial System

Sistema de gestión financiera multi-empresa con importación Excel y conciliación bancaria.

## 🚀 Stack Tecnológico

- **Backend:** Hono (Cloudflare Workers)
- **Frontend:** TypeScript + Tailwind CSS
- **Database:** Cloudflare D1 (SQLite)
- **Storage:** Cloudflare R2 (para Excel, PDFs)
- **Deployment:** Cloudflare Pages
- **Build:** Vite

## 📋 Características Implementadas

### ✅ Fase 1 - MVP Core (COMPLETADO)

- [x] Autenticación con JWT
- [x] CRUD de usuarios
- [x] CRUD de empresas
- [x] CRUD de cuentas bancarias
- [x] CRUD de movimientos (ingresos/egresos)
- [x] Sistema de transferencias internas
- [x] CRUD de categorías
- [x] Dashboard con resumen
- [x] Cálculo automático de saldos

### ⏳ Próximas Fases

- [ ] Importación de Excel (Fase 2)
- [ ] Exportación a Excel (Fase 2)
- [ ] Estados de cuenta bancarios (Fase 3)
- [ ] Conciliación bancaria (Fase 3)
- [ ] Reportes avanzados (Fase 4)
- [ ] Presupuestos (Fase 5)
- [ ] Movimientos recurrentes (Fase 5)

## 🛠️ Setup Local

### 1. Instalar dependencias

\`\`\`bash
npm install
\`\`\`

### 2. Base de datos local

La base de datos D1 ya está creada. Para trabajar localmente:

\`\`\`bash
# Ejecutar migraciones localmente (ya ejecutadas)
npm run db:migrate:local

# Ver consola de la base de datos local
npm run db:console:local
\`\`\`

### 3. Iniciar desarrollo

\`\`\`bash
# Opción 1: Vite dev server (puerto 3001)
npm run dev

# Opción 2: Wrangler con D1 local (puerto 3000)
npm run dev:d1
\`\`\`

Abre http://localhost:3001 (o 3000 si usas dev:d1)

### 4. Build y Deploy

\`\`\`bash
# Build para producción
npm run build

# Deploy a Cloudflare Pages
npm run deploy
\`\`\`

## 📦 Base de Datos

### Tablas Principales

- **users** - Usuarios del sistema
- **companies** - Empresas del usuario
- **bank_accounts** - Cuentas bancarias por empresa
- **categories** - Categorías de ingresos/egresos
- **movements** - Movimientos financieros
- **transfers** - Transferencias internas entre cuentas
- **attachments** - Archivos adjuntos a movimientos
- **imports** - Historial de importaciones Excel
- **import_rows** - Detalle de filas importadas
- **bank_statements** - Estados de cuenta bancarios
- **audit_log** - Log de auditoría

### Ejecutar migraciones

\`\`\`bash
# Local
npm run db:migrate:local

# Producción (Cloudflare)
npm run db:migrate:prod
\`\`\`

### Resetear base de datos local

\`\`\`bash
npm run db:reset
\`\`\`

## 🔑 API Endpoints

### Autenticación

\`\`\`
POST   /api/auth/register    - Registro de usuario
POST   /api/auth/login       - Login
POST   /api/auth/logout      - Logout
GET    /api/auth/me          - Usuario actual
\`\`\`

### Empresas

\`\`\`
GET    /api/companies        - Listar empresas
POST   /api/companies        - Crear empresa
PUT    /api/companies/:id    - Editar empresa
DELETE /api/companies/:id    - Eliminar empresa (soft delete)
\`\`\`

### Cuentas Bancarias

\`\`\`
GET    /api/accounts              - Listar cuentas
POST   /api/accounts              - Crear cuenta
GET    /api/accounts/:id/balance  - Obtener saldo de cuenta
\`\`\`

### Movimientos

\`\`\`
GET    /api/movements        - Listar movimientos (con filtros)
POST   /api/movements        - Crear movimiento
PUT    /api/movements/:id    - Editar movimiento
DELETE /api/movements/:id    - Cancelar movimiento
\`\`\`

### Transferencias

\`\`\`
POST   /api/transfers        - Crear transferencia interna
GET    /api/transfers        - Listar transferencias
DELETE /api/transfers/:id    - Cancelar transferencia
\`\`\`

### Categorías

\`\`\`
GET    /api/categories       - Listar categorías
POST   /api/categories       - Crear categoría
\`\`\`

### Dashboard

\`\`\`
GET    /api/dashboard/summary - Resumen completo (saldos, stats, movimientos recientes)
\`\`\`

## 🧪 Testing

### Probar endpoints

\`\`\`bash
# 1. Registrar usuario
curl -X POST http://localhost:3001/api/auth/register \\
  -H "Content-Type: application/json" \\
  -d '{"email":"test@test.com","password":"123456","name":"Test User"}'

# 2. Login
curl -X POST http://localhost:3001/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"email":"test@test.com","password":"123456"}' \\
  --cookie-jar cookies.txt

# 3. Crear empresa (usando cookie)
curl -X POST http://localhost:3001/api/companies \\
  -H "Content-Type: application/json" \\
  -d '{"name":"Empresa A","initial_saldo":100000,"currency":"MXN"}' \\
  --cookie cookies.txt

# 4. Ver empresas
curl http://localhost:3001/api/companies --cookie cookies.txt

# 5. Ver dashboard
curl http://localhost:3001/api/dashboard/summary --cookie cookies.txt
\`\`\`

## 📂 Estructura del Proyecto

\`\`\`
lyra-financial-system/
├── src/
│   ├── index.tsx          # Aplicación principal (Hono)
│   └── styles.css         # Estilos Tailwind
├── migrations/
│   ├── 0001_initial_schema.sql
│   └── 0002_seed_default_categories.sql
├── public/
│   └── static/            # Archivos estáticos
├── package.json
├── wrangler.toml          # Config Cloudflare
├── vite.config.ts
├── tailwind.config.js
└── tsconfig.json
\`\`\`

## 🔐 Seguridad

- Autenticación JWT con cookies HttpOnly
- Hash de passwords con SHA-256 + salt
- Validación de permisos en cada endpoint
- Usuario solo puede ver/editar sus propios datos
- SQL injection protegido (prepared statements)

## 💡 Lógica de Negocio Crítica

### Cálculo de Saldo

\`\`\`
Saldo Actual = Saldo Inicial + Σ(Ingresos) - Σ(Egresos)
\`\`\`

**IMPORTANTE:** Los movimientos cancelados NO afectan el saldo.

### Transferencias Internas

Cuando se crea una transferencia:
1. Se crea 1 registro en tabla \`transfers\`
2. Se crea 1 movimiento de EGRESO en cuenta origen
3. Se crea 1 movimiento de INGRESO en cuenta destino
4. Ambos movimientos se vinculan con \`transfer_id\`
5. Si se cancela uno, se cancela el otro automáticamente

**DEBE SER TRANSACCIONAL** - Todo o nada.

## 📊 Database Info

**Database ID:** \`4ac0788b-d3e9-4667-be39-097a71a46991\`
**Database Name:** \`lyra-db\`
**Region:** ENAM (Eastern North America)

## 🐛 Debug

Ver logs en tiempo real:

\`\`\`bash
npx wrangler pages dev dist --d1=lyra-db --local --log-level debug
\`\`\`

## 📝 Notas

- El proyecto sigue el estilo **gusbit** (todo en un archivo \`src/index.tsx\`)
- Las categorías predefinidas se crean automáticamente al registrar el primer usuario
- La base de datos usa **SQLite** (D1) adaptado desde PostgreSQL
- Los UUIDs se generan con \`crypto.randomUUID()\`

## 🚀 Próximos Pasos

1. ✅ **MVP Core completo** (Auth, Empresas, Cuentas, Movimientos, Transferencias)
2. ⏳ **Importación Excel** - Permitir migración desde Excel existente
3. ⏳ **Estados de Cuenta** - Adjuntar PDFs bancarios y comparar
4. ⏳ **Reportes** - Generar reportes y exportar a Excel
5. ⏳ **Frontend mejorado** - React components con shadcn/ui

## 📧 Contacto

Proyecto desarrollado para Gus.

---

**Status:** 🟢 Setup inicial completado - Fase 1 MVP funcional
