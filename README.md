# 💰 Estados de Cuenta - Sistema de Control Financiero

Sistema de gestión financiera personal y empresarial construido con Next.js 14, Firebase y Tailwind CSS.

## ✨ Características

- 🔐 **Autenticación** con Firebase Auth
- 🏢 **Multi-empresa** - Gestiona múltiples empresas
- 👤 **Finanzas personales** - Área separada para finanzas personales
- 💳 **Múltiples cuentas** por empresa (cheques, crédito, préstamos)
- 📊 **Movimientos** - Registro de ingresos y egresos
- 💾 **Saldo automático** - Cálculo en tiempo real
- 📄 **Estados de cuenta PDF** - Almacenamiento en Firebase Storage
- 🌍 **Multi-moneda** - USD, MXN, EUR

## 🚀 Stack Tecnológico

- **Framework:** Next.js 14 (App Router)
- **Language:** TypeScript
- **Styling:** Tailwind CSS
- **UI Components:** shadcn/ui
- **Database:** Firebase Firestore
- **Authentication:** Firebase Auth
- **Storage:** Firebase Storage
- **Deployment:** Vercel

## 📋 Requisitos Previos

- Node.js 18+ instalado
- Cuenta de Firebase
- Cuenta de GitHub (opcional)
- Cuenta de Vercel (para deployment)

## 🛠️ Instalación

### 1. Clonar el repositorio

\`\`\`bash
git clone <tu-repo-url>
cd estados-cuenta-v2
\`\`\`

### 2. Instalar dependencias

\`\`\`bash
npm install
\`\`\`

### 3. Configurar Firebase

Sigue las instrucciones completas en [FIREBASE_SETUP.md](./FIREBASE_SETUP.md)

Resumen:
1. Crea un proyecto en [Firebase Console](https://console.firebase.google.com/)
2. Activa Authentication (Email/Password)
3. Crea Firestore Database
4. Activa Storage
5. Obtén las credenciales del proyecto

### 4. Variables de Entorno

Crea un archivo \`.env.local\` en la raíz del proyecto:

\`\`\`env
NEXT_PUBLIC_FIREBASE_API_KEY=tu-api-key
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=tu-auth-domain
NEXT_PUBLIC_FIREBASE_PROJECT_ID=tu-project-id
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=tu-storage-bucket
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=tu-sender-id
NEXT_PUBLIC_FIREBASE_APP_ID=tu-app-id
\`\`\`

### 5. Iniciar el servidor de desarrollo

\`\`\`bash
npm run dev
\`\`\`

Abre [http://localhost:3000](http://localhost:3000) en tu navegador.

## 📁 Estructura del Proyecto

\`\`\`
estados-cuenta-v2/
├── app/
│   ├── auth/
│   │   └── login/          # Página de login
│   ├── dashboard/          # Dashboard principal
│   ├── empresas/           # Gestión de empresas
│   ├── personal/           # Finanzas personales
│   ├── layout.tsx          # Layout principal con AuthProvider
│   └── page.tsx            # Página de inicio (redirect)
├── components/
│   └── ui/                 # Componentes shadcn/ui
├── lib/
│   ├── firebase.ts         # Configuración de Firebase
│   └── auth-context.tsx    # Contexto de autenticación
├── public/                 # Archivos estáticos
└── FIREBASE_SETUP.md       # Guía de configuración Firebase
\`\`\`

## 🔥 Configuración de Firebase

### Firestore Rules

\`\`\`javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
\`\`\`

### Storage Rules

\`\`\`javascript
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.auth != null;
    }
  }
}
\`\`\`

## 🚢 Deploy en Vercel

### Opción 1: Desde GitHub (Recomendado)

1. Push tu código a GitHub
2. Ve a [Vercel](https://vercel.com)
3. Click "New Project"
4. Importa tu repositorio
5. Agrega las variables de entorno (\`.env.local\`)
6. Click "Deploy"

### Opción 2: CLI

\`\`\`bash
npm install -g vercel
vercel login
vercel
\`\`\`

## 📚 Próximas Features

- [ ] CRUD completo de empresas
- [ ] CRUD de cuentas bancarias
- [ ] Sistema de categorías
- [ ] Filtros y búsqueda
- [ ] Exportación a Excel
- [ ] Gráficas y reportes
- [ ] Recordatorios de pagos
- [ ] Dashboard con KPIs

## 🤝 Contribuir

Este es un proyecto personal, pero si quieres contribuir:

1. Fork el proyecto
2. Crea una rama (\`git checkout -b feature/AmazingFeature\`)
3. Commit tus cambios (\`git commit -m 'Add some AmazingFeature'\`)
4. Push a la rama (\`git push origin feature/AmazingFeature\`)
5. Abre un Pull Request

## 📝 Licencia

MIT

## 👤 Autor

**Gus**

---

**Nota:** Este proyecto fue desarrollado con Next.js 14, TypeScript y Firebase. Para más información sobre las tecnologías utilizadas, consulta la documentación oficial de cada una.
