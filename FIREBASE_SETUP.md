# 🔥 Configuración de Firebase

## Paso 1: Crear Proyecto en Firebase

1. Ve a [Firebase Console](https://console.firebase.google.com/)
2. Click en "Add project" / "Agregar proyecto"
3. Nombre: `estados-cuenta` (o el que prefieras)
4. **NO actives Google Analytics** (opcional, no lo necesitamos)
5. Click "Create project"

## Paso 2: Activar Autenticación

1. En el menú lateral, click "Build" → "Authentication"
2. Click "Get started"
3. Click en "Email/Password"
4. **Activa** "Email/Password"
5. Click "Save"

## Paso 3: Crear Base de Datos Firestore

1. En el menú lateral, click "Build" → "Firestore Database"
2. Click "Create database"
3. Selecciona "Start in **production mode**"
4. Location: `us-central1` (o el más cercano a ti)
5. Click "Enable"

## Paso 4: Configurar Storage

1. En el menú lateral, click "Build" → "Storage"
2. Click "Get started"
3. Usar reglas de seguridad por defecto
4. Location: el mismo que Firestore
5. Click "Done"

## Paso 5: Obtener Credenciales

1. En el menú lateral, click en el ícono de ⚙️ (Settings)
2. Selecciona "Project settings"
3. Baja hasta "Your apps"
4. Click en el ícono `</>` (Web)
5. Nickname: `estados-cuenta-web`
6. **NO actives** Firebase Hosting
7. Click "Register app"
8. **Copia** el objeto `firebaseConfig` que aparece

## Paso 6: Configurar Variables de Entorno

1. En la raíz del proyecto, crea el archivo `.env.local`
2. Copia el contenido de `.env.local.example`
3. Pega los valores del `firebaseConfig` de Firebase:

```env
NEXT_PUBLIC_FIREBASE_API_KEY=AIza...
NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN=estados-cuenta-xxxxx.firebaseapp.com
NEXT_PUBLIC_FIREBASE_PROJECT_ID=estados-cuenta-xxxxx
NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET=estados-cuenta-xxxxx.appspot.com
NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID=123456789
NEXT_PUBLIC_FIREBASE_APP_ID=1:123456789:web:abcdef
```

## Paso 7: Configurar Reglas de Firestore

1. Ve a Firestore Database → Rules
2. Pega estas reglas:

```javascript
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Solo usuarios autenticados
    match /{document=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```

3. Click "Publish"

## Paso 8: Configurar Reglas de Storage

1. Ve a Storage → Rules
2. Pega estas reglas:

```javascript
rules_version = '2';
service firebase.storage {
  match /b/{bucket}/o {
    match /{allPaths=**} {
      allow read, write: if request.auth != null;
    }
  }
}
```

3. Click "Publish"

## ✅ Listo!

Ahora ejecuta:
```bash
npm run dev
```

Y abre http://localhost:3000
