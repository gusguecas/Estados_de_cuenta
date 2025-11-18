// Script para ver TODAS las transferencias con sus adjuntos
const { execSync } = require('child_process');

const PROJECT_ID = 'estados-de-cuenta-bd1e5';
const DATABASE = '(default)';

// Obtener access token
function getAccessToken() {
  return execSync('gcloud auth print-access-token').toString().trim();
}

// Hacer request a Firestore REST API
async function firestoreRequest(path, method = 'GET', body = null) {
  const accessToken = getAccessToken();
  const baseUrl = `https://firestore.googleapis.com/v1/projects/${PROJECT_ID}/databases/${DATABASE}/documents`;

  const options = {
    method,
    headers: {
      'Authorization': `Bearer ${accessToken}`,
      'Content-Type': 'application/json',
      'x-goog-user-project': PROJECT_ID
    }
  };

  if (body) {
    options.body = JSON.stringify(body);
  }

  const response = await fetch(`${baseUrl}${path}`, options);

  if (!response.ok) {
    const error = await response.text();
    throw new Error(`Firestore API error: ${response.status} - ${error}`);
  }

  return response.json();
}

// Convertir documento de Firestore a objeto simple
function convertFirestoreDoc(doc) {
  const data = {};
  if (doc.fields) {
    for (const [key, value] of Object.entries(doc.fields)) {
      if (value.stringValue !== undefined) data[key] = value.stringValue;
      else if (value.integerValue !== undefined) data[key] = parseInt(value.integerValue);
      else if (value.doubleValue !== undefined) data[key] = value.doubleValue;
      else if (value.booleanValue !== undefined) data[key] = value.booleanValue;
      else if (value.timestampValue !== undefined) data[key] = value.timestampValue;
      else if (value.arrayValue) {
        data[key] = value.arrayValue.values?.map(v => v.stringValue || v) || [];
      }
    }
  }
  return data;
}

async function verTodasTransferencias() {
  console.log('🔍 Viendo TODAS las transferencias...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Filtrar movimientos con movimientoVinculadoId (son transferencias)
    const transferencias = movimientos
      .filter(doc => {
        const mov = convertFirestoreDoc(doc);
        return mov.movimientoVinculadoId;
      })
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)); // Más recientes primero

    console.log(`📊 Total de transferencias: ${transferencias.length}\\n`);
    console.log('='.repeat(100));

    for (const mov of transferencias) {
      const fechaMov = new Date(mov.fecha);
      const fechaCreacion = new Date(mov.createdAt);

      console.log(`\\n📌 ID: ${mov.id}`);
      console.log(`   Fecha Movimiento: ${fechaMov.toISOString().split('T')[0]} (${fechaMov.toISOString()})`);
      console.log(`   Fecha Creación: ${fechaCreacion.toISOString()}`);
      console.log(`   Tipo: ${mov.tipo} | Monto: $${mov.monto} | Es Origen: ${mov.esOrigen}`);
      console.log(`   Cuenta: ${mov.cuentaId}`);
      console.log(`   Descripción: ${mov.descripcion}`);
      console.log(`   Vinculado a: ${mov.movimientoVinculadoId}`);

      // Verificar adjuntos
      const tieneAdjunto = mov.adjunto ? '✅' : '❌';
      const tieneAdjuntos = mov.adjuntos && mov.adjuntos.length > 0 ? '✅' : '❌';

      console.log(`   ${tieneAdjunto} adjunto (legacy): ${mov.adjunto || 'NO'}`);
      console.log(`   ${tieneAdjuntos} adjuntos (array): ${mov.adjuntos ? JSON.stringify(mov.adjuntos, null, 2) : 'NO'}`);
      console.log('   ' + '-'.repeat(96));
    }

    console.log('='.repeat(100));
    console.log(`\\n✅ Total: ${transferencias.length} transferencias`);

    // Resumen
    const conAdjuntos = transferencias.filter(t => t.adjuntos && t.adjuntos.length > 0).length;
    const sinAdjuntos = transferencias.length - conAdjuntos;
    console.log(`\\n📎 Con adjuntos: ${conAdjuntos}`);
    console.log(`📎 Sin adjuntos: ${sinAdjuntos}`);

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
verTodasTransferencias();
