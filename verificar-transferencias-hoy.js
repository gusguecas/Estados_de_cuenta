// Script para verificar transferencias creadas hoy
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

async function verificarTransferenciasHoy() {
  console.log('🔍 Verificando transferencias de HOY...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Filtrar movimientos con movimientoVinculadoId (son transferencias)
    const transferencias = movimientos.filter(doc => {
      const mov = convertFirestoreDoc(doc);
      return mov.movimientoVinculadoId;
    });

    console.log(`📊 Total de transferencias encontradas: ${transferencias.length}\\n`);

    // Obtener fecha de hoy (UTC)
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);
    const hoyStr = hoy.toISOString().split('T')[0];

    console.log(`📅 Buscando transferencias del día: ${hoyStr}\\n`);
    console.log('='.repeat(80));

    let encontradas = 0;
    for (const doc of transferencias) {
      const movimientoId = doc.name.split('/').pop();
      const movimiento = convertFirestoreDoc(doc);

      // Verificar si es de hoy
      const fechaMov = new Date(movimiento.fecha);
      const fechaMovStr = fechaMov.toISOString().split('T')[0];

      if (fechaMovStr === hoyStr) {
        encontradas++;
        console.log(`\\n📌 Movimiento ID: ${movimientoId}`);
        console.log(`   Tipo: ${movimiento.tipo}`);
        console.log(`   Cuenta: ${movimiento.cuentaId}`);
        console.log(`   Monto: $${movimiento.monto}`);
        console.log(`   Descripción: ${movimiento.descripcion}`);
        console.log(`   Es Origen: ${movimiento.esOrigen}`);
        console.log(`   Vinculado a: ${movimiento.movimientoVinculadoId}`);
        console.log(`   📎 Adjunto (legacy): ${movimiento.adjunto || 'NO'}`);
        console.log(`   📎 Adjuntos (array): ${movimiento.adjuntos ? JSON.stringify(movimiento.adjuntos) : 'NO'}`);
        console.log(`   Creado: ${movimiento.createdAt}`);
        console.log('   ' + '-'.repeat(76));
      }
    }

    console.log('='.repeat(80));
    console.log(`\\n✅ Total de transferencias de HOY: ${encontradas}`);

    if (encontradas === 0) {
      console.log('\\n⚠️  No se encontraron transferencias creadas hoy.');
      console.log('   Verifica que la fecha de tu sistema esté en UTC o que realmente hayas creado una transferencia hoy.');
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
verificarTransferenciasHoy();
