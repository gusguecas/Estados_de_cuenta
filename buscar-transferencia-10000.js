// Script para buscar la transferencia de $10,000 del 18 de noviembre
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

async function buscarTransferencia() {
  console.log('🔍 Buscando transferencia de $10,000 del 18 de noviembre...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Buscar movimientos de $10,000 con monto exacto
    const candidatos = movimientos
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .filter(m => m.monto === 10000 || m.monto === 10000.0);

    console.log(`📊 Movimientos de $10,000 encontrados: ${candidatos.length}\\n`);

    if (candidatos.length === 0) {
      console.log('❌ No se encontraron movimientos de $10,000');
      return;
    }

    console.log('='.repeat(100));

    for (const mov of candidatos) {
      const fechaCreacion = new Date(mov.createdAt);
      const fechaMovimiento = new Date(mov.fecha);

      console.log(`\\n📌 ID: ${mov.id}`);
      console.log(`   Fecha Movimiento: ${fechaMovimiento.toISOString()}`);
      console.log(`   Fecha Creación: ${fechaCreacion.toLocaleString('es-MX')} (${fechaCreacion.toISOString()})`);
      console.log(`   Tipo: ${mov.tipo} | Monto: $${mov.monto}`);
      console.log(`   Cuenta ID: ${mov.cuentaId}`);
      console.log(`   Descripción: ${mov.descripcion}`);
      console.log(`   Cancelado: ${mov.cancelado}`);

      // Si es transferencia
      if (mov.movimientoVinculadoId) {
        console.log(`   🔗 ES TRANSFERENCIA`);
        console.log(`   Vinculado a: ${mov.movimientoVinculadoId}`);
        console.log(`   Es Origen: ${mov.esOrigen}`);
        console.log(`   Cuenta Destino ID: ${mov.cuentaDestinoId}`);
      }

      // Adjuntos
      const tieneAdjunto = mov.adjunto ? '✅' : '❌';
      const tieneAdjuntos = mov.adjuntos && mov.adjuntos.length > 0 ? '✅' : '❌';

      console.log(`   ${tieneAdjunto} adjunto (legacy): ${mov.adjunto || 'NO'}`);
      console.log(`   ${tieneAdjuntos} adjuntos (array): ${mov.adjuntos && mov.adjuntos.length > 0 ? JSON.stringify(mov.adjuntos, null, 6) : 'NO'}`);

      // Si es transferencia, buscar el movimiento vinculado
      if (mov.movimientoVinculadoId) {
        console.log(`\\n   🔍 Buscando movimiento vinculado...`);
        try {
          const vinculadoDoc = await firestoreRequest(`/movimientos/${mov.movimientoVinculadoId}`);
          const vinculado = convertFirestoreDoc(vinculadoDoc);

          console.log(`   📌 MOVIMIENTO VINCULADO (${mov.movimientoVinculadoId}):`);
          console.log(`      Tipo: ${vinculado.tipo} | Monto: $${vinculado.monto}`);
          console.log(`      Cuenta ID: ${vinculado.cuentaId}`);
          console.log(`      Descripción: ${vinculado.descripcion}`);

          const tieneAdjuntoVinc = vinculado.adjunto ? '✅' : '❌';
          const tieneAdjuntosVinc = vinculado.adjuntos && vinculado.adjuntos.length > 0 ? '✅' : '❌';

          console.log(`      ${tieneAdjuntoVinc} adjunto (legacy): ${vinculado.adjunto || 'NO'}`);
          console.log(`      ${tieneAdjuntosVinc} adjuntos (array): ${vinculado.adjuntos && vinculado.adjuntos.length > 0 ? JSON.stringify(vinculado.adjuntos, null, 9) : 'NO'}`);

        } catch (error) {
          console.log(`   ❌ Error al obtener vinculado: ${error.message}`);
        }
      }

      console.log('   ' + '-'.repeat(96));
    }

    console.log('='.repeat(100));

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
buscarTransferencia();
