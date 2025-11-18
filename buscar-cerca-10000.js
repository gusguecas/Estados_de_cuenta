// Script para buscar movimientos cerca de $10,000
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

async function buscarCerca10000() {
  console.log('🔍 Buscando movimientos cerca de $10,000...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Convertir todos
    const todos = movimientos
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    // Buscar cerca de 10,000
    const cerca = todos.filter(m => m.monto >= 9000 && m.monto <= 11000);

    console.log(`📊 Movimientos entre $9,000 y $11,000: ${cerca.length}\\n`);

    if (cerca.length === 0) {
      console.log('❌ No se encontraron movimientos en ese rango');
      console.log('\\n📋 Mostrando los 20 movimientos más recientes con cualquier monto:\\n');

      const recientes = todos.slice(0, 20);
      for (const mov of recientes) {
        const fechaCreacion = new Date(mov.createdAt);
        const esTransf = mov.movimientoVinculadoId ? '🔗' : '  ';
        const tieneAdj = (mov.adjuntos && mov.adjuntos.length > 0) || mov.adjunto ? '📎' : '  ';
        console.log(`${esTransf}${tieneAdj} ${mov.id} | $${mov.monto.toFixed(2).padStart(10)} | ${fechaCreacion.toISOString()} | ${mov.descripcion.substring(0, 50)}`);
      }
      return;
    }

    console.log('='.repeat(100));

    for (const mov of cerca) {
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
buscarCerca10000();
