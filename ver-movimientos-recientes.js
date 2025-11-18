// Script para ver los movimientos más recientes (no solo transferencias)
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

async function verMovimientosRecientes() {
  console.log('🔍 Viendo movimientos más recientes...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Convertir y ordenar por fecha de creación (más recientes primero)
    const movimientosOrdenados = movimientos
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt))
      .slice(0, 10); // Solo los 10 más recientes

    console.log('📊 LOS 10 MOVIMIENTOS MÁS RECIENTES:\\n');
    console.log('='.repeat(100));

    const ahora = new Date();
    const hoyInicio = new Date(ahora.getFullYear(), ahora.getMonth(), ahora.getDate());

    for (const mov of movimientosOrdenados) {
      const fechaCreacion = new Date(mov.createdAt);
      const esDeHoy = fechaCreacion >= hoyInicio;
      const marcador = esDeHoy ? '🆕 HOY' : '   ';

      console.log(`\\n${marcador} 📌 ID: ${mov.id}`);
      console.log(`   Creado: ${fechaCreacion.toLocaleString('es-MX')} (${fechaCreacion.toISOString()})`);
      console.log(`   Tipo: ${mov.tipo} | Monto: $${mov.monto}`);
      console.log(`   Cuenta: ${mov.cuentaId}`);
      console.log(`   Descripción: ${mov.descripcion}`);

      // Verificar si es transferencia
      if (mov.movimientoVinculadoId) {
        console.log(`   🔗 ES TRANSFERENCIA - Vinculado a: ${mov.movimientoVinculadoId} | Es Origen: ${mov.esOrigen}`);
      }

      // Verificar adjuntos
      const tieneAdjunto = mov.adjunto ? '✅' : '❌';
      const tieneAdjuntos = mov.adjuntos && mov.adjuntos.length > 0 ? '✅' : '❌';

      console.log(`   ${tieneAdjunto} adjunto: ${mov.adjunto ? 'SÍ' : 'NO'}`);
      console.log(`   ${tieneAdjuntos} adjuntos[]: ${mov.adjuntos && mov.adjuntos.length > 0 ? `SÍ (${mov.adjuntos.length})` : 'NO'}`);
      console.log('   ' + '-'.repeat(96));
    }

    console.log('='.repeat(100));

    // Resumen de hoy
    const movimientosHoy = movimientosOrdenados.filter(m => {
      const fechaCreacion = new Date(m.createdAt);
      return fechaCreacion >= hoyInicio;
    });

    console.log(`\\n📅 Movimientos creados HOY: ${movimientosHoy.length}`);
    if (movimientosHoy.length > 0) {
      const transferenciasHoy = movimientosHoy.filter(m => m.movimientoVinculadoId).length;
      console.log(`   🔗 Transferencias: ${transferenciasHoy}`);
      const conAdjuntos = movimientosHoy.filter(m => m.adjuntos && m.adjuntos.length > 0).length;
      console.log(`   📎 Con adjuntos: ${conAdjuntos}`);
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
verMovimientosRecientes();
