// Script para listar TODOS los movimientos ordenados por fecha de creación
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

async function listarTodos() {
  console.log('📋 Listando TODOS los movimientos...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    console.log(`📊 TOTAL DE MOVIMIENTOS EN BASE DE DATOS: ${movimientos.length}\\n`);

    // Convertir y ordenar por fecha de creación (más recientes primero)
    const ordenados = movimientos
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    console.log('='.repeat(120));
    console.log('LOS 30 MOVIMIENTOS MÁS RECIENTES:');
    console.log('='.repeat(120));
    console.log('');

    for (let i = 0; i < Math.min(30, ordenados.length); i++) {
      const mov = ordenados[i];
      const fechaCreacion = new Date(mov.createdAt);
      const fechaMov = new Date(mov.fecha);

      const esTransf = mov.movimientoVinculadoId ? '🔗TRANSF' : '       ';
      const tieneAdj = (mov.adjuntos && mov.adjuntos.length > 0) || mov.adjunto ? '📎ADJ' : '     ';
      const cancelado = mov.cancelado ? '❌CANC' : '      ';

      console.log(`${String(i + 1).padStart(2)}. ${esTransf} ${tieneAdj} ${cancelado} | ID: ${mov.id}`);
      console.log(`    Creado: ${fechaCreacion.toISOString()}`);
      console.log(`    Fecha Mov: ${fechaMov.toISOString().split('T')[0]} | Tipo: ${mov.tipo.padEnd(12)} | Monto: $${String(mov.monto).padStart(10)}`);
      console.log(`    Cuenta: ${mov.cuentaId}`);
      console.log(`    Desc: ${mov.descripcion.substring(0, 80)}`);

      if (mov.movimientoVinculadoId) {
        console.log(`    Vinculado: ${mov.movimientoVinculadoId} | EsOrigen: ${mov.esOrigen}`);
      }

      if (mov.adjunto || (mov.adjuntos && mov.adjuntos.length > 0)) {
        console.log(`    Adjunto: ${mov.adjunto ? 'SÍ' : 'NO'}`);
        console.log(`    Adjuntos[]: ${mov.adjuntos ? mov.adjuntos.length : 0}`);
      }

      console.log('    ' + '-'.repeat(116));
    }

    console.log('='.repeat(120));

    // Estadísticas
    const hoy = new Date();
    hoy.setHours(0, 0, 0, 0);

    const creados18Nov = ordenados.filter(m => {
      const f = new Date(m.createdAt);
      return f.getFullYear() === 2025 && f.getMonth() === 10 && f.getDate() === 18;
    });

    console.log(`\\n📅 Movimientos creados el 18 de noviembre de 2025: ${creados18Nov.length}`);

    if (creados18Nov.length > 0) {
      console.log('\\nDetalle de movimientos del 18 de noviembre:');
      for (const mov of creados18Nov) {
        const esTransf = mov.movimientoVinculadoId ? '🔗' : '  ';
        const tieneAdj = (mov.adjuntos && mov.adjuntos.length > 0) || mov.adjunto ? '📎' : '  ';
        console.log(`${esTransf}${tieneAdj} ${mov.id} | $${mov.monto} | ${mov.descripcion.substring(0, 50)}`);
      }
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
listarTodos();
