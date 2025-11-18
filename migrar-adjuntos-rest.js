// Script para migrar adjuntos de transferencias antiguas usando REST API
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
      else if (value.arrayValue) {
        data[key] = value.arrayValue.values?.map(v => v.stringValue || v) || [];
      }
    }
  }
  return data;
}

// Convertir objeto a formato Firestore
function toFirestoreFormat(obj) {
  const fields = {};
  for (const [key, value] of Object.entries(obj)) {
    if (Array.isArray(value)) {
      fields[key] = {
        arrayValue: {
          values: value.map(v => ({ stringValue: v }))
        }
      };
    } else if (typeof value === 'string') {
      fields[key] = { stringValue: value };
    }
  }
  return { fields };
}

async function migrarAdjuntosTransferencias() {
  console.log('🚀 Iniciando migración de adjuntos en transferencias...\n');

  try {
    // Hacer query a Firestore para obtener movimientos con movimientoVinculadoId
    const response = await firestoreRequest('/movimientos');

    const movimientos = response.documents || [];
    console.log(`📊 Total de movimientos encontrados: ${movimientos.length}\n`);

    let procesados = 0;
    let actualizados = 0;
    let errores = 0;

    for (const doc of movimientos) {
      const movimientoId = doc.name.split('/').pop();
      const movimiento = convertFirestoreDoc(doc);

      // Solo procesar si tiene movimientoVinculadoId
      if (!movimiento.movimientoVinculadoId) continue;

      procesados++;

      // Verificar si tiene adjuntos
      const adjuntos = movimiento.adjuntos || (movimiento.adjunto ? [movimiento.adjunto] : null);
      if (!adjuntos || adjuntos.length === 0) continue;

      try {
        // Obtener el movimiento vinculado
        const vinculadoId = movimiento.movimientoVinculadoId;
        const vinculadoDoc = await firestoreRequest(`/movimientos/${vinculadoId}`);
        const vinculado = convertFirestoreDoc(vinculadoDoc);

        // Si ya tiene adjuntos, skip
        if (vinculado.adjuntos || vinculado.adjunto) continue;

        // Actualizar el vinculado con los adjuntos
        const updateData = toFirestoreFormat({
          adjuntos: Array.isArray(adjuntos) ? adjuntos : [adjuntos],
          adjunto: Array.isArray(adjuntos) ? adjuntos[0] : adjuntos
        });

        await firestoreRequest(
          `/movimientos/${vinculadoId}?updateMask.fieldPaths=adjuntos&updateMask.fieldPaths=adjunto`,
          'PATCH',
          updateData
        );

        actualizados++;
        const adjuntosCount = Array.isArray(adjuntos) ? adjuntos.length : 1;
        console.log(`✅ Actualizado: ${movimientoId} → ${vinculadoId} (${adjuntosCount} adjunto(s) copiado(s))`);

      } catch (error) {
        console.error(`❌ Error al procesar ${movimientoId}:`, error.message);
        errores++;
      }
    }

    console.log('\n' + '='.repeat(60));
    console.log('📈 RESUMEN DE MIGRACIÓN:');
    console.log('='.repeat(60));
    console.log(`✅ Movimientos procesados: ${procesados}`);
    console.log(`🔄 Movimientos actualizados: ${actualizados}`);
    console.log(`❌ Errores: ${errores}`);
    console.log('='.repeat(60));

    if (actualizados > 0) {
      console.log(`\n🎉 ¡Migración completada! ${actualizados} movimiento(s) fueron actualizados con adjuntos.`);
    } else {
      console.log('\n✨ No se encontraron movimientos que necesiten actualización.');
    }

  } catch (error) {
    console.error('❌ Error general:', error.message);
  }
}

// Ejecutar
migrarAdjuntosTransferencias();
