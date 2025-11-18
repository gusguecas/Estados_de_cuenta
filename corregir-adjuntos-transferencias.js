// Script para corregir adjuntos en transferencias existentes
// Copia adjuntos del movimiento que los tiene al que no los tiene
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

async function corregirAdjuntosTransferencias() {
  console.log('🔧 Corrigiendo adjuntos en transferencias...\\n');

  try {
    // Obtener todos los movimientos
    const response = await firestoreRequest('/movimientos');
    const movimientos = response.documents || [];

    // Filtrar solo transferencias
    const transferencias = movimientos
      .map(doc => ({
        id: doc.name.split('/').pop(),
        ...convertFirestoreDoc(doc)
      }))
      .filter(m => m.movimientoVinculadoId);

    console.log(`📊 Total de transferencias: ${transferencias.length}\\n`);

    let procesadas = 0;
    let corregidas = 0;

    console.log('='.repeat(100));

    for (const mov of transferencias) {
      procesadas++;

      // Verificar si tiene adjuntos
      const tieneAdjuntos = (mov.adjuntos && mov.adjuntos.length > 0) || mov.adjunto;

      if (!tieneAdjuntos) {
        continue; // Si no tiene adjuntos, no hay nada que copiar
      }

      try {
        // Obtener el movimiento vinculado
        const vinculadoDoc = await firestoreRequest(`/movimientos/${mov.movimientoVinculadoId}`);
        const vinculado = convertFirestoreDoc(vinculadoDoc);

        // Verificar si el vinculado YA tiene adjuntos
        const vinculadoTieneAdjuntos = (vinculado.adjuntos && vinculado.adjuntos.length > 0) || vinculado.adjunto;

        if (vinculadoTieneAdjuntos) {
          continue; // Ya tiene adjuntos, no hacer nada
        }

        // Preparar los adjuntos para copiar
        const adjuntosCopiar = mov.adjuntos || (mov.adjunto ? [mov.adjunto] : []);

        if (adjuntosCopiar.length === 0) {
          continue;
        }

        console.log(`\\n🔧 Corrigiendo par de transferencias:`);
        console.log(`   Origen: ${mov.id} (${mov.tipo}, $${mov.monto})`);
        console.log(`   Destino: ${mov.movimientoVinculadoId} (${vinculado.tipo}, $${vinculado.monto})`);
        console.log(`   Adjuntos a copiar: ${adjuntosCopiar.length}`);

        // Actualizar el movimiento vinculado
        const updateData = toFirestoreFormat({
          adjuntos: adjuntosCopiar,
          adjunto: adjuntosCopiar[0]
        });

        await firestoreRequest(
          `/movimientos/${mov.movimientoVinculadoId}?updateMask.fieldPaths=adjuntos&updateMask.fieldPaths=adjunto`,
          'PATCH',
          updateData
        );

        console.log(`   ✅ Adjuntos copiados correctamente`);
        corregidas++;

      } catch (error) {
        console.error(`   ❌ Error al procesar ${mov.id}: ${error.message}`);
      }
    }

    console.log('\\n' + '='.repeat(100));
    console.log('\\n📈 RESUMEN:');
    console.log(`   Transferencias procesadas: ${procesadas}`);
    console.log(`   Transferencias corregidas: ${corregidas}`);
    console.log('='.repeat(100));

    if (corregidas > 0) {
      console.log(`\\n🎉 Se corrigieron ${corregidas} transferencias.`);
      console.log('   Los adjuntos ahora aparecen en ambas cuentas.');
    } else {
      console.log(`\\n✨ No se encontraron transferencias que necesiten corrección.`);
    }

  } catch (error) {
    console.error('❌ Error:', error.message);
  }
}

// Ejecutar
corregirAdjuntosTransferencias();
