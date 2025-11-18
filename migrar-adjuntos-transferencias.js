// Script para migrar adjuntos de transferencias antiguas
// Este script copia los adjuntos al movimiento vinculado en transferencias

const admin = require('firebase-admin');
const { execSync } = require('child_process');

// Obtener el access token de gcloud
const accessToken = execSync('gcloud auth print-access-token').toString().trim();

// Inicializar Firebase Admin con el token
process.env.GOOGLE_APPLICATION_CREDENTIALS = '';
process.env.FIRESTORE_EMULATOR_HOST = '';

admin.initializeApp({
  credential: admin.credential.applicationDefault(),
  projectId: 'estados-de-cuenta-bd1e5'
});

const db = admin.firestore();

async function migrarAdjuntosTransferencias() {
  console.log('🚀 Iniciando migración de adjuntos en transferencias...\n');

  try {
    // Obtener todos los movimientos que tienen movimientoVinculadoId (son transferencias)
    const movimientosSnapshot = await db.collection('movimientos')
      .where('movimientoVinculadoId', '!=', null)
      .get();

    console.log(`📊 Total de movimientos de transferencia encontrados: ${movimientosSnapshot.size}\n`);

    let procesados = 0;
    let actualizados = 0;
    let errores = 0;

    for (const docSnap of movimientosSnapshot.docs) {
      procesados++;
      const movimiento = docSnap.data();
      const movimientoId = docSnap.id;
      const vinculadoId = movimiento.movimientoVinculadoId;

      // Verificar si este movimiento tiene adjuntos
      const tieneAdjuntos = movimiento.adjuntos || movimiento.adjunto;

      if (!tieneAdjuntos) {
        continue; // Si no tiene adjuntos, pasar al siguiente
      }

      try {
        // Obtener el movimiento vinculado
        const vinculadoDoc = await db.collection('movimientos').doc(vinculadoId).get();

        if (!vinculadoDoc.exists) {
          console.log(`⚠️  Movimiento vinculado ${vinculadoId} no existe`);
          errores++;
          continue;
        }

        const vinculado = vinculadoDoc.data();
        const tieneAdjuntosVinculado = vinculado.adjuntos || vinculado.adjunto;

        // Si el vinculado YA tiene adjuntos, no hacer nada
        if (tieneAdjuntosVinculado) {
          continue;
        }

        // Preparar los adjuntos a copiar
        const adjuntosACopiar = movimiento.adjuntos || (movimiento.adjunto ? [movimiento.adjunto] : []);

        if (adjuntosACopiar.length === 0) {
          continue;
        }

        // Actualizar el movimiento vinculado con los adjuntos
        await db.collection('movimientos').doc(vinculadoId).update({
          adjuntos: adjuntosACopiar,
          adjunto: adjuntosACopiar[0], // Para compatibilidad
          updatedAt: admin.firestore.FieldValue.serverTimestamp()
        });

        actualizados++;
        console.log(`✅ Actualizado: ${movimientoId} → ${vinculadoId} (${adjuntosACopiar.length} adjuntos copiados)`);

      } catch (error) {
        console.error(`❌ Error al procesar movimiento ${movimientoId}:`, error.message);
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
      console.log(`\n🎉 ¡Migración completada! ${actualizados} movimientos fueron actualizados con adjuntos.`);
    } else {
      console.log('\n✨ No se encontraron movimientos que necesiten actualización.');
    }

  } catch (error) {
    console.error('❌ Error general en la migración:', error);
  }

  process.exit(0);
}

// Ejecutar la migración
migrarAdjuntosTransferencias();
