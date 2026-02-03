import {
  collection,
  addDoc,
  updateDoc,
  deleteDoc,
  doc,
  getDocs,
  getDoc,
  query,
  where,
  serverTimestamp,
  orderBy,
  Timestamp,
  writeBatch
} from 'firebase/firestore'
import { ref, uploadBytes, getDownloadURL } from 'firebase/storage'
import { db, storage } from './firebase'
import type {
  Empresa,
  EmpresaFormData,
  CuentaBancaria,
  CuentaBancariaFormData,
  Movimiento,
  MovimientoFormData,
  TransferenciaFormData,
  Categoria,
  TipoMovimiento,
  EstadoCuenta,
  DocumentoFinanciero,
  DocumentoFinancieroFormData,
  Persona,
  PersonaFormData,
  DocumentoPersonal,
  DocumentoPersonalFormData
} from './types'

// ============================================================================
// EMPRESAS
// ============================================================================

export async function createEmpresa(userId: string, data: EmpresaFormData): Promise<string> {
  const empresaRef = await addDoc(collection(db, 'empresas'), {
    ...data,
    userId,
    activo: true,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  })
  return empresaRef.id
}

export async function getEmpresas(userId: string): Promise<Empresa[]> {
  const q = query(
    collection(db, 'empresas'),
    where('userId', '==', userId),
    where('activo', '==', true),
    orderBy('nombre')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as Empresa[]
}

export async function getEmpresa(id: string): Promise<Empresa | null> {
  const docRef = doc(db, 'empresas', id)
  const docSnap = await getDoc(docRef)

  if (!docSnap.exists()) {
    return null
  }

  return {
    id: docSnap.id,
    ...docSnap.data(),
    createdAt: (docSnap.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (docSnap.data().updatedAt as Timestamp)?.toDate() || new Date()
  } as Empresa
}

export async function updateEmpresa(id: string, data: Partial<EmpresaFormData>): Promise<void> {
  const docRef = doc(db, 'empresas', id)
  await updateDoc(docRef, {
    ...data,
    updatedAt: serverTimestamp()
  })
}

export async function deleteEmpresa(id: string): Promise<void> {
  const docRef = doc(db, 'empresas', id)
  await updateDoc(docRef, {
    activo: false,
    updatedAt: serverTimestamp()
  })
}

// ============================================================================
// CUENTAS BANCARIAS
// ============================================================================

export async function createCuenta(userId: string, empresaId: string, data: CuentaBancariaFormData): Promise<string> {
  const cuentaRef = await addDoc(collection(db, 'cuentas'), {
    ...data,
    userId,
    empresaId, // "personal" para cuentas personales
    saldoActual: data.saldoInicial,
    activo: true,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  })
  return cuentaRef.id
}

export async function getCuentas(userId: string, empresaId?: string): Promise<CuentaBancaria[]> {
  let q

  if (empresaId) {
    q = query(
      collection(db, 'cuentas'),
      where('userId', '==', userId),
      where('empresaId', '==', empresaId),
      where('activo', '==', true),
      orderBy('nombre')
    )
  } else {
    q = query(
      collection(db, 'cuentas'),
      where('userId', '==', userId),
      where('activo', '==', true),
      orderBy('nombre')
    )
  }

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fechaApertura: doc.data().fechaApertura ? (doc.data().fechaApertura as Timestamp).toDate() : undefined,
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as CuentaBancaria[]
}

export async function getCuenta(id: string): Promise<CuentaBancaria | null> {
  const docRef = doc(db, 'cuentas', id)
  const docSnap = await getDoc(docRef)

  if (!docSnap.exists()) {
    return null
  }

  return {
    id: docSnap.id,
    ...docSnap.data(),
    fechaApertura: docSnap.data().fechaApertura ? (docSnap.data().fechaApertura as Timestamp).toDate() : undefined,
    createdAt: (docSnap.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (docSnap.data().updatedAt as Timestamp)?.toDate() || new Date()
  } as CuentaBancaria
}

export async function updateCuenta(id: string, data: Partial<CuentaBancariaFormData>): Promise<void> {
  const docRef = doc(db, 'cuentas', id)
  await updateDoc(docRef, {
    ...data,
    updatedAt: serverTimestamp()
  })
}

export async function deleteCuenta(id: string): Promise<void> {
  const docRef = doc(db, 'cuentas', id)
  await updateDoc(docRef, {
    activo: false,
    updatedAt: serverTimestamp()
  })
}

// ============================================================================
// MOVIMIENTOS
// ============================================================================

// Función para subir archivo adjunto de movimiento
export async function uploadMovimientoAdjunto(
  file: File,
  userId: string,
  cuentaId: string
): Promise<string> {
  const timestamp = Date.now()
  const fileName = `${timestamp}_${file.name}`
  const storageRef = ref(storage, `movimientos/${userId}/${cuentaId}/${fileName}`)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

export async function createMovimiento(
  userId: string,
  cuentaId: string,
  data: MovimientoFormData,
  adjuntosUrls?: string[]
): Promise<string> {
  // Obtener la cuenta para calcular el nuevo saldo
  const cuenta = await getCuenta(cuentaId)
  if (!cuenta) {
    throw new Error('Cuenta no encontrada')
  }

  // Función para redondear a 2 decimales y evitar errores de precisión
  const roundMoney = (value: number) => Math.round(value * 100) / 100

  // Calcular el nuevo saldo (la comisión siempre se resta)
  const comision = data.comision || 0
  const nuevoSaldo = roundMoney(
    data.tipo === 'ingreso'
      ? cuenta.saldoActual + data.monto - comision
      : cuenta.saldoActual - data.monto - comision
  )

  // Crear el movimiento con fecha en UTC para evitar problemas de zona horaria
  const [year, month, day] = data.fecha.split('-').map(Number)
  const fechaUTC = new Date(Date.UTC(year, month - 1, day))

  const movimientoRef = await addDoc(collection(db, 'movimientos'), {
    ...data,
    userId,
    cuentaId,
    fecha: fechaUTC,
    saldoDespues: nuevoSaldo,
    adjuntos: adjuntosUrls && adjuntosUrls.length > 0 ? adjuntosUrls : null,
    // Mantener adjunto para compatibilidad con registros antiguos
    adjunto: adjuntosUrls && adjuntosUrls.length > 0 ? adjuntosUrls[0] : null,
    cancelado: false,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  })

  // Actualizar el saldo de la cuenta
  await updateDoc(doc(db, 'cuentas', cuentaId), {
    saldoActual: nuevoSaldo,
    updatedAt: serverTimestamp()
  })

  return movimientoRef.id
}

export async function getMovimientos(cuentaId: string): Promise<Movimiento[]> {
  const q = query(
    collection(db, 'movimientos'),
    where('cuentaId', '==', cuentaId),
    where('cancelado', '==', false),
    orderBy('fecha', 'desc')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fecha: (doc.data().fecha as Timestamp).toDate(),
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as Movimiento[]
}

export async function getAllMovimientos(userId: string): Promise<Movimiento[]> {
  const q = query(
    collection(db, 'movimientos'),
    where('userId', '==', userId),
    where('cancelado', '==', false),
    orderBy('fecha', 'desc')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fecha: (doc.data().fecha as Timestamp).toDate(),
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as Movimiento[]
}

export async function updateMovimiento(id: string, data: Partial<MovimientoFormData>): Promise<void> {
  const docRef = doc(db, 'movimientos', id)
  const movimiento = await getDoc(docRef)

  if (!movimiento.exists()) {
    throw new Error('Movimiento no encontrado')
  }

  const movimientoData = movimiento.data()
  const cuentaIdAnterior = movimientoData.cuentaId
  const cuentaIdNueva = data.cuentaId

  const updateData: Record<string, unknown> = {
    ...data,
    updatedAt: serverTimestamp()
  }

  if (data.fecha) {
    // Usar UTC para evitar problemas de zona horaria
    const [year, month, day] = data.fecha.split('-').map(Number)
    updateData.fecha = new Date(Date.UTC(year, month - 1, day))
  }

  await updateDoc(docRef, updateData)

  // Si cambió la cuenta, recalcular saldos de ambas cuentas
  if (cuentaIdNueva && cuentaIdNueva !== cuentaIdAnterior) {
    await recalcularSaldos(cuentaIdAnterior)
    await recalcularSaldos(cuentaIdNueva)
  } else if (cuentaIdAnterior) {
    // Si no cambió la cuenta, solo recalcular la cuenta actual
    await recalcularSaldos(cuentaIdAnterior)
  }
}

export async function deleteMovimiento(id: string): Promise<void> {
  const docRef = doc(db, 'movimientos', id)
  const movimientoSnap = await getDoc(docRef)

  if (!movimientoSnap.exists()) {
    throw new Error('Movimiento no encontrado')
  }

  const movimientoData = movimientoSnap.data()
  const cuentaId = movimientoData.cuentaId
  let movimientoVinculadoId = movimientoData.movimientoVinculadoId
  const cuentaDestinoId = movimientoData.cuentaDestinoId

  console.log('🗑️ Eliminando movimiento:', id)
  console.log('  - cuentaId:', cuentaId)
  console.log('  - movimientoVinculadoId:', movimientoVinculadoId)
  console.log('  - cuentaDestinoId:', cuentaDestinoId)

  // Cancelar el movimiento principal
  await updateDoc(docRef, {
    cancelado: true,
    updatedAt: serverTimestamp()
  })
  console.log('✅ Movimiento principal cancelado')

  // Si es una transferencia, buscar y cancelar el movimiento vinculado
  // Puede tener movimientoVinculadoId directo, o podemos buscarlo por cuentaDestinoId
  if (movimientoVinculadoId || cuentaDestinoId) {
    let vinculadoRef = null
    let vinculadoSnap = null
    let vinculadoData = null

    // Primero intentar con movimientoVinculadoId si existe
    if (movimientoVinculadoId) {
      vinculadoRef = doc(db, 'movimientos', movimientoVinculadoId)
      vinculadoSnap = await getDoc(vinculadoRef)
      if (vinculadoSnap.exists()) {
        vinculadoData = vinculadoSnap.data()
        console.log('✅ Encontrado movimiento vinculado por ID:', movimientoVinculadoId)
      }
    }

    // Si no encontramos por ID, buscar por criterios de transferencia
    if (!vinculadoData && cuentaDestinoId) {
      console.log('🔍 Buscando movimiento vinculado en cuenta:', cuentaDestinoId)

      // Buscar movimiento en la cuenta destino con el mismo monto, fecha similar y que nos apunte
      const fechaMovimiento = movimientoData.fecha
      const montoMovimiento = movimientoData.monto
      const tipoOpuesto = movimientoData.tipo === 'egreso' ? 'ingreso' : 'egreso'

      const qVinculado = query(
        collection(db, 'movimientos'),
        where('cuentaId', '==', cuentaDestinoId),
        where('cancelado', '==', false),
        where('tipo', '==', tipoOpuesto),
        where('monto', '==', montoMovimiento)
      )

      const vinculadosSnapshot = await getDocs(qVinculado)

      // Buscar el que coincida mejor (mismo movimientoVinculadoId que apunte a nosotros, o misma fecha)
      for (const docSnap of vinculadosSnapshot.docs) {
        const data = docSnap.data()
        // Verificar si nos apunta directamente
        if (data.movimientoVinculadoId === id) {
          vinculadoRef = doc(db, 'movimientos', docSnap.id)
          vinculadoSnap = docSnap
          vinculadoData = data
          movimientoVinculadoId = docSnap.id
          console.log('✅ Encontrado movimiento vinculado que nos apunta:', docSnap.id)
          break
        }
        // O verificar si tiene la misma cuentaDestinoId apuntando a nuestra cuenta
        if (data.cuentaDestinoId === cuentaId) {
          // Verificar fecha similar (mismo día)
          const fechaVinculado = data.fecha?.toDate ? data.fecha.toDate() : new Date(data.fecha)
          const fechaOriginal = fechaMovimiento?.toDate ? fechaMovimiento.toDate() : new Date(fechaMovimiento)

          if (fechaVinculado.toDateString() === fechaOriginal.toDateString()) {
            vinculadoRef = doc(db, 'movimientos', docSnap.id)
            vinculadoSnap = docSnap
            vinculadoData = data
            movimientoVinculadoId = docSnap.id
            console.log('✅ Encontrado movimiento vinculado por criterios:', docSnap.id)
            break
          }
        }
      }
    }

    // Si encontramos el movimiento vinculado, cancelarlo
    if (vinculadoData && vinculadoRef) {
      const cuentaVinculadaId = vinculadoData.cuentaId

      // Cancelar el movimiento vinculado
      await updateDoc(vinculadoRef, {
        cancelado: true,
        updatedAt: serverTimestamp()
      })
      console.log('✅ Movimiento vinculado cancelado:', movimientoVinculadoId)

      // Recalcular saldos de la cuenta vinculada
      if (cuentaVinculadaId) {
        await recalcularSaldos(cuentaVinculadaId)
        console.log('✅ Saldos recalculados para cuenta vinculada:', cuentaVinculadaId)
      }
    } else {
      console.log('⚠️ No se encontró movimiento vinculado para cancelar')
    }
  }

  // Recalcular saldos de la cuenta principal
  if (cuentaId) {
    await recalcularSaldos(cuentaId)
    console.log('✅ Saldos recalculados para cuenta principal:', cuentaId)
  }
}

export async function recalcularSaldos(cuentaId: string): Promise<void> {
  // Obtener la cuenta
  const cuenta = await getCuenta(cuentaId)
  if (!cuenta) {
    throw new Error('Cuenta no encontrada')
  }

  // Función para redondear a 2 decimales y evitar errores de precisión
  const roundMoney = (value: number) => Math.round(value * 100) / 100

  // Obtener todos los movimientos ordenados por fecha
  const q = query(
    collection(db, 'movimientos'),
    where('cuentaId', '==', cuentaId),
    where('cancelado', '==', false),
    orderBy('fecha', 'asc')
  )

  const snapshot = await getDocs(q)
  let saldoActual = cuenta.saldoInicial

  console.log(`📊 Recalculando ${snapshot.size} movimientos para cuenta ${cuentaId}`)

  // Usar batch writes para mayor velocidad (máximo 500 por batch)
  const BATCH_SIZE = 500
  let batch = writeBatch(db)
  let operationsInBatch = 0

  for (const docSnap of snapshot.docs) {
    const movimiento = docSnap.data() as Movimiento
    const comision = movimiento.comision || 0
    saldoActual = roundMoney(
      movimiento.tipo === 'ingreso'
        ? saldoActual + movimiento.monto - comision
        : saldoActual - movimiento.monto - comision
    )

    // Solo actualizar si el saldo cambió
    if (movimiento.saldoDespues !== saldoActual) {
      batch.update(doc(db, 'movimientos', docSnap.id), {
        saldoDespues: saldoActual
      })
      operationsInBatch++

      // Si llegamos al límite del batch, ejecutarlo y crear uno nuevo
      if (operationsInBatch >= BATCH_SIZE) {
        await batch.commit()
        batch = writeBatch(db)
        operationsInBatch = 0
      }
    }
  }

  // Agregar la actualización de la cuenta al batch final
  batch.update(doc(db, 'cuentas', cuentaId), {
    saldoActual,
    updatedAt: serverTimestamp()
  })
  operationsInBatch++

  // Ejecutar el batch final si tiene operaciones
  if (operationsInBatch > 0) {
    await batch.commit()
  }

  console.log(`✅ Recálculo completado - Saldo final: ${saldoActual}`)
}

// ============================================================================
// TRANSFERENCIAS ENTRE CUENTAS
// ============================================================================

export async function createTransferencia(
  userId: string,
  data: TransferenciaFormData
): Promise<{ origenId: string; destinoId: string }> {
  const { cuentaOrigenId, cuentaDestinoId, monto, comision, fecha, descripcion, categoriaId, referencia, beneficiario, notas, adjuntos } = data

  // Verificar que las cuentas existan y obtener sus datos
  const [cuentaOrigen, cuentaDestino] = await Promise.all([
    getCuenta(cuentaOrigenId),
    getCuenta(cuentaDestinoId)
  ])

  if (!cuentaOrigen || !cuentaDestino) {
    throw new Error('Una de las cuentas no existe')
  }

  if (cuentaOrigenId === cuentaDestinoId) {
    throw new Error('No puedes transferir a la misma cuenta')
  }

  // Función para redondear a 2 decimales y evitar errores de precisión
  const roundMoney = (value: number) => Math.round(value * 100) / 100

  // Calcular nuevos saldos (la comisión se resta de la cuenta origen)
  const comisionMonto = comision || 0
  const nuevoSaldoOrigen = roundMoney(cuentaOrigen.saldoActual - monto - comisionMonto)
  const nuevoSaldoDestino = roundMoney(cuentaDestino.saldoActual + monto)

  // Usar UTC para evitar problemas de zona horaria
  const [year, month, day] = fecha.split('-').map(Number)
  const fechaMovimiento = new Date(Date.UTC(year, month - 1, day))
  const timestampNow = serverTimestamp()

  // Crear el movimiento de SALIDA (egreso en cuenta origen)
  const movimientoOrigenData = {
    cuentaId: cuentaOrigenId,
    userId,
    fecha: fechaMovimiento,
    tipo: 'egreso' as TipoMovimiento,
    monto,
    comision: comisionMonto > 0 ? comisionMonto : null,
    descripcion: `Transferencia a ${cuentaDestino.nombre} - ${descripcion}`,
    categoriaId: categoriaId || null,
    referencia,
    beneficiario: beneficiario || null,
    notas,
    saldoDespues: nuevoSaldoOrigen,
    cuentaDestinoId,
    esOrigen: true,
    // Agregar adjuntos a ambos movimientos
    adjuntos: adjuntos && adjuntos.length > 0 ? adjuntos : null,
    adjunto: adjuntos && adjuntos.length > 0 ? adjuntos[0] : null,
    cancelado: false,
    createdAt: timestampNow,
    updatedAt: timestampNow
  }

  // Crear el movimiento de ENTRADA (ingreso en cuenta destino)
  const movimientoDestinoData = {
    cuentaId: cuentaDestinoId,
    userId,
    fecha: fechaMovimiento,
    tipo: 'ingreso' as TipoMovimiento,
    monto,
    descripcion: `Transferencia desde ${cuentaOrigen.nombre} - ${descripcion}`,
    categoriaId: categoriaId || null,
    referencia,
    beneficiario: beneficiario || null,
    notas,
    saldoDespues: nuevoSaldoDestino,
    cuentaDestinoId: cuentaOrigenId, // La cuenta destino es la origen del movimiento vinculado
    esOrigen: false,
    // Agregar los MISMOS adjuntos en ambos movimientos
    adjuntos: adjuntos && adjuntos.length > 0 ? adjuntos : null,
    adjunto: adjuntos && adjuntos.length > 0 ? adjuntos[0] : null,
    cancelado: false,
    createdAt: timestampNow,
    updatedAt: timestampNow
  }

  // Crear ambos movimientos
  const [movimientoOrigenRef, movimientoDestinoRef] = await Promise.all([
    addDoc(collection(db, 'movimientos'), movimientoOrigenData),
    addDoc(collection(db, 'movimientos'), movimientoDestinoData)
  ])

  // Vincular los movimientos entre sí
  await Promise.all([
    updateDoc(doc(db, 'movimientos', movimientoOrigenRef.id), {
      movimientoVinculadoId: movimientoDestinoRef.id
    }),
    updateDoc(doc(db, 'movimientos', movimientoDestinoRef.id), {
      movimientoVinculadoId: movimientoOrigenRef.id
    })
  ])

  // Actualizar los saldos de ambas cuentas
  await Promise.all([
    updateDoc(doc(db, 'cuentas', cuentaOrigenId), {
      saldoActual: nuevoSaldoOrigen,
      updatedAt: timestampNow
    }),
    updateDoc(doc(db, 'cuentas', cuentaDestinoId), {
      saldoActual: nuevoSaldoDestino,
      updatedAt: timestampNow
    })
  ])

  return {
    origenId: movimientoOrigenRef.id,
    destinoId: movimientoDestinoRef.id
  }
}

// ============================================================================
// CATEGORÍAS
// ============================================================================

export async function getCategorias(userId: string): Promise<Categoria[]> {
  const q = query(
    collection(db, 'categorias'),
    where('userId', '==', userId),
    where('activo', '==', true),
    orderBy('nombre')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data()
  })) as Categoria[]
}

export async function createCategoria(userId: string, nombre: string, tipo: 'ingreso' | 'egreso'): Promise<string> {
  const categoriaRef = await addDoc(collection(db, 'categorias'), {
    userId,
    nombre,
    tipo,
    activo: true
  })
  return categoriaRef.id
}

export async function updateCategoria(id: string, nombre: string): Promise<void> {
  const docRef = doc(db, 'categorias', id)
  await updateDoc(docRef, {
    nombre
  })
}

export async function deleteCategoria(id: string): Promise<void> {
  const docRef = doc(db, 'categorias', id)
  await updateDoc(docRef, {
    activo: false
  })
}

// ============= Estados de Cuenta =============

export async function getEstadosCuenta(cuentaId: string): Promise<EstadoCuenta[]> {
  const q = query(
    collection(db, 'estados_cuenta'),
    where('cuentaId', '==', cuentaId),
    orderBy('ano', 'desc'),
    orderBy('mes', 'desc')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => {
    const data = doc.data()
    return {
      id: doc.id,
      cuentaId: data.cuentaId as string,
      userId: data.userId as string,
      mes: data.mes as number,
      año: data.ano as number,
      archivoUrl: data.archivoUrl as string,
      uploadedAt: (data.fechaCarga as Timestamp)?.toDate() || new Date()
    }
  })
}

export async function createEstadoCuenta(
  userId: string,
  cuentaId: string,
  mes: number,
  ano: number,
  archivoUrl: string
): Promise<string> {
  const estadoRef = await addDoc(collection(db, 'estados_cuenta'), {
    userId,
    cuentaId,
    mes,
    ano,
    archivoUrl,
    fechaCarga: serverTimestamp(),
    createdAt: serverTimestamp()
  })
  return estadoRef.id
}

export async function deleteEstadoCuenta(id: string): Promise<void> {
  await deleteDoc(doc(db, 'estados_cuenta', id))
}

export async function uploadEstadoCuentaPDF(file: File, cuentaId: string, mes: number, año: number): Promise<string> {
  const fileName = `estados-cuenta/${cuentaId}/${año}-${String(mes).padStart(2, '0')}.pdf`
  const storageRef = ref(storage, fileName)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

export async function uploadEmpresaLogo(file: File, empresaId: string): Promise<string> {
  const fileExtension = file.name.split('.').pop()
  const fileName = `empresas/${empresaId}/logo.${fileExtension}`
  const storageRef = ref(storage, fileName)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

export async function uploadCuentaLogo(file: File, cuentaId: string): Promise<string> {
  const fileExtension = file.name.split('.').pop()
  const fileName = `cuentas/${cuentaId}/logo.${fileExtension}`
  const storageRef = ref(storage, fileName)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

// ============================================================================
// DOCUMENTOS FINANCIEROS
// ============================================================================

export async function uploadDocumentoFinancieroPDF(
  file: File,
  userId: string
): Promise<string> {
  const timestamp = Date.now()
  const fileName = `documentos-financieros/${userId}/${timestamp}_${file.name}`
  const storageRef = ref(storage, fileName)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

export async function createDocumentoFinanciero(
  userId: string,
  data: DocumentoFinancieroFormData,
  archivoUrl: string,
  nombreArchivo: string,
  tamanioArchivo: number
): Promise<string> {
  const docRef = await addDoc(collection(db, 'documentos_financieros'), {
    ...data,
    userId,
    archivoUrl,
    nombreArchivo,
    tamanioArchivo,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  })
  return docRef.id
}

export async function getDocumentosFinancieros(userId: string): Promise<DocumentoFinanciero[]> {
  const q = query(
    collection(db, 'documentos_financieros'),
    where('userId', '==', userId),
    orderBy('createdAt', 'desc')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as DocumentoFinanciero[]
}

export async function deleteDocumentoFinanciero(id: string): Promise<void> {
  await deleteDoc(doc(db, 'documentos_financieros', id))
}

// ============================================================================
// PERSONAS (FAMILIARES)
// ============================================================================

export async function createPersona(userId: string, data: PersonaFormData): Promise<string> {
  const personaData: Record<string, unknown> = {
    userId,
    nombre: data.nombre,
    apellidos: data.apellidos,
    parentesco: data.parentesco,
    activo: true,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  }

  // Solo agregar campos opcionales si tienen valor
  if (data.fechaNacimiento) {
    const [year, month, day] = data.fechaNacimiento.split('-').map(Number)
    personaData.fechaNacimiento = new Date(Date.UTC(year, month - 1, day))
  }
  if (data.email) personaData.email = data.email
  if (data.telefono) personaData.telefono = data.telefono
  if (data.notas) personaData.notas = data.notas

  const personaRef = await addDoc(collection(db, 'personas'), personaData)
  return personaRef.id
}

export async function getPersonas(userId: string): Promise<Persona[]> {
  const q = query(
    collection(db, 'personas'),
    where('userId', '==', userId),
    where('activo', '==', true),
    orderBy('nombre')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fechaNacimiento: doc.data().fechaNacimiento ? (doc.data().fechaNacimiento as Timestamp).toDate() : undefined,
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as Persona[]
}

export async function getPersona(id: string): Promise<Persona | null> {
  const docRef = doc(db, 'personas', id)
  const docSnap = await getDoc(docRef)

  if (!docSnap.exists()) {
    return null
  }

  return {
    id: docSnap.id,
    ...docSnap.data(),
    fechaNacimiento: docSnap.data().fechaNacimiento ? (docSnap.data().fechaNacimiento as Timestamp).toDate() : undefined,
    createdAt: (docSnap.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (docSnap.data().updatedAt as Timestamp)?.toDate() || new Date()
  } as Persona
}

export async function updatePersona(id: string, data: Partial<PersonaFormData>): Promise<void> {
  const updateData: Record<string, unknown> = {
    updatedAt: serverTimestamp()
  }

  // Solo agregar campos si tienen valor
  if (data.nombre) updateData.nombre = data.nombre
  if (data.apellidos) updateData.apellidos = data.apellidos
  if (data.parentesco) updateData.parentesco = data.parentesco
  if (data.email) updateData.email = data.email
  if (data.telefono) updateData.telefono = data.telefono
  if (data.notas) updateData.notas = data.notas

  // Convertir fecha de nacimiento si existe
  if (data.fechaNacimiento) {
    const [year, month, day] = data.fechaNacimiento.split('-').map(Number)
    updateData.fechaNacimiento = new Date(Date.UTC(year, month - 1, day))
  }

  const docRef = doc(db, 'personas', id)
  await updateDoc(docRef, updateData)
}

export async function deletePersona(id: string): Promise<void> {
  const docRef = doc(db, 'personas', id)
  await updateDoc(docRef, {
    activo: false,
    updatedAt: serverTimestamp()
  })
}

// ============================================================================
// DOCUMENTOS PERSONALES (IDENTIDAD)
// ============================================================================

export async function uploadDocumentoPersonalArchivo(
  file: File,
  userId: string,
  personaId: string
): Promise<string> {
  const timestamp = Date.now()
  const fileName = `documentos-personales/${userId}/${personaId}/${timestamp}_${file.name}`
  const storageRef = ref(storage, fileName)

  await uploadBytes(storageRef, file)
  const downloadURL = await getDownloadURL(storageRef)

  return downloadURL
}

export async function createDocumentoPersonal(
  userId: string,
  data: DocumentoPersonalFormData,
  archivoUrl?: string,
  nombreArchivo?: string,
  tamanioArchivo?: number
): Promise<string> {
  const docData: Record<string, unknown> = {
    userId,
    personaId: data.personaId,
    tipoDocumento: data.tipoDocumento,
    nombre: data.nombre,
    activo: true,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp()
  }

  // Solo agregar campos opcionales si tienen valor
  if (data.numeroDocumento) docData.numeroDocumento = data.numeroDocumento
  if (data.lugarExpedicion) docData.lugarExpedicion = data.lugarExpedicion
  if (data.entidadEmisora) docData.entidadEmisora = data.entidadEmisora
  if (data.notas) docData.notas = data.notas
  if (archivoUrl) docData.archivoUrl = archivoUrl
  if (nombreArchivo) docData.nombreArchivo = nombreArchivo
  if (tamanioArchivo) docData.tamanioArchivo = tamanioArchivo

  // Convertir fechas si existen
  if (data.fechaExpedicion) {
    const [year, month, day] = data.fechaExpedicion.split('-').map(Number)
    docData.fechaExpedicion = new Date(Date.UTC(year, month - 1, day))
  }

  if (data.fechaVencimiento) {
    const [year, month, day] = data.fechaVencimiento.split('-').map(Number)
    docData.fechaVencimiento = new Date(Date.UTC(year, month - 1, day))
  }

  const docRef = await addDoc(collection(db, 'documentos_personales'), docData)
  return docRef.id
}

export async function getDocumentosPersonales(userId: string, personaId?: string): Promise<DocumentoPersonal[]> {
  let q

  if (personaId) {
    q = query(
      collection(db, 'documentos_personales'),
      where('userId', '==', userId),
      where('personaId', '==', personaId),
      where('activo', '==', true),
      orderBy('createdAt', 'desc')
    )
  } else {
    q = query(
      collection(db, 'documentos_personales'),
      where('userId', '==', userId),
      where('activo', '==', true),
      orderBy('createdAt', 'desc')
    )
  }

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fechaExpedicion: doc.data().fechaExpedicion ? (doc.data().fechaExpedicion as Timestamp).toDate() : undefined,
    fechaVencimiento: doc.data().fechaVencimiento ? (doc.data().fechaVencimiento as Timestamp).toDate() : undefined,
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as DocumentoPersonal[]
}

export async function getDocumentoPersonal(id: string): Promise<DocumentoPersonal | null> {
  const docRef = doc(db, 'documentos_personales', id)
  const docSnap = await getDoc(docRef)

  if (!docSnap.exists()) {
    return null
  }

  return {
    id: docSnap.id,
    ...docSnap.data(),
    fechaExpedicion: docSnap.data().fechaExpedicion ? (docSnap.data().fechaExpedicion as Timestamp).toDate() : undefined,
    fechaVencimiento: docSnap.data().fechaVencimiento ? (docSnap.data().fechaVencimiento as Timestamp).toDate() : undefined,
    createdAt: (docSnap.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (docSnap.data().updatedAt as Timestamp)?.toDate() || new Date()
  } as DocumentoPersonal
}

export async function updateDocumentoPersonal(
  id: string,
  data: Partial<DocumentoPersonalFormData>,
  archivoUrl?: string,
  nombreArchivo?: string,
  tamanioArchivo?: number
): Promise<void> {
  const updateData: Record<string, unknown> = {
    updatedAt: serverTimestamp()
  }

  // Solo agregar campos si tienen valor
  if (data.personaId) updateData.personaId = data.personaId
  if (data.tipoDocumento) updateData.tipoDocumento = data.tipoDocumento
  if (data.nombre) updateData.nombre = data.nombre
  if (data.numeroDocumento) updateData.numeroDocumento = data.numeroDocumento
  if (data.lugarExpedicion) updateData.lugarExpedicion = data.lugarExpedicion
  if (data.entidadEmisora) updateData.entidadEmisora = data.entidadEmisora
  if (data.notas) updateData.notas = data.notas

  // Agregar archivo si se proporciona
  if (archivoUrl) {
    updateData.archivoUrl = archivoUrl
    updateData.nombreArchivo = nombreArchivo
    updateData.tamanioArchivo = tamanioArchivo
  }

  // Convertir fechas si existen
  if (data.fechaExpedicion) {
    const [year, month, day] = data.fechaExpedicion.split('-').map(Number)
    updateData.fechaExpedicion = new Date(Date.UTC(year, month - 1, day))
  }

  if (data.fechaVencimiento) {
    const [year, month, day] = data.fechaVencimiento.split('-').map(Number)
    updateData.fechaVencimiento = new Date(Date.UTC(year, month - 1, day))
  }

  const docRef = doc(db, 'documentos_personales', id)
  await updateDoc(docRef, updateData)
}

export async function deleteDocumentoPersonal(id: string): Promise<void> {
  const docRef = doc(db, 'documentos_personales', id)
  await updateDoc(docRef, {
    activo: false,
    updatedAt: serverTimestamp()
  })
}

// Obtener documentos próximos a vencer (para alertas)
export async function getDocumentosProximosAVencer(userId: string, diasAnticipacion: number = 30): Promise<DocumentoPersonal[]> {
  const hoy = new Date()
  const fechaLimite = new Date()
  fechaLimite.setDate(hoy.getDate() + diasAnticipacion)

  const q = query(
    collection(db, 'documentos_personales'),
    where('userId', '==', userId),
    where('activo', '==', true),
    where('fechaVencimiento', '>=', hoy),
    where('fechaVencimiento', '<=', fechaLimite),
    orderBy('fechaVencimiento', 'asc')
  )

  const snapshot = await getDocs(q)
  return snapshot.docs.map(doc => ({
    id: doc.id,
    ...doc.data(),
    fechaExpedicion: doc.data().fechaExpedicion ? (doc.data().fechaExpedicion as Timestamp).toDate() : undefined,
    fechaVencimiento: doc.data().fechaVencimiento ? (doc.data().fechaVencimiento as Timestamp).toDate() : undefined,
    createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
    updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
  })) as DocumentoPersonal[]
}
