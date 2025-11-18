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
  Timestamp
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
  EstadoCuenta
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
  console.log('🔍 getEmpresas - userId:', userId)
  try {
    const q = query(
      collection(db, 'empresas'),
      where('userId', '==', userId),
      where('activo', '==', true),
      orderBy('nombre')
    )

    console.log('📊 Ejecutando query de empresas...')
    const snapshot = await getDocs(q)
    console.log('✅ Query exitosa, documentos encontrados:', snapshot.size)
    return snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
      updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
    })) as Empresa[]
  } catch (error) {
    console.error('❌ Error en getEmpresas:', error)
    throw error
  }
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
  console.log('🔍 getCuentas - userId:', userId, 'empresaId:', empresaId)
  try {
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

    console.log('📊 Ejecutando query de cuentas...')
    const snapshot = await getDocs(q)
    console.log('✅ Query exitosa, documentos encontrados:', snapshot.size)
    return snapshot.docs.map(doc => ({
      id: doc.id,
      ...doc.data(),
      fechaApertura: doc.data().fechaApertura ? (doc.data().fechaApertura as Timestamp).toDate() : undefined,
      createdAt: (doc.data().createdAt as Timestamp)?.toDate() || new Date(),
      updatedAt: (doc.data().updatedAt as Timestamp)?.toDate() || new Date()
    })) as CuentaBancaria[]
  } catch (error) {
    console.error('❌ Error en getCuentas:', error)
    throw error
  }
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
  adjuntoUrl?: string
): Promise<string> {
  // Obtener la cuenta para calcular el nuevo saldo
  const cuenta = await getCuenta(cuentaId)
  if (!cuenta) {
    throw new Error('Cuenta no encontrada')
  }

  // Función para redondear a 2 decimales y evitar errores de precisión
  const roundMoney = (value: number) => Math.round(value * 100) / 100

  // Calcular el nuevo saldo
  const nuevoSaldo = roundMoney(
    data.tipo === 'ingreso'
      ? cuenta.saldoActual + data.monto
      : cuenta.saldoActual - data.monto
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
    adjunto: adjuntoUrl || null,
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
}

export async function deleteMovimiento(id: string): Promise<void> {
  const docRef = doc(db, 'movimientos', id)
  await updateDoc(docRef, {
    cancelado: true,
    updatedAt: serverTimestamp()
  })
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

  // Recalcular cada movimiento
  for (const docSnap of snapshot.docs) {
    const movimiento = docSnap.data() as Movimiento
    saldoActual = roundMoney(
      movimiento.tipo === 'ingreso'
        ? saldoActual + movimiento.monto
        : saldoActual - movimiento.monto
    )

    await updateDoc(doc(db, 'movimientos', docSnap.id), {
      saldoDespues: saldoActual,
      updatedAt: serverTimestamp()
    })
  }

  // Actualizar el saldo final de la cuenta
  await updateDoc(doc(db, 'cuentas', cuentaId), {
    saldoActual,
    updatedAt: serverTimestamp()
  })
}

// ============================================================================
// TRANSFERENCIAS ENTRE CUENTAS
// ============================================================================

export async function createTransferencia(
  userId: string,
  data: TransferenciaFormData
): Promise<{ origenId: string; destinoId: string }> {
  const { cuentaOrigenId, cuentaDestinoId, monto, fecha, descripcion, referencia, notas } = data

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

  // Calcular nuevos saldos
  const nuevoSaldoOrigen = roundMoney(cuentaOrigen.saldoActual - monto)
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
    descripcion: `Transferencia a ${cuentaDestino.nombre} - ${descripcion}`,
    referencia,
    notas,
    saldoDespues: nuevoSaldoOrigen,
    cuentaDestinoId,
    esOrigen: true,
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
    referencia,
    notas,
    saldoDespues: nuevoSaldoDestino,
    cuentaDestinoId: cuentaOrigenId, // La cuenta destino es la origen del movimiento vinculado
    esOrigen: false,
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
