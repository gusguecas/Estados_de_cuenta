import {
  collection,
  addDoc,
  updateDoc,
  doc,
  getDocs,
  getDoc,
  query,
  where,
  serverTimestamp,
  orderBy,
  Timestamp
} from 'firebase/firestore'
import { db } from './firebase'
import type {
  Empresa,
  EmpresaFormData,
  CuentaBancaria,
  CuentaBancariaFormData,
  Movimiento,
  MovimientoFormData,
  Categoria
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

export async function createMovimiento(
  userId: string,
  cuentaId: string,
  data: MovimientoFormData
): Promise<string> {
  // Obtener la cuenta para calcular el nuevo saldo
  const cuenta = await getCuenta(cuentaId)
  if (!cuenta) {
    throw new Error('Cuenta no encontrada')
  }

  // Calcular el nuevo saldo
  const nuevoSaldo = data.tipo === 'ingreso'
    ? cuenta.saldoActual + data.monto
    : cuenta.saldoActual - data.monto

  // Crear el movimiento
  const movimientoRef = await addDoc(collection(db, 'movimientos'), {
    ...data,
    userId,
    cuentaId,
    fecha: new Date(data.fecha),
    saldoDespues: nuevoSaldo,
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
    updateData.fecha = new Date(data.fecha)
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
    saldoActual = movimiento.tipo === 'ingreso'
      ? saldoActual + movimiento.monto
      : saldoActual - movimiento.monto

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
