// Tipos de datos para el sistema

export type Moneda = 'MXN' | 'USD' | 'EUR'

export type TipoCuenta = 'cheques' | 'credito' | 'prestamo' | 'ahorro'

export type TipoMovimiento = 'ingreso' | 'egreso' | 'transferencia'

export interface Empresa {
  id: string
  userId: string
  nombre: string
  nombreComercial?: string
  rfc?: string
  direccion?: string
  ciudad?: string
  estado?: string
  codigoPostal?: string
  telefono?: string
  email?: string
  giro?: string
  logo?: string
  moneda: Moneda
  activo: boolean
  createdAt: Date
  updatedAt: Date
}

export interface CuentaBancaria {
  id: string
  empresaId: string // "personal" para cuentas personales
  userId: string
  nombre: string
  banco: string
  numeroCuenta: string
  clabe?: string
  tipoCuenta: TipoCuenta
  moneda: Moneda
  saldoInicial: number
  saldoActual: number
  beneficiario?: string
  sucursal?: string
  asesor?: string
  emailBanco?: string
  telefonoBanco?: string
  fechaApertura?: Date
  limiteCredito?: number
  diaCorte?: number // Día del mes en que corta la tarjeta (1-31)
  diaLimitePago?: number // Día límite para pagar la tarjeta (1-31)
  notas?: string
  logo?: string
  activo: boolean
  createdAt: Date
  updatedAt: Date
}

export interface Categoria {
  id: string
  userId: string
  nombre: string
  tipo: TipoMovimiento // Para qué tipo de movimiento es
  color?: string
  icono?: string
  activo: boolean
}

export interface Movimiento {
  id: string
  cuentaId: string
  userId: string
  fecha: Date
  tipo: TipoMovimiento
  monto: number
  descripcion: string
  categoriaId?: string
  referencia?: string // Número de cheque o referencia
  beneficiario?: string
  comentarios?: string
  notas?: string
  saldoDespues: number // Saldo después de este movimiento
  adjunto?: string // URL del archivo adjunto (legacy - para compatibilidad)
  adjuntos?: string[] // URLs de los archivos adjuntos (nuevo)
  // Campos para transferencias
  cuentaDestinoId?: string // ID de la cuenta destino (para transferencias)
  movimientoVinculadoId?: string // ID del movimiento relacionado (para transferencias)
  esOrigen?: boolean // true si este es el movimiento de origen en una transferencia
  cancelado: boolean
  createdAt: Date
  updatedAt: Date
}

export interface EstadoCuenta {
  id: string
  cuentaId: string
  userId: string
  mes: number
  año: number
  archivoUrl: string
  uploadedAt: Date
}

// Tipos para formularios
export interface EmpresaFormData {
  nombre: string
  nombreComercial?: string
  rfc?: string
  direccion?: string
  ciudad?: string
  estado?: string
  codigoPostal?: string
  telefono?: string
  email?: string
  giro?: string
  logo?: string
  moneda: Moneda
}

export interface CuentaBancariaFormData {
  nombre: string
  banco: string
  numeroCuenta: string
  clabe?: string
  tipoCuenta: TipoCuenta
  moneda: Moneda
  saldoInicial: number
  beneficiario?: string
  sucursal?: string
  limiteCredito?: number
  diaCorte?: number
  diaLimitePago?: number
  notas?: string
  logo?: string
}

export interface MovimientoFormData {
  fecha: string
  tipo: TipoMovimiento
  monto: number
  descripcion: string
  categoriaId?: string
  referencia?: string
  beneficiario?: string
  comentarios?: string
  notas?: string
  adjunto?: string
  cuentaId?: string // Para cambiar de cuenta al editar
}

export interface TransferenciaFormData {
  fecha: string
  monto: number
  cuentaOrigenId: string
  cuentaDestinoId: string
  descripcion: string
  categoriaId?: string
  referencia?: string
  beneficiario?: string
  notas?: string
  adjuntos?: string[] // URLs de archivos adjuntos
}
