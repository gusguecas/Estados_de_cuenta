// Tipos de datos para el sistema

export type Moneda = 'MXN' | 'USD' | 'EUR'

export type TipoCuenta = 'cheques' | 'credito' | 'prestamo' | 'ahorro'

export type TipoMovimiento = 'ingreso' | 'egreso'

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
  notas?: string
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
  saldoDespues: number // Saldo después de este movimiento
  adjunto?: string // URL del archivo adjunto
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
  notas?: string
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
}
