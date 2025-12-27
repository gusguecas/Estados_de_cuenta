'use client'

export const dynamic = 'force-dynamic'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuenta, getMovimientos, deleteMovimiento, getCategorias, getCuentas, recalcularSaldos } from '@/lib/firestore'
import type { CuentaBancaria, Movimiento, Categoria } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Plus, Edit, Trash2, TrendingUp, TrendingDown, Upload, Search, FileText, Wallet, ArrowLeftRight, Paperclip, Calendar, RefreshCw, ArrowLeft, Sparkles, Undo2 } from 'lucide-react'
import { MovimientoModal } from '@/components/movimiento-modal'
import { ImportarMovimientosModal } from '@/components/importar-movimientos-modal'
import { ImportarEstadoCuentaIAModal } from '@/components/importar-estado-cuenta-ia-modal'
import { EstadoCuentaModal } from '@/components/estado-cuenta-modal'
import { TransferenciaModal } from '@/components/transferencia-modal'
import { EstadosCuentaCalendar } from '@/components/estados-cuenta-calendar'
import { Input } from '@/components/ui/input'
import { Header } from '@/components/header'
import Image from 'next/image'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface PageProps {
  params: Promise<{ id: string }>
}

export default function CuentaDetailPage({ params }: PageProps) {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuenta, setCuenta] = useState<CuentaBancaria | null>(null)
  const [movimientos, setMovimientos] = useState<Movimiento[]>([])
  const [categorias, setCategorias] = useState<Categoria[]>([])
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [loading, setLoading] = useState(true)
  const [cuentaId, setCuentaId] = useState<string>('')
  const [showModal, setShowModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [showImportIAModal, setShowImportIAModal] = useState(false)
  const [showEstadoCuentaModal, setShowEstadoCuentaModal] = useState(false)
  const [showTransferenciaModal, setShowTransferenciaModal] = useState(false)
  const [selectedMovimiento, setSelectedMovimiento] = useState<Movimiento | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [filtroFecha, setFiltroFecha] = useState('todos')
  const [filtroCategoria, setFiltroCategoria] = useState('todas')
  const [filtroTipo, setFiltroTipo] = useState('todos')
  const [fechaDesde, setFechaDesde] = useState('')
  const [fechaHasta, setFechaHasta] = useState('')
  const [montoDesde, setMontoDesde] = useState('')
  const [montoHasta, setMontoHasta] = useState('')
  const [estadoCuentaRefresh, setEstadoCuentaRefresh] = useState(0)
  const [ultimoMovimientoId, setUltimoMovimientoId] = useState<string | null>(null)
  const [ultimoMovimientoInfo, setUltimoMovimientoInfo] = useState<{ tipo: string; monto: number; descripcion: string } | null>(null)
  const [pendingUndo, setPendingUndo] = useState(false)

  useEffect(() => {
    params.then((p) => setCuentaId(p.id))
  }, [params])

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async (detectNewMovimiento = false, movimientosActuales: typeof movimientos = []) => {
    if (!user || !cuentaId) return

    try {
      setLoading(true)

      const [cuentaData, movimientosData, categoriasData, todasLasCuentas] = await Promise.all([
        getCuenta(cuentaId),
        getMovimientos(cuentaId),
        getCategorias(user.uid),
        getCuentas(user.uid)
      ])
      setCuenta(cuentaData)
      setMovimientos(movimientosData)
      setCategorias(categoriasData)
      setCuentas(todasLasCuentas)

      // Detectar si hay un nuevo movimiento para poder deshacerlo
      if (detectNewMovimiento && movimientosData.length > 0 && movimientosActuales.length > 0) {
        const movimientosAnterioresIds = movimientosActuales.map(m => m.id)

        // Buscar el movimiento más reciente (por createdAt)
        const movimientoMasReciente = movimientosData.reduce((prev, current) => {
          return (prev.createdAt > current.createdAt) ? prev : current
        })

        // Verificar si es realmente nuevo (no existía antes)
        if (!movimientosAnterioresIds.includes(movimientoMasReciente.id)) {
          setUltimoMovimientoId(movimientoMasReciente.id)
          setUltimoMovimientoInfo({
            tipo: movimientoMasReciente.tipo,
            monto: movimientoMasReciente.monto,
            descripcion: movimientoMasReciente.descripcion
          })
          setPendingUndo(true)
        }
      }
    } catch (error) {
      console.error('Error al cargar datos:', error)
    } finally {
      setLoading(false)
    }
  }, [user, cuentaId])

  useEffect(() => {
    if (user && cuentaId) {
      loadData()
    }
  }, [user, cuentaId, loadData])

  const handleDeleteMovimiento = async (id: string) => {
    if (!confirm('¿Estás seguro de cancelar este movimiento?')) return

    try {
      setLoading(true)
      await deleteMovimiento(id)
      // Esperar un momento para que Firestore procese los cambios
      await new Promise(resolve => setTimeout(resolve, 500))
      await loadData()
    } catch (error) {
      console.error('Error al cancelar movimiento:', error)
      alert('Error al cancelar el movimiento')
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteAll = async () => {
    const firstConfirm = confirm(`⚠️ ADVERTENCIA: Vas a borrar TODOS los ${movimientos.length} movimientos de esta cuenta.\n\n¿Estás completamente seguro?`)
    if (!firstConfirm) return

    const secondConfirm = confirm(`🚨 ÚLTIMA CONFIRMACIÓN: Esta acción NO se puede deshacer.\n\nSe borrarán ${movimientos.length} movimientos permanentemente.\n\n¿Confirmas borrar TODO?`)
    if (!secondConfirm) return

    try {
      setLoading(true)
      for (const mov of movimientos) {
        await deleteMovimiento(mov.id)
      }
      // Recalcular saldos para resetear al saldo inicial
      await recalcularSaldos(cuentaId)
      alert(`✅ Se borraron ${movimientos.length} movimientos exitosamente`)
      await loadData()
    } catch (error) {
      console.error('Error al borrar movimientos:', error)
      alert('❌ Error al borrar algunos movimientos')
    } finally {
      setLoading(false)
    }
  }

  const handleUndo = async () => {
    if (!ultimoMovimientoId || !ultimoMovimientoInfo) return

    const tipoTexto = ultimoMovimientoInfo.tipo === 'ingreso' ? 'Ingreso' : 'Egreso'
    const montoTexto = new Intl.NumberFormat('es-MX', { style: 'currency', currency: cuenta?.moneda || 'MXN' }).format(ultimoMovimientoInfo.monto)

    if (!confirm(`¿Deshacer el último movimiento?\n\n${tipoTexto}: ${montoTexto}\n${ultimoMovimientoInfo.descripcion}`)) return

    try {
      setLoading(true)
      await deleteMovimiento(ultimoMovimientoId)
      // Limpiar el estado de deshacer
      setPendingUndo(false)
      setUltimoMovimientoId(null)
      setUltimoMovimientoInfo(null)
      // Esperar un momento para que Firestore procese los cambios
      await new Promise(resolve => setTimeout(resolve, 500))
      await loadData()
      alert('✅ Movimiento deshecho correctamente')
    } catch (error) {
      console.error('Error al deshacer movimiento:', error)
      alert('❌ Error al deshacer el movimiento')
    } finally {
      setLoading(false)
    }
  }

  const formatMoney = (amount: number, moneda: string) => {
    const formatter = new Intl.NumberFormat('es-MX', {
      style: 'currency',
      currency: moneda
    })
    return formatter.format(amount)
  }

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('es-MX', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      timeZone: 'UTC'
    }).format(date)
  }

  const getCategoriaNombre = (categoriaId?: string) => {
    if (!categoriaId) return 'Sin categoría'
    const categoria = categorias.find(c => c.id === categoriaId)
    if (!categoria) {
      console.log('Categoría no encontrada:', categoriaId, 'Categorías disponibles:', categorias)
      return 'Categoría no encontrada'
    }
    return categoria.nombre
  }

  const filtrarMovimientos = () => {
    let filtered = [...movimientos]

    // Filtro de búsqueda
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = filtered.filter(m =>
        m.descripcion.toLowerCase().includes(term) ||
        m.beneficiario?.toLowerCase().includes(term) ||
        m.referencia?.toLowerCase().includes(term) ||
        m.comentarios?.toLowerCase().includes(term) ||
        m.notas?.toLowerCase().includes(term) ||
        getCategoriaNombre(m.categoriaId).toLowerCase().includes(term)
      )
    }

    // Filtro de categoría
    if (filtroCategoria !== 'todas') {
      if (filtroCategoria === 'sin-categoria') {
        filtered = filtered.filter(m => !m.categoriaId)
      } else {
        filtered = filtered.filter(m => m.categoriaId === filtroCategoria)
      }
    }

    // Filtro de tipo (ingreso/egreso)
    if (filtroTipo !== 'todos') {
      filtered = filtered.filter(m => m.tipo === filtroTipo)
    }

    // Filtro de fecha
    const now = new Date()
    if (filtroFecha === 'este-mes') {
      filtered = filtered.filter(m => {
        const fecha = new Date(m.fecha)
        return fecha.getMonth() === now.getMonth() && fecha.getFullYear() === now.getFullYear()
      })
    } else if (filtroFecha === 'esta-semana') {
      const startOfWeek = new Date(now)
      startOfWeek.setDate(now.getDate() - now.getDay())
      startOfWeek.setHours(0, 0, 0, 0)
      filtered = filtered.filter(m => new Date(m.fecha) >= startOfWeek)
    } else if (filtroFecha === 'rango-personalizado') {
      if (fechaDesde) {
        const desde = new Date(fechaDesde)
        desde.setHours(0, 0, 0, 0)
        filtered = filtered.filter(m => new Date(m.fecha) >= desde)
      }
      if (fechaHasta) {
        const hasta = new Date(fechaHasta)
        hasta.setHours(23, 59, 59, 999)
        filtered = filtered.filter(m => new Date(m.fecha) <= hasta)
      }
    }

    // Filtro de rango de montos
    if (montoDesde) {
      const desde = parseFloat(montoDesde)
      if (!isNaN(desde)) {
        filtered = filtered.filter(m => m.monto >= desde)
      }
    }
    if (montoHasta) {
      const hasta = parseFloat(montoHasta)
      if (!isNaN(hasta)) {
        filtered = filtered.filter(m => m.monto <= hasta)
      }
    }

    return filtered
  }

  const movimientosFiltrados = filtrarMovimientos()

  // Calcular totales de los movimientos filtrados
  const totalIngresos = movimientosFiltrados
    .filter(m => m.tipo === 'ingreso')
    .reduce((sum, m) => sum + m.monto, 0)

  const totalEgresos = movimientosFiltrados
    .filter(m => m.tipo === 'egreso')
    .reduce((sum, m) => sum + m.monto, 0)

  const diferencia = totalIngresos - totalEgresos

  // Verificar si hay algún filtro activo
  const hayFiltrosActivos = searchTerm !== '' ||
    filtroCategoria !== 'todas' ||
    filtroTipo !== 'todos' ||
    filtroFecha !== 'todos' ||
    montoDesde !== '' ||
    montoHasta !== ''

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-20 w-20 border-4 border-cyan-500 border-t-transparent mx-auto"></div>
          <p className="mt-8 text-3xl font-bold text-white">Cargando cuenta...</p>
        </div>
      </div>
    )
  }

  if (!user || !cuenta) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_50%_50%,rgba(16,185,129,0.05),transparent_50%)]"></div>
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_80%_20%,rgba(139,92,246,0.1),transparent_50%)]"></div>
      <div className="fixed inset-0 bg-[radial-gradient(circle_at_20%_80%,rgba(6,182,212,0.08),transparent_50%)]"></div>

      <div className="relative z-10">
        <Header />

        {/* Notificación flotante de deshacer */}
        {pendingUndo && ultimoMovimientoInfo && (
          <div className="fixed bottom-8 left-1/2 transform -translate-x-1/2 z-50 animate-bounce">
            <div className="flex items-center gap-4 px-8 py-5 bg-gradient-to-r from-slate-900 via-slate-800 to-slate-900 border-2 border-red-500/50 rounded-2xl shadow-2xl shadow-red-500/30 backdrop-blur-sm">
              <div className={`p-3 rounded-xl ${ultimoMovimientoInfo.tipo === 'ingreso' ? 'bg-emerald-500/20' : 'bg-red-500/20'}`}>
                {ultimoMovimientoInfo.tipo === 'ingreso' ? (
                  <TrendingUp className="h-8 w-8 text-emerald-400" strokeWidth={2.5} />
                ) : (
                  <TrendingDown className="h-8 w-8 text-red-400" strokeWidth={2.5} />
                )}
              </div>
              <div className="flex flex-col">
                <p className="text-xl font-bold text-white">
                  {ultimoMovimientoInfo.tipo === 'ingreso' ? 'Ingreso' : 'Egreso'}: {new Intl.NumberFormat('es-MX', { style: 'currency', currency: cuenta?.moneda || 'MXN' }).format(ultimoMovimientoInfo.monto)}
                </p>
                <p className="text-lg text-slate-300 truncate max-w-xs">
                  {ultimoMovimientoInfo.descripcion}
                </p>
              </div>
              <Button
                onClick={handleUndo}
                disabled={loading}
                className="h-14 px-6 text-lg font-black bg-gradient-to-r from-red-600 to-rose-600 hover:from-red-500 hover:to-rose-500 text-white shadow-lg shadow-red-500/30"
              >
                <Undo2 className="mr-2 h-6 w-6" strokeWidth={2.5} />
                Deshacer
              </Button>
              <Button
                onClick={() => {
                  setPendingUndo(false)
                  setUltimoMovimientoId(null)
                  setUltimoMovimientoInfo(null)
                }}
                variant="ghost"
                className="h-14 px-4 text-slate-400 hover:text-white hover:bg-slate-700"
              >
                ✕
              </Button>
            </div>
          </div>
        )}

        <main className="px-8 py-10">
          <div className="space-y-8">
        <div className="flex items-center justify-between pl-32 mt-8">
          <div className="flex items-center gap-36">
            <div className="relative w-28 h-28 flex items-center justify-center">
              {cuenta.logo ? (
                <Image
                  src={cuenta.logo}
                  alt={cuenta.banco}
                  fill
                  className="object-contain scale-[3]"
                />
              ) : (
                <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-600 shadow-2xl shadow-cyan-500/30">
                  <Wallet className="h-14 w-14 text-white" strokeWidth={2.5} />
                </div>
              )}
            </div>
            <div>
              <h1 className="text-6xl font-bold text-white">
                {cuenta.nombre}
              </h1>
              <p className="text-3xl text-cyan-300 mt-4">{cuenta.banco} • {cuenta.numeroCuenta}</p>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        <div className={`grid grid-cols-1 gap-8 mt-20 ${cuenta.tipoCuenta === 'credito' ? 'md:grid-cols-4' : 'md:grid-cols-3'}`}>
          <Card className="relative overflow-hidden border border-emerald-500/30 bg-gradient-to-br from-emerald-950/50 via-green-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all duration-300 hover:-translate-y-2">
            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-emerald-500 to-green-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-emerald-500 to-green-600 shadow-lg shadow-emerald-500/50">
                  <TrendingUp className="h-9 w-9 text-white" strokeWidth={2.5} />
                </div>
              </div>
              <p className="text-2xl font-bold text-white uppercase tracking-wide mb-2">
                {cuenta.tipoCuenta === 'credito' ? 'Crédito Disponible' : 'Saldo Actual'}
              </p>
              <p className="text-5xl font-bold bg-gradient-to-r from-emerald-400 to-green-400 bg-clip-text text-transparent">
                {formatMoney(cuenta.saldoActual, cuenta.moneda)}
              </p>
              {cuenta.tipoCuenta === 'credito' && cuenta.limiteCredito && (
                <p className="text-lg text-emerald-300 mt-2">
                  de {formatMoney(cuenta.limiteCredito || cuenta.saldoInicial, cuenta.moneda)}
                </p>
              )}
            </div>
          </Card>

          {cuenta.tipoCuenta === 'credito' ? (
            <Card className="relative overflow-hidden border border-red-500/30 bg-gradient-to-br from-red-950/50 via-orange-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-red-500/30 hover:shadow-red-500/50 transition-all duration-300 hover:-translate-y-2">
              <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-red-500 to-orange-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-4 rounded-2xl bg-gradient-to-br from-red-500 to-orange-600 shadow-lg shadow-red-500/50">
                    <TrendingUp className="h-9 w-9 text-white rotate-180" strokeWidth={2.5} />
                  </div>
                </div>
                <p className="text-2xl font-bold text-white uppercase tracking-wide mb-2">
                  Adeudo Total
                </p>
                <p className="text-5xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent">
                  {formatMoney((cuenta.limiteCredito || cuenta.saldoInicial) - cuenta.saldoActual, cuenta.moneda)}
                </p>
              </div>
            </Card>
          ) : (
            <Card className="relative overflow-hidden border border-cyan-500/30 bg-gradient-to-br from-cyan-950/50 via-blue-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all duration-300 hover:-translate-y-2">
              <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/50">
                    <Wallet className="h-9 w-9 text-white" strokeWidth={2.5} />
                  </div>
                </div>
                <p className="text-2xl font-bold text-white uppercase tracking-wide mb-2">
                  Saldo Inicial
                </p>
                <p className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                  {formatMoney(cuenta.saldoInicial, cuenta.moneda)}
                </p>
              </div>
            </Card>
          )}

          <Card className="relative overflow-hidden border border-purple-500/30 bg-gradient-to-br from-purple-950/50 via-pink-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-purple-500/30 hover:shadow-purple-500/50 transition-all duration-300 hover:-translate-y-2">
            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-purple-500 to-pink-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-purple-500 to-pink-600 shadow-lg shadow-purple-500/50">
                  <TrendingUp className="h-9 w-9 text-white" strokeWidth={2.5} />
                </div>
              </div>
              <p className="text-2xl font-bold text-white uppercase tracking-wide mb-2">
                Movimientos
              </p>
              <p className="text-4xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                {movimientos.length}
              </p>
            </div>
          </Card>

          {cuenta.tipoCuenta === 'credito' && cuenta.diaCorte && (
            <Card className="relative overflow-hidden border border-orange-500/30 bg-gradient-to-br from-orange-950/50 via-red-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-orange-500/30 hover:shadow-orange-500/50 transition-all duration-300 hover:-translate-y-2">
              <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-orange-500 to-red-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
              <div className="p-6">
                <div className="flex items-center justify-between mb-4">
                  <div className="p-4 rounded-2xl bg-gradient-to-br from-orange-500 to-red-600 shadow-lg shadow-orange-500/50">
                    <Calendar className="h-9 w-9 text-white" strokeWidth={2.5} />
                  </div>
                </div>
                <p className="text-2xl font-bold text-white uppercase tracking-wide mb-2">
                  Próximo Corte
                </p>
                <p className="text-3xl font-bold bg-gradient-to-r from-orange-400 to-red-400 bg-clip-text text-transparent mb-3">
                  {(() => {
                    const hoy = new Date()
                    const diaActual = hoy.getDate()
                    const mesActual = hoy.getMonth()
                    const añoActual = hoy.getFullYear()
                    let fechaCorte = new Date(añoActual, mesActual, cuenta.diaCorte)

                    if (cuenta.diaCorte < diaActual) {
                      fechaCorte = new Date(añoActual, mesActual + 1, cuenta.diaCorte)
                    }

                    const diasHasta = Math.ceil((fechaCorte.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

                    return diasHasta === 0 ? 'Hoy' : diasHasta === 1 ? 'Mañana' : `${diasHasta} días`
                  })()}
                </p>
                {cuenta.diaLimitePago && (
                  <p className="text-2xl text-white font-bold uppercase tracking-wide mb-2">
                    Fecha límite pago: {(() => {
                      const hoy = new Date()
                      const diaActual = hoy.getDate()
                      const mesActual = hoy.getMonth()
                      const añoActual = hoy.getFullYear()
                      let fechaLimite = new Date(añoActual, mesActual, cuenta.diaLimitePago)

                      if (cuenta.diaLimitePago < diaActual) {
                        fechaLimite = new Date(añoActual, mesActual + 1, cuenta.diaLimitePago)
                      }

                      const diasHasta = Math.ceil((fechaLimite.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

                      return diasHasta === 0 ? 'Hoy' : diasHasta === 1 ? 'Mañana' : `${diasHasta} días`
                    })()}
                  </p>
                )}
                <p className="text-xl text-orange-300 font-bold">
                  Monto a pagar: {(() => {
                    if (cuenta.limiteCredito) {
                      // Para tarjetas: lo gastado = límite - disponible
                      const montoGastado = cuenta.limiteCredito - cuenta.saldoActual
                      return formatMoney(montoGastado, cuenta.moneda)
                    }
                    return formatMoney(Math.abs(cuenta.saldoActual), cuenta.moneda)
                  })()}
                </p>
              </div>
            </Card>
          )}
        </div>

        <EstadosCuentaCalendar
          cuentaId={cuentaId}
          onUploadClick={() => setShowEstadoCuentaModal(true)}
          refreshTrigger={estadoCuentaRefresh}
        />

        <div className="space-y-6">
          <div className="flex items-center justify-between">
            <h2 className="text-5xl font-bold text-white">Movimientos</h2>
            <div className="flex gap-4">
              <Button
                onClick={() => setShowTransferenciaModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-emerald-600 via-green-600 to-emerald-700 hover:from-emerald-500 hover:via-green-500 hover:to-emerald-600 text-white shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all border border-emerald-400/30"
              >
                <ArrowLeftRight className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Transferir
              </Button>
              <Button
                onClick={() => setShowEstadoCuentaModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-blue-600 via-cyan-600 to-blue-700 hover:from-blue-500 hover:via-cyan-500 hover:to-blue-600 text-white shadow-2xl shadow-blue-500/30 hover:shadow-blue-500/50 transition-all border border-blue-400/30"
              >
                <FileText className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Estado de Cuenta
              </Button>
              <Button
                onClick={() => setShowImportModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-purple-600 via-pink-600 to-purple-700 hover:from-purple-500 hover:via-pink-500 hover:to-purple-600 text-white shadow-2xl shadow-purple-500/30 hover:shadow-purple-500/50 transition-all border border-purple-400/30"
              >
                <Upload className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Importar Excel
              </Button>
              <Button
                onClick={() => setShowImportIAModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-pink-600 via-purple-600 to-pink-700 hover:from-pink-500 hover:via-purple-500 hover:to-pink-600 text-white shadow-2xl shadow-pink-500/30 hover:shadow-pink-500/50 transition-all border border-pink-400/30 animate-pulse"
              >
                <Sparkles className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Importar con IA 🤖
              </Button>
              <Button
                onClick={() => setShowModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 hover:from-cyan-500 hover:via-blue-500 hover:to-purple-500 text-white shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all border border-cyan-400/30"
              >
                <Plus className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Nuevo Movimiento
              </Button>
              <Button
                onClick={async () => {
                  if (confirm('¿Recalcular todos los saldos? Esto corregirá cualquier error en los cálculos.')) {
                    setLoading(true)
                    try {
                      await recalcularSaldos(cuentaId)
                      alert('✅ Saldos recalculados correctamente')
                      await loadData()
                    } catch (error) {
                      console.error('Error al recalcular saldos:', error)
                      alert('❌ Error al recalcular saldos')
                    } finally {
                      setLoading(false)
                    }
                  }
                }}
                className="h-16 px-8 text-xl bg-gradient-to-r from-yellow-600 via-orange-600 to-yellow-700 hover:from-yellow-500 hover:via-orange-500 hover:to-yellow-600 text-white shadow-2xl shadow-yellow-500/30 hover:shadow-yellow-500/50 transition-all border border-yellow-400/30"
              >
                <RefreshCw className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Recalcular Saldos
              </Button>
              {pendingUndo && ultimoMovimientoInfo && (
                <Button
                  onClick={handleUndo}
                  disabled={loading}
                  className="h-16 px-8 text-xl bg-gradient-to-r from-red-600 via-rose-600 to-red-700 hover:from-red-500 hover:via-rose-500 hover:to-red-600 text-white shadow-2xl shadow-red-500/30 hover:shadow-red-500/50 transition-all border border-red-400/30 animate-pulse"
                >
                  <Undo2 className="mr-3 h-8 w-8" strokeWidth={2.5} />
                  Deshacer Último
                </Button>
              )}
            </div>
          </div>

          {movimientos.length > 0 && (
            <div className="space-y-6">
              <div className="flex gap-4">
                <div className="relative flex-1">
                  <Search className="absolute left-5 top-1/2 transform -translate-y-1/2 h-8 w-8 text-cyan-400" strokeWidth={2.5} />
                  <Input
                    placeholder="Buscar por descripción, beneficiario, referencia..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="h-16 pl-16 text-2xl bg-slate-900/50 border-cyan-500/30 text-white placeholder:text-gray-400 focus:border-cyan-500/50 backdrop-blur-sm"
                  />
                </div>
                <Select value={filtroTipo} onValueChange={setFiltroTipo}>
                  <SelectTrigger className="w-64 h-16 text-2xl bg-slate-900/50 border-emerald-500/30 text-white focus:border-emerald-500/50 backdrop-blur-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-emerald-500/30 text-white">
                    <SelectItem value="todos" className="text-xl font-bold">💸 Todos los tipos</SelectItem>
                    <SelectItem value="ingreso" className="text-xl">💰 Solo Ingresos</SelectItem>
                    <SelectItem value="egreso" className="text-xl">🔴 Solo Egresos</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={filtroCategoria} onValueChange={setFiltroCategoria}>
                  <SelectTrigger className="w-64 h-16 text-2xl bg-slate-900/50 border-purple-500/30 text-white focus:border-purple-500/50 backdrop-blur-sm">
                    <SelectValue placeholder="Categoría" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-purple-500/30 text-white">
                    <SelectItem value="todas" className="text-xl font-bold">📁 Todas</SelectItem>
                    <SelectItem value="sin-categoria" className="text-xl">⚠️ Sin categoría</SelectItem>
                    {Array.from(new Map(categorias.map(c => [c.nombre, c])).values()).map(categoria => (
                      <SelectItem key={categoria.id} value={categoria.id} className="text-xl">
                        {categoria.tipo === 'ingreso' ? '💰' : '💸'} {categoria.nombre}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={filtroFecha} onValueChange={setFiltroFecha}>
                  <SelectTrigger className="w-64 h-16 text-2xl bg-slate-900/50 border-blue-500/30 text-white focus:border-blue-500/50 backdrop-blur-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-blue-500/30 text-white">
                    <SelectItem value="todos" className="text-xl">📅 Todas</SelectItem>
                    <SelectItem value="este-mes" className="text-xl">📆 Este mes</SelectItem>
                    <SelectItem value="esta-semana" className="text-xl">🗓️ Semana</SelectItem>
                    <SelectItem value="rango-personalizado" className="text-xl">🔍 Rango</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {filtroFecha === 'rango-personalizado' && (
                <div className="flex gap-6 items-center p-6 bg-blue-950/20 border-2 border-blue-500/20 rounded-xl">
                  <span className="text-2xl text-blue-300 font-bold">📅 Rango de Fechas:</span>
                  <div className="flex items-center gap-3">
                    <label className="text-xl text-white font-semibold whitespace-nowrap">Desde:</label>
                    <Input
                      type="date"
                      value={fechaDesde}
                      onChange={(e) => setFechaDesde(e.target.value)}
                      className="w-52 h-12 text-lg bg-slate-900/50 border-blue-500/30 text-white focus:border-blue-500/50 backdrop-blur-sm"
                    />
                  </div>
                  <div className="flex items-center gap-3">
                    <label className="text-xl text-white font-semibold whitespace-nowrap">Hasta:</label>
                    <Input
                      type="date"
                      value={fechaHasta}
                      onChange={(e) => setFechaHasta(e.target.value)}
                      className="w-52 h-12 text-lg bg-slate-900/50 border-blue-500/30 text-white focus:border-blue-500/50 backdrop-blur-sm"
                    />
                  </div>
                </div>
              )}

              {/* Filtro de rango de montos */}
              <div className="flex gap-6 items-center p-6 bg-yellow-950/20 border-2 border-yellow-500/20 rounded-xl">
                <span className="text-2xl text-yellow-300 font-bold">💰 Rango de Montos:</span>
                <div className="flex items-center gap-3">
                  <label className="text-xl text-white font-semibold whitespace-nowrap">Desde $:</label>
                  <Input
                    type="number"
                    step="0.01"
                    placeholder="0.00"
                    value={montoDesde}
                    onChange={(e) => setMontoDesde(e.target.value)}
                    className="w-44 h-12 text-lg bg-slate-900/50 border-yellow-500/30 text-white focus:border-yellow-500/50 backdrop-blur-sm"
                  />
                </div>
                <div className="flex items-center gap-3">
                  <label className="text-xl text-white font-semibold whitespace-nowrap">Hasta $:</label>
                  <Input
                    type="number"
                    step="0.01"
                    placeholder="999999.99"
                    value={montoHasta}
                    onChange={(e) => setMontoHasta(e.target.value)}
                    className="w-44 h-12 text-lg bg-slate-900/50 border-yellow-500/30 text-white focus:border-yellow-500/50 backdrop-blur-sm"
                  />
                </div>
                {(montoDesde || montoHasta) && (
                  <Button
                    variant="ghost"
                    onClick={() => {
                      setMontoDesde('')
                      setMontoHasta('')
                    }}
                    className="text-yellow-300 hover:text-yellow-100 hover:bg-yellow-950/30"
                  >
                    ✕ Limpiar
                  </Button>
                )}
              </div>

              {/* Resumen de totales filtrados */}
              {movimientosFiltrados.length > 0 && (
                <div className="grid grid-cols-4 gap-6 p-6 bg-gradient-to-r from-slate-900/80 via-blue-950/50 to-slate-900/80 border-2 border-cyan-500/30 rounded-2xl shadow-xl">
                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-emerald-500/20">
                      <TrendingUp className="h-8 w-8 text-emerald-400" strokeWidth={2.5} />
                    </div>
                    <div>
                      <p className="text-lg font-bold text-emerald-300 uppercase">Total Abonos</p>
                      <p className="text-3xl font-black text-emerald-400">
                        {formatMoney(totalIngresos, cuenta.moneda)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-red-500/20">
                      <TrendingDown className="h-8 w-8 text-red-400" strokeWidth={2.5} />
                    </div>
                    <div>
                      <p className="text-lg font-bold text-red-300 uppercase">Total Cargos</p>
                      <p className="text-3xl font-black text-red-400">
                        {formatMoney(totalEgresos, cuenta.moneda)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className={`p-3 rounded-xl ${diferencia >= 0 ? 'bg-cyan-500/20' : 'bg-orange-500/20'}`}>
                      <Wallet className={`h-8 w-8 ${diferencia >= 0 ? 'text-cyan-400' : 'text-orange-400'}`} strokeWidth={2.5} />
                    </div>
                    <div>
                      <p className={`text-lg font-bold uppercase ${diferencia >= 0 ? 'text-cyan-300' : 'text-orange-300'}`}>Diferencia</p>
                      <p className={`text-3xl font-black ${diferencia >= 0 ? 'text-cyan-400' : 'text-orange-400'}`}>
                        {formatMoney(diferencia, cuenta.moneda)}
                      </p>
                    </div>
                  </div>

                  <div className="flex items-center gap-4">
                    <div className="p-3 rounded-xl bg-purple-500/20">
                      <FileText className="h-8 w-8 text-purple-400" strokeWidth={2.5} />
                    </div>
                    <div>
                      <p className="text-lg font-bold text-purple-300 uppercase">Movimientos</p>
                      <p className="text-3xl font-black text-purple-400">
                        {movimientosFiltrados.length}
                      </p>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>

        {movimientos.length === 0 ? (
          <Card className="border border-cyan-500/30 bg-gradient-to-br from-slate-950/80 via-blue-950/50 to-slate-900/80 backdrop-blur-sm shadow-2xl shadow-cyan-500/20">
            <CardContent className="flex flex-col items-center justify-center py-32">
              <div className="p-8 rounded-3xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-600 mb-10 shadow-2xl shadow-cyan-500/50">
                <TrendingUp className="h-24 w-24 text-white" strokeWidth={2.5} />
              </div>
              <h3 className="text-5xl font-bold text-white mb-6">
                No hay movimientos registrados
              </h3>
              <p className="text-3xl text-cyan-300 mb-12">
                Comienza registrando el primer movimiento de esta cuenta
              </p>
              <Button
                onClick={() => setShowModal(true)}
                className="h-20 px-12 text-2xl bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 hover:from-cyan-500 hover:via-blue-500 hover:to-purple-500 text-white shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all"
              >
                <Plus className="mr-3 h-9 w-9" strokeWidth={2.5} />
                Crear Primer Movimiento
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card className="border border-cyan-500/30 bg-gradient-to-br from-slate-950/80 via-blue-950/50 to-slate-900/80 backdrop-blur-sm shadow-2xl shadow-cyan-500/20">
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="border-b border-cyan-500/30 hover:bg-slate-900/50">
                    <TableHead className="text-2xl text-white font-bold text-center">Fecha</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">No. Cheque</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Categoría</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Descripción</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Abono</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Cargo</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Saldo</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Comentarios</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">Notas</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-center">
                      <div className="flex flex-col items-center gap-2">
                        <span>Acciones</span>
                        {movimientos.length > 0 && (
                          <Button
                            onClick={handleDeleteAll}
                            disabled={loading}
                            className="h-8 px-3 text-xs bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white shadow-lg shadow-red-500/30"
                          >
                            <Trash2 className="h-3 w-3 mr-1" strokeWidth={2.5} />
                            Borrar todo
                          </Button>
                        )}
                      </div>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {movimientosFiltrados.map((movimiento) => (
                    <TableRow key={movimiento.id} className="border-b border-slate-700/50 hover:bg-slate-900/50 transition-colors">
                      <TableCell className="text-xl text-white whitespace-nowrap py-6 text-center">
                        {formatDate(movimiento.fecha)}
                      </TableCell>
                      <TableCell className="text-xl text-cyan-300 text-center">
                        {movimiento.referencia || '-'}
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge className="text-lg px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white border-purple-400/30">
                          {getCategoriaNombre(movimiento.categoriaId)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center">
                        <div className="flex flex-col items-center">
                          <p className="text-xl font-bold text-white flex items-center gap-2">
                            {(movimiento.cuentaDestinoId || movimiento.movimientoVinculadoId) && (
                              <ArrowLeftRight className="h-7 w-7 text-cyan-400" strokeWidth={2.5} />
                            )}
                            {movimiento.descripcion}
                          </p>
                          {movimiento.beneficiario && (
                            <p className="text-lg text-cyan-300 mt-1">{movimiento.beneficiario}</p>
                          )}
                          {(movimiento.cuentaDestinoId || movimiento.movimientoVinculadoId) && (
                            <div className="mt-2 px-4 py-2 bg-gradient-to-r from-blue-600/30 to-cyan-600/30 border border-blue-500/50 rounded-lg">
                              <p className="text-xl text-cyan-300 font-bold flex items-center gap-2">
                                {movimiento.esOrigen ? (
                                  <>
                                    <span className="text-red-400">→</span>
                                    <span>Destino:</span>
                                  </>
                                ) : (
                                  <>
                                    <span className="text-green-400">←</span>
                                    <span>Origen:</span>
                                  </>
                                )}
                                <span className="text-white">
                                  {cuentas.find(c => c.id === movimiento.cuentaDestinoId)?.nombre || 'Cuenta vinculada'}
                                </span>
                              </p>
                            </div>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-center">
                        {movimiento.tipo === 'ingreso' && (
                          <span className="text-2xl font-bold bg-gradient-to-r from-emerald-400 to-green-400 bg-clip-text text-transparent flex items-center justify-center gap-2">
                            <TrendingUp className="h-7 w-7 text-emerald-400" strokeWidth={2.5} />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-center">
                        {movimiento.tipo === 'egreso' && (
                          <span className="text-2xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent flex items-center justify-center gap-2">
                            <TrendingDown className="h-7 w-7 text-red-400" strokeWidth={2.5} />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-center text-2xl font-bold text-white">
                        {formatMoney(movimiento.saldoDespues, cuenta.moneda)}
                      </TableCell>
                      <TableCell className="text-xl text-gray-300 max-w-xs truncate text-center">
                        {movimiento.comentarios || '-'}
                      </TableCell>
                      <TableCell className="text-xl text-gray-300 max-w-xs truncate text-center">
                        {movimiento.notas || '-'}
                      </TableCell>
                      <TableCell className="text-center">
                        <div className="flex gap-3 justify-center">
                          {(movimiento.adjunto || (movimiento.adjuntos && movimiento.adjuntos.length > 0)) && (
                            <Button
                              onClick={() => {
                                // Si hay adjuntos (array), abrir el primero. Si hay adjunto (string), abrirlo
                                const url = movimiento.adjuntos && movimiento.adjuntos.length > 0
                                  ? movimiento.adjuntos[0]
                                  : movimiento.adjunto
                                if (url) window.open(url, '_blank')
                              }}
                              className="h-12 w-12 p-0 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white shadow-lg shadow-purple-500/30"
                              title={`Ver comprobante${movimiento.adjuntos && movimiento.adjuntos.length > 1 ? ` (${movimiento.adjuntos.length} archivos)` : ''}`}
                            >
                              <Paperclip className="h-6 w-6" strokeWidth={2.5} />
                            </Button>
                          )}
                          <Button
                            onClick={() => {
                              setSelectedMovimiento(movimiento)
                              setShowModal(true)
                            }}
                            className="h-12 w-12 p-0 bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-500 hover:to-cyan-500 text-white shadow-lg shadow-blue-500/30"
                          >
                            <Edit className="h-6 w-6" strokeWidth={2.5} />
                          </Button>
                          <Button
                            onClick={() => handleDeleteMovimiento(movimiento.id)}
                            className="h-12 w-12 p-0 bg-gradient-to-r from-red-600 to-orange-600 hover:from-red-500 hover:to-orange-500 text-white shadow-lg shadow-red-500/30"
                          >
                            <Trash2 className="h-6 w-6" strokeWidth={2.5} />
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        )}
        </div>
        </main>
      </div>

      <MovimientoModal
        open={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedMovimiento(null)
        }}
        movimiento={selectedMovimiento}
        cuentaId={cuentaId}
        onSuccess={() => loadData(true, movimientos)}
      />

      <ImportarMovimientosModal
        open={showImportModal}
        onClose={() => setShowImportModal(false)}
        cuentaId={cuentaId}
        onSuccess={() => loadData(true, movimientos)}
      />

      <EstadoCuentaModal
        open={showEstadoCuentaModal}
        onClose={() => setShowEstadoCuentaModal(false)}
        cuentaId={cuentaId}
        onSuccess={() => {
          loadData()
          setEstadoCuentaRefresh(prev => prev + 1)
        }}
      />

      <TransferenciaModal
        open={showTransferenciaModal}
        onClose={() => setShowTransferenciaModal(false)}
        cuentaOrigenPreseleccionada={cuentaId}
        onSuccess={() => loadData(true, movimientos)}
      />

      <ImportarEstadoCuentaIAModal
        open={showImportIAModal}
        onClose={() => setShowImportIAModal(false)}
        cuentaId={cuentaId}
        onSuccess={() => loadData(true, movimientos)}
      />
    </div>
  )
}
