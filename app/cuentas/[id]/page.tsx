'use client'

export const dynamic = 'force-dynamic'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuenta, getMovimientos, deleteMovimiento, getCategorias, getCuentas } from '@/lib/firestore'
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
import { Plus, Edit, Trash2, TrendingUp, TrendingDown, Upload, Search, FileText, Wallet, ArrowLeftRight, Paperclip } from 'lucide-react'
import { MovimientoModal } from '@/components/movimiento-modal'
import { ImportarMovimientosModal } from '@/components/importar-movimientos-modal'
import { EstadoCuentaModal } from '@/components/estado-cuenta-modal'
import { TransferenciaModal } from '@/components/transferencia-modal'
import { EstadosCuentaCalendar } from '@/components/estados-cuenta-calendar'
import { Input } from '@/components/ui/input'
import { MainLayout } from '@/components/main-layout'
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
  const [showEstadoCuentaModal, setShowEstadoCuentaModal] = useState(false)
  const [showTransferenciaModal, setShowTransferenciaModal] = useState(false)
  const [selectedMovimiento, setSelectedMovimiento] = useState<Movimiento | null>(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [filtroFecha, setFiltroFecha] = useState('todos')
  const [fechaDesde, setFechaDesde] = useState('')
  const [fechaHasta, setFechaHasta] = useState('')
  const [estadoCuentaRefresh, setEstadoCuentaRefresh] = useState(0)

  useEffect(() => {
    params.then((p) => setCuentaId(p.id))
  }, [params])

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async () => {
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
      await deleteMovimiento(id)
      await loadData()
    } catch (error) {
      console.error('Error al cancelar movimiento:', error)
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
      day: 'numeric'
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

    return filtered
  }

  const movimientosFiltrados = filtrarMovimientos()

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
    <MainLayout>
      <div className="space-y-8">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-bold text-white flex items-center gap-4">
              <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-600 shadow-2xl shadow-cyan-500/30">
                <Wallet className="h-14 w-14 text-white" strokeWidth={2.5} />
              </div>
              {cuenta.nombre}
            </h1>
            <p className="text-3xl text-cyan-300 mt-4 ml-20">{cuenta.banco} • {cuenta.numeroCuenta}</p>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <Card className="relative overflow-hidden border border-emerald-500/30 bg-gradient-to-br from-emerald-950/50 via-green-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all duration-300 hover:-translate-y-2">
            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-emerald-500 to-green-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
            <div className="p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-emerald-500 to-green-600 shadow-lg shadow-emerald-500/50">
                  <TrendingUp className="h-9 w-9 text-white" strokeWidth={2.5} />
                </div>
              </div>
              <p className="text-2xl font-bold text-white uppercase tracking-wide mb-3">
                Saldo Actual
              </p>
              <p className="text-5xl font-bold bg-gradient-to-r from-emerald-400 to-green-400 bg-clip-text text-transparent">
                {formatMoney(cuenta.saldoActual, cuenta.moneda)}
              </p>
            </div>
          </Card>

          <Card className="relative overflow-hidden border border-cyan-500/30 bg-gradient-to-br from-cyan-950/50 via-blue-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all duration-300 hover:-translate-y-2">
            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
            <div className="p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 shadow-lg shadow-cyan-500/50">
                  <Wallet className="h-9 w-9 text-white" strokeWidth={2.5} />
                </div>
              </div>
              <p className="text-2xl font-bold text-white uppercase tracking-wide mb-3">
                Saldo Inicial
              </p>
              <p className="text-4xl font-bold bg-gradient-to-r from-cyan-400 to-blue-400 bg-clip-text text-transparent">
                {formatMoney(cuenta.saldoInicial, cuenta.moneda)}
              </p>
            </div>
          </Card>

          <Card className="relative overflow-hidden border border-purple-500/30 bg-gradient-to-br from-purple-950/50 via-pink-950/30 to-slate-950/50 backdrop-blur-sm shadow-2xl shadow-purple-500/30 hover:shadow-purple-500/50 transition-all duration-300 hover:-translate-y-2">
            <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-purple-500 to-pink-500 opacity-20 rounded-full -mr-20 -mt-20"></div>
            <div className="p-8">
              <div className="flex items-center justify-between mb-6">
                <div className="p-4 rounded-2xl bg-gradient-to-br from-purple-500 to-pink-600 shadow-lg shadow-purple-500/50">
                  <TrendingUp className="h-9 w-9 text-white" strokeWidth={2.5} />
                </div>
              </div>
              <p className="text-2xl font-bold text-white uppercase tracking-wide mb-3">
                Movimientos
              </p>
              <p className="text-4xl font-bold bg-gradient-to-r from-purple-400 to-pink-400 bg-clip-text text-transparent">
                {movimientos.length}
              </p>
            </div>
          </Card>
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
                onClick={() => setShowModal(true)}
                className="h-16 px-8 text-xl bg-gradient-to-r from-cyan-600 via-blue-600 to-purple-600 hover:from-cyan-500 hover:via-blue-500 hover:to-purple-500 text-white shadow-2xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all border border-cyan-400/30"
              >
                <Plus className="mr-3 h-8 w-8" strokeWidth={2.5} />
                Nuevo Movimiento
              </Button>
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
                <Select value={filtroFecha} onValueChange={setFiltroFecha}>
                  <SelectTrigger className="w-80 h-16 text-2xl bg-slate-900/50 border-blue-500/30 text-white focus:border-blue-500/50 backdrop-blur-sm">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-blue-500/30 text-white">
                    <SelectItem value="todos" className="text-xl">Todos</SelectItem>
                    <SelectItem value="este-mes" className="text-xl">Este mes</SelectItem>
                    <SelectItem value="esta-semana" className="text-xl">Esta semana</SelectItem>
                    <SelectItem value="rango-personalizado" className="text-xl">Rango personalizado</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {filtroFecha === 'rango-personalizado' && (
                <div className="flex gap-6 items-center">
                  <div className="flex items-center gap-3">
                    <label className="text-2xl text-white font-semibold whitespace-nowrap">Desde:</label>
                    <Input
                      type="date"
                      value={fechaDesde}
                      onChange={(e) => setFechaDesde(e.target.value)}
                      className="w-60 h-14 text-xl bg-slate-900/50 border-purple-500/30 text-white focus:border-purple-500/50 backdrop-blur-sm"
                    />
                  </div>
                  <div className="flex items-center gap-3">
                    <label className="text-2xl text-white font-semibold whitespace-nowrap">Hasta:</label>
                    <Input
                      type="date"
                      value={fechaHasta}
                      onChange={(e) => setFechaHasta(e.target.value)}
                      className="w-60 h-14 text-xl bg-slate-900/50 border-purple-500/30 text-white focus:border-purple-500/50 backdrop-blur-sm"
                    />
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
                    <TableHead className="text-2xl text-white font-bold">Fecha</TableHead>
                    <TableHead className="text-2xl text-white font-bold">No. Cheque</TableHead>
                    <TableHead className="text-2xl text-white font-bold">Categoría</TableHead>
                    <TableHead className="text-2xl text-white font-bold">Descripción</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-right">Cargo</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-right">Abono</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-right">Saldo</TableHead>
                    <TableHead className="text-2xl text-white font-bold">Comentarios</TableHead>
                    <TableHead className="text-2xl text-white font-bold">Notas</TableHead>
                    <TableHead className="text-2xl text-white font-bold text-right">Acciones</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {movimientosFiltrados.map((movimiento) => (
                    <TableRow key={movimiento.id} className="border-b border-slate-700/50 hover:bg-slate-900/50 transition-colors">
                      <TableCell className="text-xl text-white whitespace-nowrap py-6">
                        {formatDate(movimiento.fecha)}
                      </TableCell>
                      <TableCell className="text-xl text-cyan-300">
                        {movimiento.referencia || '-'}
                      </TableCell>
                      <TableCell>
                        <Badge className="text-lg px-4 py-2 bg-gradient-to-r from-purple-600 to-pink-600 text-white border-purple-400/30">
                          {getCategoriaNombre(movimiento.categoriaId)}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <div>
                          <p className="text-xl font-bold text-white flex items-center gap-2">
                            {movimiento.cuentaDestinoId && (
                              <ArrowLeftRight className="h-7 w-7 text-cyan-400" strokeWidth={2.5} />
                            )}
                            {movimiento.descripcion}
                          </p>
                          {movimiento.beneficiario && (
                            <p className="text-lg text-cyan-300 mt-1">{movimiento.beneficiario}</p>
                          )}
                          {movimiento.cuentaDestinoId && (
                            <p className="text-lg text-blue-400 font-semibold flex items-center gap-1 mt-1">
                              {movimiento.esOrigen ? '→' : '←'}{' '}
                              {cuentas.find(c => c.id === movimiento.cuentaDestinoId)?.nombre || 'Cuenta relacionada'}
                            </p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell className="text-right">
                        {movimiento.tipo === 'egreso' && (
                          <span className="text-2xl font-bold bg-gradient-to-r from-red-400 to-orange-400 bg-clip-text text-transparent flex items-center justify-end gap-2">
                            <TrendingDown className="h-7 w-7 text-red-400" strokeWidth={2.5} />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {movimiento.tipo === 'ingreso' && (
                          <span className="text-2xl font-bold bg-gradient-to-r from-emerald-400 to-green-400 bg-clip-text text-transparent flex items-center justify-end gap-2">
                            <TrendingUp className="h-7 w-7 text-emerald-400" strokeWidth={2.5} />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right text-2xl font-bold text-white">
                        {formatMoney(movimiento.saldoDespues, cuenta.moneda)}
                      </TableCell>
                      <TableCell className="text-xl text-gray-300 max-w-xs truncate">
                        {movimiento.comentarios || '-'}
                      </TableCell>
                      <TableCell className="text-xl text-gray-300 max-w-xs truncate">
                        {movimiento.notas || '-'}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex gap-3 justify-end">
                          {movimiento.adjunto && (
                            <Button
                              onClick={() => window.open(movimiento.adjunto, '_blank')}
                              className="h-12 w-12 p-0 bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white shadow-lg shadow-purple-500/30"
                              title="Ver comprobante"
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

      <MovimientoModal
        open={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedMovimiento(null)
        }}
        movimiento={selectedMovimiento}
        cuentaId={cuentaId}
        onSuccess={loadData}
      />

      <ImportarMovimientosModal
        open={showImportModal}
        onClose={() => setShowImportModal(false)}
        cuentaId={cuentaId}
        onSuccess={loadData}
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
        onSuccess={loadData}
      />
    </MainLayout>
  )
}
