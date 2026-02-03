'use client'

export const dynamic = 'force-dynamic'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuentas, getEmpresas, getMovimientos, getCategorias } from '@/lib/firestore'
import type { CuentaBancaria, Empresa, Movimiento, Categoria } from '@/lib/types'
import { Card, CardContent } from '@/components/ui/card'
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  DollarSign,
  PieChart,
  Wallet,
  Tag,
  ArrowUpCircle,
  ArrowDownCircle,
  Target
} from 'lucide-react'
import { MainLayout } from '@/components/main-layout'

interface CategoriaConTotal {
  id: string
  nombre: string
  tipo: 'ingreso' | 'egreso'
  total: number
  cantidad: number
  porcentaje: number
}

interface MesData {
  mes: string
  mesCorto: string
  ingresos: number
  egresos: number
  balance: number
}

export default function AnalisisPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [empresas, setEmpresas] = useState<Empresa[]>([])
  const [categorias, setCategorias] = useState<Categoria[]>([])
  const [todosMovimientos, setTodosMovimientos] = useState<Movimiento[]>([])
  const [loading, setLoading] = useState(true)
  const [periodoSeleccionado, setPeriodoSeleccionado] = useState<'todo' | '12meses' | '6meses' | '3meses' | 'mes'>('12meses')

  // Tabs
  const [tabCategorias, setTabCategorias] = useState<'egreso' | 'ingreso'>('egreso')
  const [tabMovimientos, setTabMovimientos] = useState<'egreso' | 'ingreso'>('egreso')

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const [cuentasData, empresasData, categoriasData] = await Promise.all([
        getCuentas(user.uid),
        getEmpresas(user.uid),
        getCategorias(user.uid)
      ])
      setCuentas(cuentasData)
      setEmpresas(empresasData)
      setCategorias(categoriasData)

      const movimientos: Movimiento[] = []
      for (const cuenta of cuentasData) {
        const movs = await getMovimientos(cuenta.id)
        movimientos.push(...movs)
      }
      setTodosMovimientos(movimientos)
    } catch (error) {
      console.error('Error al cargar datos:', error)
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    if (user) {
      loadData()
    }
  }, [user, loadData])

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-16 w-16 border-4 border-cyan-500 border-t-transparent mx-auto"></div>
          <p className="mt-4 text-xl font-bold text-white">Cargando análisis...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  const formatMoney = (amount: number) => {
    return new Intl.NumberFormat('es-MX', {
      style: 'currency',
      currency: 'MXN',
      minimumFractionDigits: 0,
      maximumFractionDigits: 0
    }).format(amount)
  }

  // Filtrar por período
  const filtrarPorPeriodo = (movimientos: Movimiento[]) => {
    if (periodoSeleccionado === 'todo') return movimientos

    const hoy = new Date()
    let fechaInicio: Date

    switch (periodoSeleccionado) {
      case 'mes':
        fechaInicio = new Date(hoy.getFullYear(), hoy.getMonth(), 1)
        break
      case '3meses':
        fechaInicio = new Date(hoy.getFullYear(), hoy.getMonth() - 3, 1)
        break
      case '6meses':
        fechaInicio = new Date(hoy.getFullYear(), hoy.getMonth() - 6, 1)
        break
      case '12meses':
        fechaInicio = new Date(hoy.getFullYear() - 1, hoy.getMonth(), 1)
        break
      default:
        return movimientos
    }

    return movimientos.filter(m => m.fecha >= fechaInicio)
  }

  const movimientosFiltrados = filtrarPorPeriodo(todosMovimientos)

  // Totales
  const totalSaldo = cuentas.reduce((sum, c) => sum + c.saldoActual, 0)
  const ingresosFiltrados = movimientosFiltrados.filter(m => m.tipo === 'ingreso').reduce((sum, m) => sum + m.monto, 0)
  const egresosFiltrados = movimientosFiltrados.filter(m => m.tipo === 'egreso').reduce((sum, m) => sum + m.monto, 0)
  const balanceFiltrado = ingresosFiltrados - egresosFiltrados

  // Agrupar por categoría
  const agruparPorCategoria = (tipo: 'ingreso' | 'egreso'): CategoriaConTotal[] => {
    const movsTipo = movimientosFiltrados.filter(m => m.tipo === tipo)
    const total = movsTipo.reduce((sum, m) => sum + m.monto, 0)

    const grupos: { [key: string]: { nombre: string, total: number, cantidad: number } } = {}

    movsTipo.forEach(mov => {
      const catId = mov.categoriaId || 'sin-categoria'
      const categoria = categorias.find(c => c.id === catId)
      const nombre = categoria?.nombre || 'Sin categoría'

      if (!grupos[catId]) {
        grupos[catId] = { nombre, total: 0, cantidad: 0 }
      }
      grupos[catId].total += mov.monto
      grupos[catId].cantidad++
    })

    return Object.entries(grupos)
      .map(([id, data]) => ({
        id,
        nombre: data.nombre,
        tipo,
        total: data.total,
        cantidad: data.cantidad,
        porcentaje: total > 0 ? (data.total / total) * 100 : 0
      }))
      .sort((a, b) => b.total - a.total)
  }

  const categoriasActuales = agruparPorCategoria(tabCategorias)

  // Agrupar por mes
  const agruparPorMes = (): MesData[] => {
    const meses: MesData[] = []
    const hoy = new Date()
    const numMeses = periodoSeleccionado === 'mes' ? 1 :
                     periodoSeleccionado === '3meses' ? 3 :
                     periodoSeleccionado === '6meses' ? 6 : 12

    for (let i = numMeses - 1; i >= 0; i--) {
      const fecha = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1)
      const mesCorto = fecha.toLocaleDateString('es-MX', { month: 'short' })

      const movsDelMes = todosMovimientos.filter(m => {
        const movFecha = new Date(m.fecha)
        return movFecha.getFullYear() === fecha.getFullYear() && movFecha.getMonth() === fecha.getMonth()
      })

      const ingresos = movsDelMes.filter(m => m.tipo === 'ingreso').reduce((sum, m) => sum + m.monto, 0)
      const egresos = movsDelMes.filter(m => m.tipo === 'egreso').reduce((sum, m) => sum + m.monto, 0)

      meses.push({
        mes: fecha.toLocaleDateString('es-MX', { month: 'long', year: 'numeric' }),
        mesCorto: mesCorto.charAt(0).toUpperCase() + mesCorto.slice(1),
        ingresos,
        egresos,
        balance: ingresos - egresos
      })
    }

    return meses
  }

  const datosMensuales = agruparPorMes()
  const maxMensual = Math.max(...datosMensuales.map(m => Math.max(m.ingresos, m.egresos)), 1)

  // Top movimientos
  const topMovimientos = movimientosFiltrados
    .filter(m => m.tipo === tabMovimientos)
    .sort((a, b) => b.monto - a.monto)
    .slice(0, 5)

  const periodos = [
    { id: 'mes', label: 'Este mes' },
    { id: '3meses', label: '3 meses' },
    { id: '6meses', label: '6 meses' },
    { id: '12meses', label: '12 meses' },
    { id: 'todo', label: 'Todo' },
  ]

  return (
    <MainLayout>
      <div className="space-y-8">
        {/* Header con selector de período */}
        <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 shadow-lg shadow-cyan-500/30">
              <PieChart className="h-8 w-8 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <h1 className="text-3xl font-black text-white">Análisis</h1>
              <p className="text-gray-400 font-medium">Resumen de tus finanzas</p>
            </div>
          </div>

          {/* Selector de período */}
          <div className="flex items-center gap-2 bg-slate-900/50 p-1 rounded-xl">
            {periodos.map(p => (
              <button
                key={p.id}
                onClick={() => setPeriodoSeleccionado(p.id as typeof periodoSeleccionado)}
                className={`px-4 py-2 rounded-lg font-bold text-sm transition-all ${
                  periodoSeleccionado === p.id
                    ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg'
                    : 'text-gray-400 hover:text-white hover:bg-slate-800/50'
                }`}
              >
                {p.label}
              </button>
            ))}
          </div>
        </div>

        {/* KPIs compactos */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Card className="bg-gradient-to-br from-slate-900/80 to-emerald-950/30 border border-emerald-500/30">
            <div className="p-5">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-emerald-500/20">
                  <Wallet className="h-5 w-5 text-emerald-400" />
                </div>
                <span className="text-sm font-bold text-gray-400">Saldo Total</span>
              </div>
              <p className="text-2xl font-black text-emerald-400">{formatMoney(totalSaldo)}</p>
            </div>
          </Card>

          <Card className="bg-gradient-to-br from-slate-900/80 to-green-950/30 border border-green-500/30">
            <div className="p-5">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-green-500/20">
                  <TrendingUp className="h-5 w-5 text-green-400" />
                </div>
                <span className="text-sm font-bold text-gray-400">Ingresos</span>
              </div>
              <p className="text-2xl font-black text-green-400">{formatMoney(ingresosFiltrados)}</p>
            </div>
          </Card>

          <Card className="bg-gradient-to-br from-slate-900/80 to-red-950/30 border border-red-500/30">
            <div className="p-5">
              <div className="flex items-center gap-3 mb-2">
                <div className="p-2 rounded-lg bg-red-500/20">
                  <TrendingDown className="h-5 w-5 text-red-400" />
                </div>
                <span className="text-sm font-bold text-gray-400">Egresos</span>
              </div>
              <p className="text-2xl font-black text-red-400">{formatMoney(egresosFiltrados)}</p>
            </div>
          </Card>

          <Card className={`bg-gradient-to-br from-slate-900/80 ${balanceFiltrado >= 0 ? 'to-cyan-950/30 border-cyan-500/30' : 'to-orange-950/30 border-orange-500/30'} border`}>
            <div className="p-5">
              <div className="flex items-center gap-3 mb-2">
                <div className={`p-2 rounded-lg ${balanceFiltrado >= 0 ? 'bg-cyan-500/20' : 'bg-orange-500/20'}`}>
                  <BarChart3 className={`h-5 w-5 ${balanceFiltrado >= 0 ? 'text-cyan-400' : 'text-orange-400'}`} />
                </div>
                <span className="text-sm font-bold text-gray-400">Balance</span>
              </div>
              <p className={`text-2xl font-black ${balanceFiltrado >= 0 ? 'text-cyan-400' : 'text-orange-400'}`}>
                {formatMoney(balanceFiltrado)}
              </p>
            </div>
          </Card>
        </div>

        {/* Gráfico de Tendencia Mensual */}
        <Card className="bg-gradient-to-br from-slate-900/80 to-blue-950/30 border border-slate-700/50">
          <CardContent className="p-6">
            <h2 className="text-xl font-black text-white mb-6 flex items-center gap-3">
              <BarChart3 className="h-6 w-6 text-purple-400" />
              Tendencia Mensual
            </h2>

            <div className="space-y-4">
              {datosMensuales.map((mes, idx) => (
                <div key={idx} className="group">
                  <div className="flex items-center gap-4">
                    <span className="text-sm font-bold text-gray-400 w-12">{mes.mesCorto}</span>
                    <div className="flex-1 space-y-1">
                      {/* Barra de ingresos */}
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-5 bg-slate-800/50 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-green-500 to-emerald-400 rounded-full transition-all duration-500"
                            style={{ width: `${(mes.ingresos / maxMensual) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-bold text-green-400 w-24 text-right">
                          {mes.ingresos > 0 ? formatMoney(mes.ingresos) : '-'}
                        </span>
                      </div>
                      {/* Barra de egresos */}
                      <div className="flex items-center gap-2">
                        <div className="flex-1 h-5 bg-slate-800/50 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-red-500 to-orange-400 rounded-full transition-all duration-500"
                            style={{ width: `${(mes.egresos / maxMensual) * 100}%` }}
                          />
                        </div>
                        <span className="text-xs font-bold text-red-400 w-24 text-right">
                          {mes.egresos > 0 ? formatMoney(mes.egresos) : '-'}
                        </span>
                      </div>
                    </div>
                    <span className={`text-sm font-black w-24 text-right ${mes.balance >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                      {formatMoney(mes.balance)}
                    </span>
                  </div>
                </div>
              ))}
            </div>

            {/* Leyenda */}
            <div className="flex items-center justify-center gap-6 mt-6 pt-4 border-t border-slate-700/50">
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-gradient-to-r from-green-500 to-emerald-400" />
                <span className="text-sm text-gray-400 font-medium">Ingresos</span>
              </div>
              <div className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full bg-gradient-to-r from-red-500 to-orange-400" />
                <span className="text-sm text-gray-400 font-medium">Egresos</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Categorías y Top Movimientos - Grid de 2 columnas */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Por Categoría */}
          <Card className="bg-gradient-to-br from-slate-900/80 to-slate-950/50 border border-slate-700/50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-black text-white flex items-center gap-3">
                  <Tag className="h-6 w-6 text-orange-400" />
                  Por Categoría
                </h2>
                {/* Tabs */}
                <div className="flex bg-slate-800/50 p-1 rounded-lg">
                  <button
                    onClick={() => setTabCategorias('egreso')}
                    className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all ${
                      tabCategorias === 'egreso'
                        ? 'bg-red-500/20 text-red-400'
                        : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    Gastos
                  </button>
                  <button
                    onClick={() => setTabCategorias('ingreso')}
                    className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all ${
                      tabCategorias === 'ingreso'
                        ? 'bg-green-500/20 text-green-400'
                        : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    Ingresos
                  </button>
                </div>
              </div>

              {categoriasActuales.length === 0 ? (
                <div className="text-center py-8">
                  <Tag className="h-12 w-12 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-500">Sin datos en este período</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {categoriasActuales.slice(0, 6).map((cat, idx) => (
                    <div key={cat.id} className="space-y-2">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <span className="text-lg font-black text-gray-600">#{idx + 1}</span>
                          <span className="text-sm font-bold text-white">{cat.nombre}</span>
                          <span className="text-xs text-gray-500">({cat.cantidad})</span>
                        </div>
                        <div className="text-right">
                          <span className={`text-sm font-black ${tabCategorias === 'egreso' ? 'text-red-400' : 'text-green-400'}`}>
                            {formatMoney(cat.total)}
                          </span>
                          <span className="text-xs text-gray-500 ml-2">{cat.porcentaje.toFixed(0)}%</span>
                        </div>
                      </div>
                      <div className="h-2 bg-slate-800/50 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full transition-all duration-500 ${
                            tabCategorias === 'egreso'
                              ? 'bg-gradient-to-r from-red-500 to-orange-400'
                              : 'bg-gradient-to-r from-green-500 to-emerald-400'
                          }`}
                          style={{ width: `${cat.porcentaje}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Top Movimientos */}
          <Card className="bg-gradient-to-br from-slate-900/80 to-slate-950/50 border border-slate-700/50">
            <CardContent className="p-6">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-xl font-black text-white flex items-center gap-3">
                  <Target className="h-6 w-6 text-purple-400" />
                  Top Movimientos
                </h2>
                {/* Tabs */}
                <div className="flex bg-slate-800/50 p-1 rounded-lg">
                  <button
                    onClick={() => setTabMovimientos('egreso')}
                    className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all ${
                      tabMovimientos === 'egreso'
                        ? 'bg-red-500/20 text-red-400'
                        : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    Gastos
                  </button>
                  <button
                    onClick={() => setTabMovimientos('ingreso')}
                    className={`px-4 py-1.5 rounded-md text-sm font-bold transition-all ${
                      tabMovimientos === 'ingreso'
                        ? 'bg-green-500/20 text-green-400'
                        : 'text-gray-500 hover:text-gray-300'
                    }`}
                  >
                    Ingresos
                  </button>
                </div>
              </div>

              {topMovimientos.length === 0 ? (
                <div className="text-center py-8">
                  <Target className="h-12 w-12 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-500">Sin movimientos en este período</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {topMovimientos.map((mov, idx) => {
                    const categoria = categorias.find(c => c.id === mov.categoriaId)
                    return (
                      <div
                        key={mov.id}
                        className={`flex items-center gap-3 p-3 rounded-xl transition-colors ${
                          tabMovimientos === 'egreso'
                            ? 'bg-red-950/20 hover:bg-red-950/30'
                            : 'bg-green-950/20 hover:bg-green-950/30'
                        }`}
                      >
                        <span className="text-lg font-black text-gray-600 w-6">#{idx + 1}</span>
                        <div className={`p-2 rounded-lg ${
                          tabMovimientos === 'egreso' ? 'bg-red-500/20' : 'bg-green-500/20'
                        }`}>
                          {tabMovimientos === 'egreso'
                            ? <ArrowDownCircle className="h-4 w-4 text-red-400" />
                            : <ArrowUpCircle className="h-4 w-4 text-green-400" />
                          }
                        </div>
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-bold text-white truncate">{mov.descripcion}</p>
                          <p className="text-xs text-gray-500">
                            {mov.fecha.toLocaleDateString('es-MX', { day: '2-digit', month: 'short' })}
                            {categoria && ` • ${categoria.nombre}`}
                          </p>
                        </div>
                        <p className={`text-sm font-black ${
                          tabMovimientos === 'egreso' ? 'text-red-400' : 'text-green-400'
                        }`}>
                          {formatMoney(mov.monto)}
                        </p>
                      </div>
                    )
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </MainLayout>
  )
}
