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
  Building2,
  User,
  Wallet,
  Tag,
  Calendar,
  ArrowUpCircle,
  ArrowDownCircle,
  Activity,
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
  const [totalIngresos, setTotalIngresos] = useState(0)
  const [totalEgresos, setTotalEgresos] = useState(0)
  const [periodoSeleccionado, setPeriodoSeleccionado] = useState<'todo' | '12meses' | '6meses' | '3meses' | 'mes'>('todo')

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

      // Cargar movimientos de todas las cuentas
      let ingresos = 0
      let egresos = 0
      const movimientos: Movimiento[] = []

      for (const cuenta of cuentasData) {
        const movs = await getMovimientos(cuenta.id)
        movimientos.push(...movs)
        movs.forEach(mov => {
          if (mov.tipo === 'ingreso') {
            ingresos += mov.monto
          } else {
            egresos += mov.monto
          }
        })
      }

      setTodosMovimientos(movimientos)
      setTotalIngresos(ingresos)
      setTotalEgresos(egresos)
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
          <div className="animate-spin rounded-full h-20 w-20 border-4 border-cyan-500 border-t-transparent mx-auto"></div>
          <p className="mt-6 text-3xl font-black text-white">Cargando análisis...</p>
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
      currency: 'MXN'
    }).format(amount)
  }

  // Filtrar movimientos por período
  const filtrarPorPeriodo = (movimientos: Movimiento[]) => {
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

  // Calcular totales filtrados
  const ingresosFiltrados = movimientosFiltrados.filter(m => m.tipo === 'ingreso').reduce((sum, m) => sum + m.monto, 0)
  const egresosFiltrados = movimientosFiltrados.filter(m => m.tipo === 'egreso').reduce((sum, m) => sum + m.monto, 0)

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

  const categoriasEgresos = agruparPorCategoria('egreso')
  const categoriasIngresos = agruparPorCategoria('ingreso')

  // Agrupar por mes (últimos 12 meses)
  const agruparPorMes = (): MesData[] => {
    const meses: MesData[] = []
    const hoy = new Date()

    for (let i = 11; i >= 0; i--) {
      const fecha = new Date(hoy.getFullYear(), hoy.getMonth() - i, 1)
      const mesKey = `${fecha.getFullYear()}-${String(fecha.getMonth() + 1).padStart(2, '0')}`
      const nombreMes = fecha.toLocaleDateString('es-MX', { month: 'long', year: 'numeric' })
      const mesCorto = fecha.toLocaleDateString('es-MX', { month: 'short' })

      const movsDelMes = todosMovimientos.filter(m => {
        const movFecha = new Date(m.fecha)
        return movFecha.getFullYear() === fecha.getFullYear() && movFecha.getMonth() === fecha.getMonth()
      })

      const ingresos = movsDelMes.filter(m => m.tipo === 'ingreso').reduce((sum, m) => sum + m.monto, 0)
      const egresos = movsDelMes.filter(m => m.tipo === 'egreso').reduce((sum, m) => sum + m.monto, 0)

      meses.push({
        mes: nombreMes,
        mesCorto: mesCorto.charAt(0).toUpperCase() + mesCorto.slice(1),
        ingresos,
        egresos,
        balance: ingresos - egresos
      })
    }

    return meses
  }

  const datosMensuales = agruparPorMes()
  const maxMensual = Math.max(...datosMensuales.map(m => Math.max(m.ingresos, m.egresos)))

  // Top movimientos
  const topEgresos = movimientosFiltrados
    .filter(m => m.tipo === 'egreso')
    .sort((a, b) => b.monto - a.monto)
    .slice(0, 10)

  const topIngresos = movimientosFiltrados
    .filter(m => m.tipo === 'ingreso')
    .sort((a, b) => b.monto - a.monto)
    .slice(0, 10)

  const totalSaldo = cuentas.reduce((sum, c) => sum + c.saldoActual, 0)
  const cuentasEmpresas = cuentas.filter(c => c.empresaId !== 'personal')
  const cuentasPersonales = cuentas.filter(c => c.empresaId === 'personal')
  const saldoEmpresas = cuentasEmpresas.reduce((sum, c) => sum + c.saldoActual, 0)
  const saldoPersonal = cuentasPersonales.reduce((sum, c) => sum + c.saldoActual, 0)
  const balance = totalIngresos - totalEgresos

  const stats = [
    {
      title: 'Balance Total',
      value: formatMoney(totalSaldo),
      icon: DollarSign,
      color: 'from-green-500 to-emerald-600',
      description: 'Saldo acumulado'
    },
    {
      title: 'Total Ingresos',
      value: formatMoney(totalIngresos),
      icon: TrendingUp,
      color: 'from-blue-500 to-cyan-600',
      description: 'Abonos totales'
    },
    {
      title: 'Total Egresos',
      value: formatMoney(totalEgresos),
      icon: TrendingDown,
      color: 'from-red-500 to-orange-600',
      description: 'Cargos totales'
    },
    {
      title: 'Balance Neto',
      value: formatMoney(balance),
      icon: BarChart3,
      color: balance >= 0 ? 'from-green-500 to-teal-600' : 'from-orange-500 to-red-600',
      description: 'Ingresos - Egresos'
    },
  ]

  const periodos = [
    { id: 'todo', label: 'Todo' },
    { id: '12meses', label: '12 Meses' },
    { id: '6meses', label: '6 Meses' },
    { id: '3meses', label: '3 Meses' },
    { id: 'mes', label: 'Este Mes' },
  ]

  return (
    <MainLayout>
      <div className="space-y-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 flex items-center gap-6">
              <div className="p-6 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 shadow-xl shadow-cyan-500/30">
                <PieChart className="h-14 w-14 text-white" strokeWidth={2.5} />
              </div>
              Análisis Financiero
            </h1>
            <p className="text-2xl text-gray-400 mt-4 ml-2 font-bold">
              Reportes y estadísticas de tus finanzas
            </p>
          </div>
        </div>

        {/* Main Stats */}
        <div>
          <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 mb-8">Resumen General</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
            {stats.map((stat) => {
              const Icon = stat.icon
              const borderColor = stat.title.includes('Balance Total') ? 'border-emerald-500/40' :
                                 stat.title.includes('Ingresos') ? 'border-blue-500/40' :
                                 stat.title.includes('Egresos') ? 'border-red-500/40' :
                                 'border-cyan-500/40'
              return (
                <Card key={stat.title} className={`group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 ${borderColor} shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-2 hover:border-opacity-100`}>
                  <div className={`absolute top-0 right-0 w-40 h-40 bg-gradient-to-br ${stat.color} opacity-5 rounded-full -mr-20 -mt-20 group-hover:opacity-10 transition-opacity`}></div>
                  <div className="p-8">
                    <div className="flex items-center justify-between mb-6">
                      <div className={`p-5 rounded-2xl bg-gradient-to-br ${stat.color} shadow-lg`}>
                        <Icon className="h-10 w-10 text-white" strokeWidth={2.5} />
                      </div>
                    </div>
                    <p className="text-xl font-black text-gray-400 uppercase tracking-wide mb-3">
                      {stat.title}
                    </p>
                    <p className="text-5xl font-black text-white mb-2">
                      {stat.value}
                    </p>
                    <p className="text-lg text-gray-500 font-bold">
                      {stat.description}
                    </p>
                  </div>
                </Card>
              )
            })}
          </div>
        </div>

        {/* Filtro de período */}
        <div className="flex items-center gap-4 flex-wrap">
          <span className="text-xl font-bold text-gray-400">Período:</span>
          {periodos.map(p => (
            <button
              key={p.id}
              onClick={() => setPeriodoSeleccionado(p.id as typeof periodoSeleccionado)}
              className={`px-6 py-3 rounded-xl font-bold text-lg transition-all ${
                periodoSeleccionado === p.id
                  ? 'bg-gradient-to-r from-cyan-500 to-blue-500 text-white shadow-lg shadow-cyan-500/30'
                  : 'bg-slate-800/50 text-gray-400 hover:bg-slate-700/50 hover:text-white'
              }`}
            >
              {p.label}
            </button>
          ))}
        </div>

        {/* Resumen del período */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <Card className="bg-gradient-to-br from-green-950/50 to-emerald-950/50 border-2 border-green-500/30">
            <div className="p-6">
              <div className="flex items-center gap-4 mb-4">
                <div className="p-4 rounded-xl bg-gradient-to-br from-green-500 to-emerald-600">
                  <ArrowUpCircle className="h-8 w-8 text-white" />
                </div>
                <div>
                  <p className="text-lg text-gray-400 font-bold">Ingresos del Período</p>
                  <p className="text-3xl font-black text-green-400">{formatMoney(ingresosFiltrados)}</p>
                </div>
              </div>
              <p className="text-sm text-gray-500">{movimientosFiltrados.filter(m => m.tipo === 'ingreso').length} movimientos</p>
            </div>
          </Card>

          <Card className="bg-gradient-to-br from-red-950/50 to-orange-950/50 border-2 border-red-500/30">
            <div className="p-6">
              <div className="flex items-center gap-4 mb-4">
                <div className="p-4 rounded-xl bg-gradient-to-br from-red-500 to-orange-600">
                  <ArrowDownCircle className="h-8 w-8 text-white" />
                </div>
                <div>
                  <p className="text-lg text-gray-400 font-bold">Egresos del Período</p>
                  <p className="text-3xl font-black text-red-400">{formatMoney(egresosFiltrados)}</p>
                </div>
              </div>
              <p className="text-sm text-gray-500">{movimientosFiltrados.filter(m => m.tipo === 'egreso').length} movimientos</p>
            </div>
          </Card>

          <Card className={`bg-gradient-to-br ${ingresosFiltrados - egresosFiltrados >= 0 ? 'from-cyan-950/50 to-blue-950/50 border-cyan-500/30' : 'from-orange-950/50 to-red-950/50 border-orange-500/30'} border-2`}>
            <div className="p-6">
              <div className="flex items-center gap-4 mb-4">
                <div className={`p-4 rounded-xl bg-gradient-to-br ${ingresosFiltrados - egresosFiltrados >= 0 ? 'from-cyan-500 to-blue-600' : 'from-orange-500 to-red-600'}`}>
                  <Activity className="h-8 w-8 text-white" />
                </div>
                <div>
                  <p className="text-lg text-gray-400 font-bold">Balance del Período</p>
                  <p className={`text-3xl font-black ${ingresosFiltrados - egresosFiltrados >= 0 ? 'text-cyan-400' : 'text-orange-400'}`}>
                    {formatMoney(ingresosFiltrados - egresosFiltrados)}
                  </p>
                </div>
              </div>
              <p className="text-sm text-gray-500">{movimientosFiltrados.length} movimientos totales</p>
            </div>
          </Card>
        </div>

        {/* Gráfica de Tendencia Mensual */}
        <div>
          <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 mb-8 flex items-center gap-4">
            <Calendar className="h-10 w-10 text-purple-400" />
            Tendencia Mensual (Últimos 12 meses)
          </h2>
          <Card className="bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 border-purple-500/30">
            <CardContent className="p-8">
              <div className="space-y-4">
                {datosMensuales.map((mes, idx) => (
                  <div key={idx} className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="text-lg font-bold text-gray-300 w-24">{mes.mesCorto}</span>
                      <div className="flex-1 mx-4 space-y-1">
                        {/* Barra de ingresos */}
                        <div className="flex items-center gap-2">
                          <div className="w-16 text-right text-sm text-green-400 font-bold">
                            {mes.ingresos > 0 ? formatMoney(mes.ingresos) : '-'}
                          </div>
                          <div className="flex-1 h-4 bg-slate-800/50 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-green-500 to-emerald-400 rounded-full transition-all duration-500"
                              style={{ width: `${maxMensual > 0 ? (mes.ingresos / maxMensual) * 100 : 0}%` }}
                            />
                          </div>
                        </div>
                        {/* Barra de egresos */}
                        <div className="flex items-center gap-2">
                          <div className="w-16 text-right text-sm text-red-400 font-bold">
                            {mes.egresos > 0 ? formatMoney(mes.egresos) : '-'}
                          </div>
                          <div className="flex-1 h-4 bg-slate-800/50 rounded-full overflow-hidden">
                            <div
                              className="h-full bg-gradient-to-r from-red-500 to-orange-400 rounded-full transition-all duration-500"
                              style={{ width: `${maxMensual > 0 ? (mes.egresos / maxMensual) * 100 : 0}%` }}
                            />
                          </div>
                        </div>
                      </div>
                      <span className={`text-lg font-black w-32 text-right ${mes.balance >= 0 ? 'text-green-400' : 'text-red-400'}`}>
                        {formatMoney(mes.balance)}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex items-center justify-center gap-8 mt-8 pt-6 border-t border-slate-700">
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-gradient-to-r from-green-500 to-emerald-400" />
                  <span className="text-gray-400 font-bold">Ingresos</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="w-4 h-4 rounded-full bg-gradient-to-r from-red-500 to-orange-400" />
                  <span className="text-gray-400 font-bold">Egresos</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Análisis por Categoría */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Egresos por Categoría */}
          <div>
            <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400 mb-6 flex items-center gap-3">
              <Tag className="h-8 w-8 text-red-400" />
              Gastos por Categoría
            </h2>
            <Card className="bg-gradient-to-br from-slate-950/50 to-red-950/30 border-2 border-red-500/30">
              <CardContent className="p-6">
                {categoriasEgresos.length === 0 ? (
                  <p className="text-center text-gray-400 py-8">No hay gastos en este período</p>
                ) : (
                  <div className="space-y-4">
                    {categoriasEgresos.slice(0, 10).map((cat, idx) => (
                      <div key={cat.id} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-2xl font-black text-gray-500">#{idx + 1}</span>
                            <span className="text-lg font-bold text-white">{cat.nombre}</span>
                            <span className="text-sm text-gray-500">({cat.cantidad} mov.)</span>
                          </div>
                          <div className="text-right">
                            <p className="text-xl font-black text-red-400">{formatMoney(cat.total)}</p>
                            <p className="text-sm text-gray-500">{cat.porcentaje.toFixed(1)}%</p>
                          </div>
                        </div>
                        <div className="h-3 bg-slate-800/50 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-red-500 to-orange-400 rounded-full transition-all duration-500"
                            style={{ width: `${cat.porcentaje}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Ingresos por Categoría */}
          <div>
            <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-400 mb-6 flex items-center gap-3">
              <Tag className="h-8 w-8 text-green-400" />
              Ingresos por Categoría
            </h2>
            <Card className="bg-gradient-to-br from-slate-950/50 to-green-950/30 border-2 border-green-500/30">
              <CardContent className="p-6">
                {categoriasIngresos.length === 0 ? (
                  <p className="text-center text-gray-400 py-8">No hay ingresos en este período</p>
                ) : (
                  <div className="space-y-4">
                    {categoriasIngresos.slice(0, 10).map((cat, idx) => (
                      <div key={cat.id} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <span className="text-2xl font-black text-gray-500">#{idx + 1}</span>
                            <span className="text-lg font-bold text-white">{cat.nombre}</span>
                            <span className="text-sm text-gray-500">({cat.cantidad} mov.)</span>
                          </div>
                          <div className="text-right">
                            <p className="text-xl font-black text-green-400">{formatMoney(cat.total)}</p>
                            <p className="text-sm text-gray-500">{cat.porcentaje.toFixed(1)}%</p>
                          </div>
                        </div>
                        <div className="h-3 bg-slate-800/50 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-green-500 to-emerald-400 rounded-full transition-all duration-500"
                            style={{ width: `${cat.porcentaje}%` }}
                          />
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Top Movimientos */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Top Gastos */}
          <div>
            <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400 mb-6 flex items-center gap-3">
              <Target className="h-8 w-8 text-red-400" />
              Top 10 Gastos Más Grandes
            </h2>
            <Card className="bg-gradient-to-br from-slate-950/50 to-red-950/30 border-2 border-red-500/30">
              <CardContent className="p-6">
                {topEgresos.length === 0 ? (
                  <p className="text-center text-gray-400 py-8">No hay gastos en este período</p>
                ) : (
                  <div className="space-y-3">
                    {topEgresos.map((mov, idx) => {
                      const categoria = categorias.find(c => c.id === mov.categoriaId)
                      return (
                        <div key={mov.id} className="flex items-center gap-4 p-4 bg-slate-900/50 rounded-xl hover:bg-slate-800/50 transition-colors">
                          <span className="text-2xl font-black text-gray-600 w-8">#{idx + 1}</span>
                          <div className="flex-1 min-w-0">
                            <p className="text-lg font-bold text-white truncate">{mov.descripcion}</p>
                            <div className="flex items-center gap-2 text-sm text-gray-400">
                              <span>{mov.fecha.toLocaleDateString('es-MX')}</span>
                              {categoria && (
                                <>
                                  <span>•</span>
                                  <span className="text-orange-400">{categoria.nombre}</span>
                                </>
                              )}
                            </div>
                          </div>
                          <p className="text-xl font-black text-red-400">{formatMoney(mov.monto)}</p>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Top Ingresos */}
          <div>
            <h2 className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-green-400 to-emerald-400 mb-6 flex items-center gap-3">
              <Target className="h-8 w-8 text-green-400" />
              Top 10 Ingresos Más Grandes
            </h2>
            <Card className="bg-gradient-to-br from-slate-950/50 to-green-950/30 border-2 border-green-500/30">
              <CardContent className="p-6">
                {topIngresos.length === 0 ? (
                  <p className="text-center text-gray-400 py-8">No hay ingresos en este período</p>
                ) : (
                  <div className="space-y-3">
                    {topIngresos.map((mov, idx) => {
                      const categoria = categorias.find(c => c.id === mov.categoriaId)
                      return (
                        <div key={mov.id} className="flex items-center gap-4 p-4 bg-slate-900/50 rounded-xl hover:bg-slate-800/50 transition-colors">
                          <span className="text-2xl font-black text-gray-600 w-8">#{idx + 1}</span>
                          <div className="flex-1 min-w-0">
                            <p className="text-lg font-bold text-white truncate">{mov.descripcion}</p>
                            <div className="flex items-center gap-2 text-sm text-gray-400">
                              <span>{mov.fecha.toLocaleDateString('es-MX')}</span>
                              {categoria && (
                                <>
                                  <span>•</span>
                                  <span className="text-emerald-400">{categoria.nombre}</span>
                                </>
                              )}
                            </div>
                          </div>
                          <p className="text-xl font-black text-green-400">{formatMoney(mov.monto)}</p>
                        </div>
                      )
                    })}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Distribution */}
        <div>
          <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 mb-8">Distribución de Saldos</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {[
              {
                title: 'Empresas',
                value: formatMoney(saldoEmpresas),
                count: empresas.length,
                icon: Building2,
                color: 'from-blue-500 to-cyan-600',
                description: `${cuentasEmpresas.length} cuentas`,
                borderColor: 'border-emerald-500/40'
              },
              {
                title: 'Personal',
                value: formatMoney(saldoPersonal),
                count: cuentasPersonales.length,
                icon: User,
                color: 'from-purple-500 to-pink-600',
                description: `${cuentasPersonales.length} cuentas`,
                borderColor: 'border-purple-500/40'
              }
            ].map((stat) => {
              const Icon = stat.icon
              const percentage = totalSaldo > 0 ? ((parseFloat(stat.value.replace(/[^0-9.-]+/g, "")) / totalSaldo) * 100).toFixed(1) : 0
              return (
                <Card key={stat.title} className={`group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 ${stat.borderColor} shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-2`}>
                  <div className={`absolute top-0 right-0 w-48 h-48 bg-gradient-to-br ${stat.color} opacity-5 rounded-full -mr-24 -mt-24 group-hover:opacity-10 transition-opacity`}></div>
                  <div className="p-10">
                    <div className="flex items-start justify-between mb-8">
                      <div>
                        <div className="flex items-center gap-5 mb-4">
                          <div className={`p-5 rounded-2xl bg-gradient-to-br ${stat.color} shadow-lg`}>
                            <Icon className="h-12 w-12 text-white" strokeWidth={2.5} />
                          </div>
                          <div>
                            <p className="text-2xl font-black text-white uppercase tracking-wide">
                              {stat.title}
                            </p>
                            <p className="text-lg text-gray-400 font-bold">{stat.description}</p>
                          </div>
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-6xl font-black text-white">{percentage}%</p>
                      </div>
                    </div>
                    <div className="space-y-5">
                      <div>
                        <p className="text-xl font-black text-gray-400 mb-2">Saldo Total</p>
                        <p className="text-5xl font-black text-emerald-400">
                          {stat.value}
                        </p>
                      </div>
                      <div className="w-full bg-slate-800/50 rounded-full h-5">
                        <div
                          className={`h-5 rounded-full bg-gradient-to-r ${stat.color} shadow-lg`}
                          style={{ width: `${percentage}%` }}
                        ></div>
                      </div>
                    </div>
                  </div>
                </Card>
              )
            })}
          </div>
        </div>

        {/* Top Accounts */}
        <div>
          <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-cyan-400 to-blue-400 mb-8">Cuentas Principales</h2>
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 border-cyan-500/30 shadow-xl">
            <CardContent className="p-10">
              {cuentas.length === 0 ? (
                <div className="text-center py-16">
                  <div className="p-8 rounded-3xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 w-fit mx-auto mb-6 shadow-xl shadow-cyan-500/30">
                    <Wallet className="h-20 w-20 text-white" strokeWidth={2.5} />
                  </div>
                  <p className="text-3xl font-black text-white mb-4">
                    No hay cuentas para analizar
                  </p>
                  <p className="text-xl text-gray-400 font-bold">
                    Crea cuentas bancarias para ver el análisis financiero
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {cuentas
                    .sort((a, b) => b.saldoActual - a.saldoActual)
                    .slice(0, 10)
                    .map((cuenta) => {
                      const percentage = totalSaldo > 0 ? ((cuenta.saldoActual / totalSaldo) * 100).toFixed(1) : 0
                      const esEmpresa = cuenta.empresaId !== 'personal'
                      return (
                        <div
                          key={cuenta.id}
                          className="group flex items-center justify-between p-8 rounded-2xl bg-gradient-to-br from-slate-900/50 to-blue-900/30 hover:from-slate-900/70 hover:to-blue-900/50 transition-all duration-300 cursor-pointer border-2 border-cyan-500/20 hover:border-cyan-400/50 hover:shadow-lg hover:shadow-cyan-500/20"
                          onClick={() => router.push(`/cuentas/${cuenta.id}`)}
                        >
                          <div className="flex items-center gap-6 flex-1">
                            <div className={`p-5 rounded-2xl bg-gradient-to-br ${esEmpresa ? 'from-emerald-500 via-cyan-500 to-blue-500' : 'from-purple-500 to-pink-500'} shadow-lg`}>
                              <Wallet className="h-10 w-10 text-white" strokeWidth={2.5} />
                            </div>
                            <div className="flex-1">
                              <p className="font-black text-white text-2xl mb-1">{cuenta.nombre}</p>
                              <p className="text-lg text-gray-400 font-bold">{cuenta.banco}</p>
                            </div>
                          </div>
                          <div className="text-right">
                            <p className="text-4xl font-black text-emerald-400 mb-1">
                              {formatMoney(cuenta.saldoActual)}
                            </p>
                            <p className="text-lg text-cyan-400 font-black">{percentage}% del total</p>
                          </div>
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
