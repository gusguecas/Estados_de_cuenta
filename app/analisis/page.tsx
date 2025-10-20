'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuentas, getEmpresas, getMovimientos } from '@/lib/firestore'
import type { CuentaBancaria, Empresa } from '@/lib/types'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import {
  BarChart3,
  TrendingUp,
  TrendingDown,
  DollarSign,
  PieChart,
  Calendar,
  Building2,
  User,
  Wallet
} from 'lucide-react'
import { MainLayout } from '@/components/main-layout'

export default function AnalisisPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [empresas, setEmpresas] = useState<Empresa[]>([])
  const [loading, setLoading] = useState(true)
  const [totalIngresos, setTotalIngresos] = useState(0)
  const [totalEgresos, setTotalEgresos] = useState(0)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const [cuentasData, empresasData] = await Promise.all([
        getCuentas(user.uid),
        getEmpresas(user.uid)
      ])
      setCuentas(cuentasData)
      setEmpresas(empresasData)

      // Cargar movimientos de todas las cuentas para calcular ingresos y egresos
      let ingresos = 0
      let egresos = 0

      for (const cuenta of cuentasData) {
        const movimientos = await getMovimientos(cuenta.id)
        movimientos.forEach(mov => {
          if (mov.tipo === 'ingreso') {
            ingresos += mov.monto
          } else {
            egresos += mov.monto
          }
        })
      }

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
      bgColor: 'bg-green-50',
      textColor: 'text-green-700',
      description: 'Saldo acumulado'
    },
    {
      title: 'Total Ingresos',
      value: formatMoney(totalIngresos),
      icon: TrendingUp,
      color: 'from-blue-500 to-cyan-600',
      bgColor: 'bg-blue-50',
      textColor: 'text-blue-700',
      description: 'Abonos totales'
    },
    {
      title: 'Total Egresos',
      value: formatMoney(totalEgresos),
      icon: TrendingDown,
      color: 'from-red-500 to-orange-600',
      bgColor: 'bg-red-50',
      textColor: 'text-red-700',
      description: 'Cargos totales'
    },
    {
      title: 'Balance Neto',
      value: formatMoney(balance),
      icon: BarChart3,
      color: balance >= 0 ? 'from-green-500 to-teal-600' : 'from-orange-500 to-red-600',
      bgColor: balance >= 0 ? 'bg-green-50' : 'bg-orange-50',
      textColor: balance >= 0 ? 'text-green-700' : 'text-orange-700',
      description: 'Ingresos - Egresos'
    },
  ]

  const distributionStats = [
    {
      title: 'Empresas',
      value: formatMoney(saldoEmpresas),
      count: empresas.length,
      icon: Building2,
      color: 'from-blue-500 to-cyan-600',
      bgColor: 'bg-blue-50',
      textColor: 'text-blue-700',
      description: `${cuentasEmpresas.length} cuentas`
    },
    {
      title: 'Personal',
      value: formatMoney(saldoPersonal),
      count: cuentasPersonales.length,
      icon: User,
      color: 'from-purple-500 to-pink-600',
      bgColor: 'bg-purple-50',
      textColor: 'text-purple-700',
      description: `${cuentasPersonales.length} cuentas`
    },
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

        {/* Distribution */}
        <div>
          <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400 mb-8">Distribución de Saldos</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
            {distributionStats.map((stat) => {
              const Icon = stat.icon
              const percentage = totalSaldo > 0 ? ((parseFloat(stat.value.replace(/[^0-9.-]+/g, "")) / totalSaldo) * 100).toFixed(1) : 0
              const borderColor = stat.title === 'Empresas' ? 'border-emerald-500/40' : 'border-purple-500/40'
              return (
                <Card key={stat.title} className={`group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-2 ${borderColor} shadow-xl hover:shadow-2xl transition-all duration-300 hover:-translate-y-2`}>
                  <div className={`absolute top-0 right-0 w-48 h-48 bg-gradient-to-br ${stat.color} opacity-5 rounded-full -mr-24 -mt-24 group-hover:opacity-10 transition-opacity`}></div>
                  <div className="p-10">
                    <div className="flex items-start justify-between mb-8">
                      <div>
                        <div className="flex items-center gap-5 mb-4">
                          <div className={`p-5 rounded-2xl bg-gradient-to-br ${stat.color} shadow-lg shadow-${stat.title === 'Empresas' ? 'emerald' : 'purple'}-500/30`}>
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
