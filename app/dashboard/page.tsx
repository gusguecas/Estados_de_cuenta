'use client'

export const dynamic = 'force-dynamic'

import { useAuth } from '@/lib/auth-context'
import { useRouter } from 'next/navigation'
import { Card } from '@/components/ui/card'
import { useEffect, useState, useCallback } from 'react'
import { MainLayout } from '@/components/main-layout'
import { getEmpresas, getCuentas, getEmpresa } from '@/lib/firestore'
import type { Empresa, CuentaBancaria } from '@/lib/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { TransferenciaModal } from '@/components/transferencia-modal'
import { PaymentAlertModal } from '@/components/payment-alert-modal'
import { requestNotificationPermission, sendMultiplePaymentNotifications, type PaymentAlert } from '@/lib/notifications'
import Image from 'next/image'
import {
  Building2,
  User,
  Wallet,
  ArrowRight,
  DollarSign,
  PieChart,
  CreditCard,
  AlertTriangle,
  Calendar,
  Clock,
  ArrowLeftRight
} from 'lucide-react'

export default function DashboardPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [empresas, setEmpresas] = useState<Empresa[]>([])
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [loading, setLoading] = useState(true)
  const [showTransferenciaModal, setShowTransferenciaModal] = useState(false)
  const [showAlertModal, setShowAlertModal] = useState(false)
  const [paymentAlerts, setPaymentAlerts] = useState<PaymentAlert[]>([])

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const [empresasData, cuentasData] = await Promise.all([
        getEmpresas(user.uid),
        getCuentas(user.uid)
      ])
      setEmpresas(empresasData)
      setCuentas(cuentasData)

      // Calcular alertas de pago
      const alerts: PaymentAlert[] = []
      const hoy = new Date()
      const diaActual = hoy.getDate()
      const mesActual = hoy.getMonth()
      const anoActual = hoy.getFullYear()

      for (const cuenta of cuentasData) {
        if (cuenta.tipoCuenta === 'credito' && cuenta.diaLimitePago && cuenta.activo) {
          const diaLimite = cuenta.diaLimitePago
          let fechaLimite = new Date(anoActual, mesActual, diaLimite)

          // Si ya pasó este mes, calcular para el próximo mes
          if (diaLimite < diaActual) {
            fechaLimite = new Date(anoActual, mesActual + 1, diaLimite)
          }

          const diasHasta = Math.ceil((fechaLimite.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

          if (diasHasta <= 3 && diasHasta >= 0) {
            let empresaNombre: string | undefined
            if (cuenta.empresaId && cuenta.empresaId !== 'personal') {
              try {
                const empresa = await getEmpresa(cuenta.empresaId)
                empresaNombre = empresa?.nombre
              } catch (e) {
                console.error('Error al obtener empresa:', e)
              }
            }

            alerts.push({
              cuenta: cuenta.nombre,
              dias: diasHasta,
              empresa: empresaNombre,
              tipo: cuenta.empresaId === 'personal' ? 'personal' : 'empresa'
            })
          }
        }
      }

      setPaymentAlerts(alerts)

      // Mostrar modal si hay alertas urgentes
      if (alerts.length > 0) {
        setShowAlertModal(true)
      }
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

  // Solicitar permisos de notificación y enviar notificaciones cuando haya alertas
  useEffect(() => {
    if (paymentAlerts.length > 0) {
      // Solicitar permiso de notificaciones
      requestNotificationPermission().then((permission) => {
        if (permission === 'granted') {
          // Enviar notificaciones después de un pequeño delay
          setTimeout(() => {
            sendMultiplePaymentNotifications(paymentAlerts)
          }, 1000)
        }
      })
    }
  }, [paymentAlerts])

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-20 w-20 border-4 border-emerald-500 border-t-transparent mx-auto shadow-2xl shadow-emerald-500/30"></div>
          <p className="mt-8 text-2xl font-bold text-emerald-400">Cargando dashboard...</p>
        </div>
      </div>
    )
  }

  if (!user) return null

  // Agrupar saldos por moneda
  const saldosPorMoneda = cuentas.reduce((acc, cuenta) => {
    const moneda = cuenta.moneda
    if (!acc[moneda]) {
      acc[moneda] = {
        total: 0,
        empresas: 0,
        personales: 0,
        cuentasTotales: 0
      }
    }
    acc[moneda].total += cuenta.saldoActual || 0
    acc[moneda].cuentasTotales += 1

    if (cuenta.empresaId === 'personal') {
      acc[moneda].personales += cuenta.saldoActual || 0
    } else {
      acc[moneda].empresas += cuenta.saldoActual || 0
    }

    return acc
  }, {} as Record<string, { total: number; empresas: number; personales: number; cuentasTotales: number }>)

  const totalSaldo = cuentas.reduce((sum, cuenta) => sum + (cuenta.saldoActual || 0), 0)
  const cuentasEmpresas = cuentas.filter(c => c.empresaId !== 'personal')
  const cuentasPersonales = cuentas.filter(c => c.empresaId === 'personal')

  // Calcular alertas de pago para tarjetas de crédito
  const calcularDiasParaPago = (diaLimitePago: number) => {
    const hoy = new Date()
    const diaActual = hoy.getDate()
    const mesActual = hoy.getMonth()
    const anoActual = hoy.getFullYear()

    let fechaPago = new Date(anoActual, mesActual, diaLimitePago)

    // Si el día de pago ya pasó este mes, calcular para el próximo mes
    if (diaActual > diaLimitePago) {
      fechaPago = new Date(anoActual, mesActual + 1, diaLimitePago)
    }

    const diferencia = fechaPago.getTime() - hoy.getTime()
    const dias = Math.ceil(diferencia / (1000 * 60 * 60 * 24))

    return dias
  }

  const tarjetasConAlerta = cuentas
    .filter(c => c.tipoCuenta === 'credito' && c.diaLimitePago && c.activo)
    .map(cuenta => ({
      ...cuenta,
      diasParaPago: calcularDiasParaPago(cuenta.diaLimitePago!)
    }))
    .sort((a, b) => a.diasParaPago - b.diasParaPago)

  const stats = [
    {
      title: 'Saldo Total',
      value: `$${totalSaldo.toLocaleString('es-MX', { minimumFractionDigits: 2 })}`,
      icon: DollarSign,
      color: 'from-emerald-500 via-green-500 to-teal-500',
      bgColor: 'bg-emerald-950/50',
      textColor: 'text-emerald-400',
      borderColor: 'border-emerald-500/30',
      shadowColor: 'shadow-emerald-500/20',
      description: 'Todas las cuentas'
    },
    {
      title: 'Empresas',
      value: empresas.length,
      icon: Building2,
      color: 'from-blue-500 via-cyan-500 to-sky-500',
      bgColor: 'bg-blue-950/50',
      textColor: 'text-blue-400',
      borderColor: 'border-blue-500/30',
      shadowColor: 'shadow-blue-500/20',
      description: `${cuentasEmpresas.length} cuentas`
    },
    {
      title: 'Personal',
      value: cuentasPersonales.length,
      icon: User,
      color: 'from-purple-500 via-fuchsia-500 to-pink-500',
      bgColor: 'bg-purple-950/50',
      textColor: 'text-purple-400',
      borderColor: 'border-purple-500/30',
      shadowColor: 'shadow-purple-500/20',
      description: 'Cuentas personales'
    },
    {
      title: 'Total Cuentas',
      value: cuentas.length,
      icon: Wallet,
      color: 'from-orange-500 via-amber-500 to-yellow-500',
      bgColor: 'bg-orange-950/50',
      textColor: 'text-orange-400',
      borderColor: 'border-orange-500/30',
      shadowColor: 'shadow-orange-500/20',
      description: 'Activas'
    },
  ]

  const quickActions = [
    {
      title: 'Gestionar Empresas',
      description: 'Ver y administrar tus empresas',
      icon: Building2,
      color: 'from-blue-500 via-cyan-500 to-sky-500',
      borderColor: 'border-blue-500/30',
      shadowColor: 'shadow-blue-500/20',
      href: '/empresas'
    },
    {
      title: 'Finanzas Personales',
      description: 'Administra tus cuentas personales',
      icon: User,
      color: 'from-purple-500 via-fuchsia-500 to-pink-500',
      borderColor: 'border-purple-500/30',
      shadowColor: 'shadow-purple-500/20',
      href: '/personal'
    },
    {
      title: 'Análisis Financiero',
      description: 'Reportes y estadísticas',
      icon: PieChart,
      color: 'from-emerald-500 via-green-500 to-teal-500',
      borderColor: 'border-emerald-500/30',
      shadowColor: 'shadow-emerald-500/20',
      href: '/analisis'
    },
  ]

  return (
    <MainLayout>
      <div className="space-y-8">
        {/* Welcome Section */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-black bg-gradient-to-r from-emerald-400 via-cyan-400 to-blue-400 text-transparent bg-clip-text mb-3">
              Bienvenido de nuevo 👋
            </h1>
            <p className="text-2xl text-slate-400 font-semibold mt-2">
              {user.email}
            </p>
          </div>
          {cuentas.length >= 2 && (
            <Button
              onClick={() => setShowTransferenciaModal(true)}
              size="lg"
              className="bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-500 hover:via-green-500 hover:to-teal-500 text-white shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all text-lg font-bold px-8 py-6 transform hover:scale-105"
            >
              <ArrowLeftRight className="mr-3 h-6 w-6" />
              Nueva Transferencia
            </Button>
          )}
        </div>

        {/* Stats por Moneda */}
        <div className="space-y-6">
          <h2 className="text-4xl font-black bg-gradient-to-r from-emerald-400 to-cyan-400 text-transparent bg-clip-text mb-8">Saldos por Moneda</h2>

          {Object.keys(saldosPorMoneda).length === 0 ? (
            <Card className="border border-slate-700 bg-slate-900/50 shadow-2xl p-12">
              <p className="text-2xl text-slate-400 text-center font-bold">No hay cuentas registradas aún</p>
            </Card>
          ) : (
            Object.entries(saldosPorMoneda).map(([moneda, datos]) => {
              const monedaSymbol = moneda === 'MXN' ? '🇲🇽 MXN' : moneda === 'USD' ? '🇺🇸 USD' : '🇪🇺 EUR'
              const monedaColor = moneda === 'MXN' ? 'from-green-500 via-emerald-500 to-teal-500' : moneda === 'USD' ? 'from-blue-500 via-cyan-500 to-sky-500' : 'from-purple-500 via-fuchsia-500 to-pink-500'
              const borderColor = moneda === 'MXN' ? 'border-emerald-500/30' : moneda === 'USD' ? 'border-blue-500/30' : 'border-purple-500/30'
              const textColor = moneda === 'MXN' ? 'text-emerald-400' : moneda === 'USD' ? 'text-blue-400' : 'text-purple-400'
              const shadowColor = moneda === 'MXN' ? 'shadow-emerald-500/20' : moneda === 'USD' ? 'shadow-blue-500/20' : 'shadow-purple-500/20'

              return (
                <Card key={moneda} className={`border ${borderColor} bg-slate-900/50 shadow-2xl ${shadowColor} backdrop-blur-xl`}>
                  <div className="p-8">
                    <div className="flex items-center justify-between mb-8">
                      <div className="flex items-center gap-4">
                        <div className={`p-5 rounded-2xl bg-gradient-to-br ${monedaColor} shadow-xl ${shadowColor}`}>
                          <DollarSign className="h-12 w-12 text-white" strokeWidth={2.5} />
                        </div>
                        <h3 className="text-4xl font-black text-white">{monedaSymbol}</h3>
                      </div>
                      <div className="text-right">
                        <p className="text-lg text-slate-400 font-bold mb-1">SALDO TOTAL</p>
                        <p className={`text-5xl font-black ${textColor}`}>
                          {new Intl.NumberFormat('es-MX', {
                            style: 'currency',
                            currency: moneda,
                            minimumFractionDigits: 2
                          }).format(datos.total)}
                        </p>
                      </div>
                    </div>

                    <div className="grid grid-cols-3 gap-6">
                      <div className="p-6 rounded-xl bg-slate-800/50 border border-slate-700">
                        <p className="text-base text-slate-400 font-bold mb-2">EMPRESAS</p>
                        <p className="text-3xl font-black text-white">
                          {new Intl.NumberFormat('es-MX', {
                            style: 'currency',
                            currency: moneda,
                            minimumFractionDigits: 2
                          }).format(datos.empresas)}
                        </p>
                      </div>

                      <div className="p-6 rounded-xl bg-slate-800/50 border border-slate-700">
                        <p className="text-base text-slate-400 font-bold mb-2">PERSONAL</p>
                        <p className="text-3xl font-black text-white">
                          {new Intl.NumberFormat('es-MX', {
                            style: 'currency',
                            currency: moneda,
                            minimumFractionDigits: 2
                          }).format(datos.personales)}
                        </p>
                      </div>

                      <div className="p-6 rounded-xl bg-slate-800/50 border border-slate-700">
                        <p className="text-base text-slate-400 font-bold mb-2">CUENTAS</p>
                        <p className="text-3xl font-black text-white">{datos.cuentasTotales}</p>
                      </div>
                    </div>
                  </div>
                </Card>
              )
            })
          )}
        </div>

        {/* Stats Grid Generales */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
          {stats.map((stat) => {
            const Icon = stat.icon
            return (
              <Card key={stat.title} className={`relative overflow-hidden border ${stat.borderColor} ${stat.bgColor} shadow-2xl ${stat.shadowColor} hover:shadow-3xl transition-all duration-300 hover:-translate-y-2 backdrop-blur-xl`}>
                <div className={`absolute top-0 right-0 w-40 h-40 bg-gradient-to-br ${stat.color} opacity-20 rounded-full -mr-20 -mt-20`}></div>
                <div className="p-8 relative z-10">
                  <div className="flex items-center justify-between mb-6">
                    <div className={`p-4 rounded-2xl bg-gradient-to-br ${stat.color} shadow-xl ${stat.shadowColor}`}>
                      <Icon className="h-10 w-10 text-white" strokeWidth={2.5} />
                    </div>
                  </div>
                  <p className="text-base font-bold text-slate-400 uppercase tracking-wider mb-2">
                    {stat.title}
                  </p>
                  <p className={`text-4xl font-black ${stat.textColor} mb-2`}>
                    {stat.value}
                  </p>
                  <p className="text-base text-slate-500 font-semibold">
                    {stat.description}
                  </p>
                </div>
              </Card>
            )
          })}
        </div>

        {/* Quick Actions */}
        <div>
          <h2 className="text-4xl font-black bg-gradient-to-r from-emerald-400 to-cyan-400 text-transparent bg-clip-text mb-8">Acciones Rápidas</h2>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            {quickActions.map((action) => {
              const Icon = action.icon
              return (
                <Card
                  key={action.title}
                  className={`group relative overflow-hidden border ${action.borderColor} bg-slate-900/50 shadow-2xl ${action.shadowColor} hover:shadow-3xl transition-all duration-300 cursor-pointer hover:-translate-y-2 backdrop-blur-xl`}
                  onClick={() => router.push(action.href)}
                >
                  <div className={`absolute inset-0 bg-gradient-to-br ${action.color} opacity-0 group-hover:opacity-10 transition-opacity duration-300`}></div>
                  <div className="p-10 relative z-10">
                    <div className={`inline-flex p-5 rounded-3xl bg-gradient-to-br ${action.color} mb-8 shadow-2xl ${action.shadowColor} group-hover:scale-110 transition-transform duration-300`}>
                      <Icon className="h-12 w-12 text-white" strokeWidth={2.5} />
                    </div>
                    <h3 className="text-2xl font-black text-white mb-3">
                      {action.title}
                    </h3>
                    <p className="text-lg text-slate-400 mb-8 font-semibold">
                      {action.description}
                    </p>
                    <div className="flex items-center text-emerald-400 font-bold text-lg group-hover:text-emerald-300">
                      Ver más
                      <ArrowRight className="ml-2 h-6 w-6 group-hover:translate-x-2 transition-transform" />
                    </div>
                  </div>
                </Card>
              )
            })}
          </div>
        </div>

        {/* Alertas de Pago de Tarjetas */}
        {tarjetasConAlerta.length > 0 && (
          <div>
            <h2 className="text-4xl font-black mb-8 flex items-center gap-4">
              <div className="p-4 rounded-2xl bg-gradient-to-br from-orange-500 via-red-500 to-orange-500 shadow-xl shadow-orange-500/30">
                <AlertTriangle className="h-10 w-10 text-white" strokeWidth={2.5} />
              </div>
              <span className="bg-gradient-to-r from-orange-400 to-red-400 text-transparent bg-clip-text">
                Pagos de Tarjetas Próximos
              </span>
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
              {tarjetasConAlerta.map((tarjeta) => {
                const urgente = tarjeta.diasParaPago <= 3
                const proximo = tarjeta.diasParaPago <= 7

                return (
                  <Card
                    key={tarjeta.id}
                    className={`group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 shadow-2xl hover:shadow-3xl transition-all duration-300 cursor-pointer hover:-translate-y-2 backdrop-blur-sm ${
                      urgente ? 'border-2 border-red-500/50 hover:border-red-500' : proximo ? 'border-2 border-orange-500/50 hover:border-orange-500' : 'border-2 border-cyan-500/30 hover:border-cyan-500'
                    }`}
                    onClick={() => router.push(`/cuentas/${tarjeta.id}`)}
                  >
                    <div className={`absolute top-0 right-0 w-48 h-48 bg-gradient-to-br ${
                      urgente ? 'from-red-500 to-orange-500' : proximo ? 'from-orange-500 to-yellow-500' : 'from-blue-500 to-cyan-500'
                    } opacity-10 rounded-full -mr-24 -mt-24`}></div>
                    <div className="p-8">
                      <div className="flex items-start justify-between mb-6">
                        <div className="flex items-center gap-3">
                          {tarjeta.logo ? (
                            <div className="relative w-12 h-12 flex items-center justify-center">
                              <Image
                                src={tarjeta.logo}
                                alt={tarjeta.banco}
                                fill
                                className="object-contain"
                              />
                            </div>
                          ) : (
                            <div className={`p-4 rounded-2xl bg-gradient-to-br ${
                              urgente ? 'from-red-500 to-orange-500' : proximo ? 'from-orange-500 to-yellow-500' : 'from-blue-500 to-cyan-500'
                            } shadow-lg group-hover:scale-110 transition-transform duration-300`}>
                              <CreditCard className="h-8 w-8 text-white" strokeWidth={2.5} />
                            </div>
                          )}
                          <h3 className="text-3xl font-black text-white">{tarjeta.nombre}</h3>
                        </div>
                        <div className="flex flex-col items-end gap-2">
                          <Badge className={`text-xl px-5 py-2 font-black ${
                            urgente ? 'bg-red-500/20 text-red-300 border-2 border-red-500/50' : proximo ? 'bg-orange-500/20 text-orange-300 border-2 border-orange-500/50' : 'bg-blue-500/20 text-blue-300 border-2 border-blue-500/50'
                          }`}>
                            {tarjeta.diasParaPago === 0 ? 'HOY' :
                             tarjeta.diasParaPago === 1 ? 'MAÑANA' :
                             `${tarjeta.diasParaPago} DÍAS`}
                          </Badge>
                          <span className="text-4xl">
                            {tarjeta.moneda === 'MXN' ? '🇲🇽' : tarjeta.moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                          </span>
                        </div>
                      </div>

                      <p className="text-lg text-cyan-300 mb-6 font-semibold -mt-4">{tarjeta.banco}</p>

                      <div className="space-y-4">
                        <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900/50 border border-slate-700">
                          <span className="text-lg text-slate-400 flex items-center gap-2 font-bold">
                            <Calendar className="h-6 w-6" strokeWidth={2.5} />
                            Día de corte:
                          </span>
                          <span className="text-xl font-black text-white">{tarjeta.diaCorte || 'N/A'}</span>
                        </div>
                        <div className="flex items-center justify-between p-4 rounded-xl bg-slate-900/50 border border-slate-700">
                          <span className="text-lg text-slate-400 flex items-center gap-2 font-bold">
                            <Clock className="h-6 w-6" strokeWidth={2.5} />
                            Límite de pago:
                          </span>
                          <span className="text-xl font-black text-white">{tarjeta.diaLimitePago}</span>
                        </div>
                        <div className="pt-4 border-t border-slate-700">
                          <div className="flex justify-between items-center mb-2">
                            <span className="text-lg text-slate-400 font-bold">Saldo actual:</span>
                            <span className={`text-4xl font-black ${
                              tarjeta.saldoActual < 0 ? 'text-red-400' : 'text-emerald-400'
                            }`}>
                              ${Math.abs(tarjeta.saldoActual).toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                            </span>
                          </div>
                          {tarjeta.limiteCredito && (
                            <div className="flex justify-between items-center">
                              <span className="text-base text-slate-500 font-bold">Límite:</span>
                              <span className="text-xl font-black text-slate-300">
                                ${tarjeta.limiteCredito.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </Card>
                )
              })}
            </div>
          </div>
        )}

        {/* Recent Activity */}
        <div>
          <h2 className="text-4xl font-black bg-gradient-to-r from-emerald-400 to-cyan-400 text-transparent bg-clip-text mb-8">
            Actividad Reciente
          </h2>
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
            <div className="p-10">
              {cuentas.length === 0 ? (
                <div className="text-center py-20">
                  <div className="p-10 rounded-3xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 mb-10 shadow-2xl shadow-cyan-500/30 inline-flex">
                    <Wallet className="h-28 w-28 text-white" strokeWidth={2.5} />
                  </div>
                  <p className="text-4xl font-black text-white mb-4">
                    No hay cuentas registradas
                  </p>
                  <p className="text-2xl text-cyan-300 font-semibold">
                    Comienza creando una empresa o cuenta personal
                  </p>
                </div>
              ) : (
                <div className="space-y-6">
                  {cuentas.slice(0, 5).map((cuenta) => (
                    <div
                      key={cuenta.id}
                      className="group relative overflow-hidden flex items-center justify-between p-8 rounded-2xl bg-gradient-to-br from-slate-900/50 to-slate-800/50 border-2 border-cyan-500/30 hover:border-cyan-500/50 transition-all duration-300 cursor-pointer hover:-translate-y-1 hover:shadow-xl hover:shadow-cyan-500/20 backdrop-blur-sm"
                      onClick={() => router.push(`/cuentas/${cuenta.id}`)}
                    >
                      <div className="absolute top-0 right-0 w-32 h-32 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-0 group-hover:opacity-10 rounded-full -mr-16 -mt-16 transition-opacity duration-300"></div>
                      <div className="flex items-center gap-6 relative z-10">
                        <div className="p-5 rounded-2xl bg-gradient-to-br from-cyan-500 via-blue-500 to-purple-500 shadow-lg shadow-cyan-500/30 group-hover:scale-110 transition-transform duration-300">
                          <Wallet className="h-10 w-10 text-white" strokeWidth={2.5} />
                        </div>
                        <div>
                          <p className="text-2xl font-black text-white mb-1">{cuenta.nombre}</p>
                          <p className="text-lg text-cyan-300 font-semibold">{cuenta.banco} • {cuenta.moneda}</p>
                        </div>
                      </div>
                      <div className="text-right relative z-10">
                        <p className="text-4xl font-black text-cyan-400">
                          {new Intl.NumberFormat('es-MX', {
                            style: 'currency',
                            currency: cuenta.moneda,
                            minimumFractionDigits: 2
                          }).format(cuenta.saldoActual || 0)}
                        </p>
                        <p className="text-lg text-slate-400 font-bold mt-1">
                          {cuenta.empresaId === 'personal' ? '👤 Personal' : '🏢 Empresarial'}
                        </p>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>

      <TransferenciaModal
        open={showTransferenciaModal}
        onClose={() => setShowTransferenciaModal(false)}
        onSuccess={loadData}
      />

      <PaymentAlertModal
        open={showAlertModal}
        onClose={() => setShowAlertModal(false)}
        alerts={paymentAlerts}
      />
    </MainLayout>
  )
}
