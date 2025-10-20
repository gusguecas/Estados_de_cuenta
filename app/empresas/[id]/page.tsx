'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getEmpresa, getCuentas, deleteCuenta } from '@/lib/firestore'
import type { Empresa, CuentaBancaria } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Building2, Plus, Edit, Trash2, CreditCard, Wallet, DollarSign, MapPin, Mail, Phone, Briefcase } from 'lucide-react'
import { CuentaModal } from '@/components/cuenta-modal'
import { MainLayout } from '@/components/main-layout'
import Image from 'next/image'

interface PageProps {
  params: Promise<{ id: string }>
}

export default function EmpresaDetailPage({ params }: PageProps) {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [empresa, setEmpresa] = useState<Empresa | null>(null)
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [loading, setLoading] = useState(true)
  const [empresaId, setEmpresaId] = useState<string>('')
  const [showModal, setShowModal] = useState(false)
  const [selectedCuenta, setSelectedCuenta] = useState<CuentaBancaria | null>(null)

  useEffect(() => {
    params.then((p) => setEmpresaId(p.id))
  }, [params])

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadData = useCallback(async () => {
    if (!user || !empresaId) return

    try {
      setLoading(true)
      const [empresaData, cuentasData] = await Promise.all([
        getEmpresa(empresaId),
        getCuentas(user.uid, empresaId)
      ])
      setEmpresa(empresaData)
      setCuentas(cuentasData)
    } catch (error) {
      console.error('Error al cargar datos:', error)
    } finally {
      setLoading(false)
    }
  }, [user, empresaId])

  useEffect(() => {
    if (user && empresaId) {
      loadData()
    }
  }, [user, empresaId, loadData])

  const handleDeleteCuenta = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar esta cuenta?')) return

    try {
      await deleteCuenta(id)
      await loadData()
    } catch (error) {
      console.error('Error al eliminar cuenta:', error)
    }
  }

  const formatMoney = (amount: number, moneda: string) => {
    const formatter = new Intl.NumberFormat('es-MX', {
      style: 'currency',
      currency: moneda
    })
    return formatter.format(amount)
  }

  const getTipoCuentaBadge = (tipo: string) => {
    const variants: Record<string, { label: string; className: string }> = {
      cheques: { label: 'Cheques', className: 'bg-blue-500/20 text-blue-300 border-blue-500/50 text-lg font-bold px-4 py-2' },
      credito: { label: 'Crédito', className: 'bg-purple-500/20 text-purple-300 border-purple-500/50 text-lg font-bold px-4 py-2' },
      prestamo: { label: 'Préstamo', className: 'bg-orange-500/20 text-orange-300 border-orange-500/50 text-lg font-bold px-4 py-2' },
      ahorro: { label: 'Ahorro', className: 'bg-green-500/20 text-green-300 border-green-500/50 text-lg font-bold px-4 py-2' }
    }
    const config = variants[tipo] || variants.cheques
    return <Badge className={config.className}>{config.label}</Badge>
  }

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-20 w-20 border-4 border-emerald-500 border-t-transparent mx-auto"></div>
          <p className="mt-6 text-2xl font-bold text-white">Cargando empresa...</p>
        </div>
      </div>
    )
  }

  if (!user || !empresa) {
    return null
  }

  // Group accounts by currency
  const saldosPorMoneda = cuentas.reduce((acc, cuenta) => {
    const moneda = cuenta.moneda
    if (!acc[moneda]) {
      acc[moneda] = {
        total: 0,
        cuentas: 0,
        cheques: 0,
        credito: 0,
        prestamo: 0,
        ahorro: 0
      }
    }
    acc[moneda].total += cuenta.saldoActual || 0
    acc[moneda].cuentas += 1

    if (cuenta.tipoCuenta === 'cheques') acc[moneda].cheques += 1
    else if (cuenta.tipoCuenta === 'credito') acc[moneda].credito += 1
    else if (cuenta.tipoCuenta === 'prestamo') acc[moneda].prestamo += 1
    else if (cuenta.tipoCuenta === 'ahorro') acc[moneda].ahorro += 1

    return acc
  }, {} as Record<string, { total: number; cuentas: number; cheques: number; credito: number; prestamo: number; ahorro: number }>)

  return (
    <MainLayout>
      <div className="space-y-10">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-6">
            <div className="relative w-32 h-32 rounded-2xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 flex items-center justify-center overflow-hidden shadow-2xl shadow-emerald-500/30">
              {empresa.logo ? (
                <Image
                  src={empresa.logo}
                  alt={empresa.nombre}
                  fill
                  className="object-contain p-4"
                />
              ) : (
                <Building2 className="h-16 w-16 text-white" strokeWidth={2.5} />
              )}
            </div>
            <div>
              <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-blue-400">
                {empresa.nombre}
              </h1>
              {empresa.nombreComercial && (
                <p className="text-2xl text-emerald-300 mt-2 font-semibold">{empresa.nombreComercial}</p>
              )}
              <div className="flex items-center gap-3 mt-3">
                <Badge className="text-xl px-5 py-2 bg-gradient-to-r from-emerald-500 to-cyan-500 text-white font-bold">
                  {empresa.moneda === 'MXN' ? '🇲🇽 MXN' : empresa.moneda === 'USD' ? '🇺🇸 USD' : '🇪🇺 EUR'}
                </Badge>
                <Badge className={`text-xl px-5 py-2 font-bold ${empresa.activo ? 'bg-green-500/20 text-green-300 border-green-500/50' : 'bg-red-500/20 text-red-300 border-red-500/50'}`}>
                  {empresa.activo ? 'Activa' : 'Inactiva'}
                </Badge>
              </div>
            </div>
          </div>
        </div>

        {/* Info Cards */}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <Card className="relative overflow-hidden bg-gradient-to-br from-blue-950/50 to-cyan-950/50 border-cyan-500/30 shadow-2xl shadow-cyan-500/20 backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
            <CardHeader className="pb-6">
              <CardTitle className="text-3xl font-black text-white flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-lg shadow-cyan-500/30">
                  <Briefcase className="h-8 w-8 text-white" strokeWidth={2.5} />
                </div>
                Información General
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {empresa.rfc && (
                <div className="flex items-center justify-between py-2 border-b border-cyan-500/20">
                  <span className="text-xl text-cyan-300 font-bold">
                    {empresa.moneda === 'MXN' ? 'RFC:' : empresa.moneda === 'EUR' ? 'NIF/CIF/NIE:' : 'EIN/Tax ID:'}
                  </span>
                  <span className="text-xl font-black text-white">{empresa.rfc}</span>
                </div>
              )}
              {empresa.giro && (
                <div className="flex items-center justify-between py-2 border-b border-cyan-500/20">
                  <span className="text-xl text-cyan-300 font-bold">Giro:</span>
                  <span className="text-xl font-black text-white">{empresa.giro}</span>
                </div>
              )}
              {empresa.email && (
                <div className="flex items-center gap-3 py-2">
                  <Mail className="h-6 w-6 text-cyan-400" />
                  <span className="text-lg font-bold text-white">{empresa.email}</span>
                </div>
              )}
              {empresa.telefono && (
                <div className="flex items-center gap-3 py-2">
                  <Phone className="h-6 w-6 text-cyan-400" />
                  <span className="text-lg font-bold text-white">{empresa.telefono}</span>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="relative overflow-hidden bg-gradient-to-br from-purple-950/50 to-pink-950/50 border-purple-500/30 shadow-2xl shadow-purple-500/20 backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-purple-500 to-pink-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
            <CardHeader className="pb-6">
              <CardTitle className="text-3xl font-black text-white flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-purple-500 to-pink-500 shadow-lg shadow-purple-500/30">
                  <MapPin className="h-8 w-8 text-white" strokeWidth={2.5} />
                </div>
                Ubicación
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {empresa.direccion && (
                <div className="py-2 border-b border-purple-500/20">
                  <span className="text-lg text-purple-300 font-bold uppercase">Dirección:</span>
                  <p className="text-xl font-black text-white mt-2">{empresa.direccion}</p>
                </div>
              )}
              {empresa.ciudad && (
                <div className="flex items-center justify-between py-2 border-b border-purple-500/20">
                  <span className="text-xl text-purple-300 font-bold">Ciudad:</span>
                  <span className="text-xl font-black text-white">{empresa.ciudad}</span>
                </div>
              )}
              {empresa.estado && (
                <div className="flex items-center justify-between py-2 border-b border-purple-500/20">
                  <span className="text-xl text-purple-300 font-bold">
                    {empresa.moneda === 'MXN' ? 'Estado:' : empresa.moneda === 'EUR' ? 'Provincia:' : 'State:'}
                  </span>
                  <span className="text-xl font-black text-white">{empresa.estado}</span>
                </div>
              )}
              {empresa.codigoPostal && (
                <div className="flex items-center justify-between py-2">
                  <span className="text-xl text-purple-300 font-bold">
                    {empresa.moneda === 'USD' ? 'ZIP Code:' : 'C.P.:'}
                  </span>
                  <span className="text-xl font-black text-white">{empresa.codigoPostal}</span>
                </div>
              )}
            </CardContent>
          </Card>

          <Card className="relative overflow-hidden bg-gradient-to-br from-emerald-950/50 to-green-950/50 border-emerald-500/30 shadow-2xl shadow-emerald-500/20 backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-emerald-500 to-green-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
            <CardHeader className="pb-6">
              <CardTitle className="text-3xl font-black text-white flex items-center gap-4">
                <div className="p-3 rounded-xl bg-gradient-to-br from-emerald-500 to-green-500 shadow-lg shadow-emerald-500/30">
                  <Wallet className="h-8 w-8 text-white" strokeWidth={2.5} />
                </div>
                Resumen Financiero
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5">
              <div>
                <p className="text-xl font-bold text-emerald-300 uppercase tracking-wide mb-2">Total Cuentas</p>
                <p className="text-5xl font-black text-white">{cuentas.length}</p>
              </div>
              <div>
                <p className="text-xl font-bold text-emerald-300 uppercase tracking-wide mb-2">Monedas Activas</p>
                <p className="text-4xl font-black text-emerald-400">
                  {Object.keys(saldosPorMoneda).length || 0}
                </p>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* KPIs por Moneda */}
        {Object.keys(saldosPorMoneda).length > 0 && (
          <div>
            <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400 mb-8">
              Saldos por Moneda
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
              {Object.entries(saldosPorMoneda).map(([moneda, datos]) => {
                const monedaSymbol = moneda === 'MXN' ? '🇲🇽 MXN' : moneda === 'USD' ? '🇺🇸 USD' : '🇪🇺 EUR'
                const monedaColor = moneda === 'MXN'
                  ? 'from-green-500 via-emerald-500 to-teal-500'
                  : moneda === 'USD'
                    ? 'from-blue-500 via-cyan-500 to-sky-500'
                    : 'from-purple-500 via-violet-500 to-indigo-500'
                const textColor = moneda === 'MXN'
                  ? 'text-emerald-400'
                  : moneda === 'USD'
                    ? 'text-cyan-400'
                    : 'text-purple-400'
                const borderColor = moneda === 'MXN'
                  ? 'border-emerald-500/30'
                  : moneda === 'USD'
                    ? 'border-cyan-500/30'
                    : 'border-purple-500/30'
                const bgColor = moneda === 'MXN'
                  ? 'from-emerald-950/50 to-green-950/50'
                  : moneda === 'USD'
                    ? 'from-blue-950/50 to-cyan-950/50'
                    : 'from-purple-950/50 to-indigo-950/50'

                return (
                  <Card key={moneda} className={`relative overflow-hidden bg-gradient-to-br ${bgColor} ${borderColor} shadow-2xl backdrop-blur-sm`}>
                    <div className={`absolute top-0 right-0 w-48 h-48 bg-gradient-to-br ${monedaColor} opacity-10 rounded-full -mr-24 -mt-24`}></div>
                    <CardHeader className="pb-4">
                      <CardTitle className={`text-3xl font-black ${textColor}`}>
                        {monedaSymbol}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-5">
                      <div>
                        <p className="text-lg font-bold text-white/70 uppercase mb-2">Saldo Total</p>
                        <p className={`text-5xl font-black ${textColor}`}>
                          {new Intl.NumberFormat('es-MX', {
                            style: 'currency',
                            currency: moneda,
                            minimumFractionDigits: 2
                          }).format(datos.total)}
                        </p>
                      </div>
                      <div className="grid grid-cols-2 gap-4 pt-4 border-t border-white/10">
                        <div>
                          <p className="text-base font-bold text-white/60 mb-1">Cuentas</p>
                          <p className="text-3xl font-black text-white">{datos.cuentas}</p>
                        </div>
                        <div>
                          <p className="text-base font-bold text-white/60 mb-1">Cheques</p>
                          <p className="text-3xl font-black text-white">{datos.cheques}</p>
                        </div>
                        <div>
                          <p className="text-base font-bold text-white/60 mb-1">Crédito</p>
                          <p className="text-3xl font-black text-white">{datos.credito}</p>
                        </div>
                        <div>
                          <p className="text-base font-bold text-white/60 mb-1">Ahorro</p>
                          <p className="text-3xl font-black text-white">{datos.ahorro}</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </div>
        )}

        {/* Cuentas Section */}
        <div>
          <div className="flex items-center justify-between mb-8">
            <h2 className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">
              Cuentas Bancarias
            </h2>
            <Button
              onClick={() => setShowModal(true)}
              size="lg"
              className="h-16 px-10 text-xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-700 hover:via-green-700 hover:to-teal-700 text-white shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all"
            >
              <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
              Nueva Cuenta
            </Button>
          </div>

          {cuentas.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-emerald-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-emerald-500 to-cyan-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-24">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 mb-8 shadow-2xl shadow-emerald-500/30">
                  <Wallet className="h-24 w-24 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  No hay cuentas bancarias registradas
                </h3>
                <p className="text-2xl text-emerald-300 mb-10 font-semibold">
                  Agrega la primera cuenta bancaria para esta empresa
                </p>
                <Button
                  onClick={() => setShowModal(true)}
                  size="lg"
                  className="h-16 px-10 text-xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-700 hover:via-green-700 hover:to-teal-700 text-white shadow-2xl shadow-emerald-500/30"
                >
                  <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
                  Crear Primera Cuenta
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-8">
              {cuentas.map((cuenta) => (
                <Card
                  key={cuenta.id}
                  className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                  onClick={() => router.push(`/cuentas/${cuenta.id}`)}
                >
                  <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                  <CardHeader className="pb-6">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1">
                        <CardTitle className="flex items-center gap-4 text-3xl font-black text-white mb-3">
                          <div className="p-3 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-lg shadow-cyan-500/30">
                            <CreditCard className="h-8 w-8 text-white" strokeWidth={2.5} />
                          </div>
                          {cuenta.nombre}
                        </CardTitle>
                        <CardDescription className="text-xl text-cyan-300 ml-16 font-semibold">
                          {cuenta.banco} • {cuenta.numeroCuenta}
                        </CardDescription>
                      </div>
                      {getTipoCuentaBadge(cuenta.tipoCuenta)}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-6">
                      <div>
                        <p className="text-xl font-bold text-cyan-300 uppercase tracking-wide mb-2">Saldo Actual</p>
                        <p className="text-5xl font-black text-emerald-400">
                          {formatMoney(cuenta.saldoActual, cuenta.moneda)}
                        </p>
                      </div>
                      {cuenta.limiteCredito && cuenta.tipoCuenta === 'credito' && (
                        <div className="flex justify-between text-lg pt-3 border-t border-cyan-500/20">
                          <span className="text-cyan-300 font-bold">Límite de Crédito:</span>
                          <span className="font-black text-white">
                            {formatMoney(cuenta.limiteCredito, cuenta.moneda)}
                          </span>
                        </div>
                      )}
                      <div className="flex gap-3 pt-4">
                        <Button
                          variant="outline"
                          size="lg"
                          className="flex-1 h-14 text-lg font-bold bg-blue-500/10 border-2 border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white"
                          onClick={(e) => {
                            e.stopPropagation()
                            setSelectedCuenta(cuenta)
                            setShowModal(true)
                          }}
                        >
                          <Edit className="h-6 w-6 mr-2" strokeWidth={2.5} />
                          Editar
                        </Button>
                        <Button
                          variant="outline"
                          size="lg"
                          className="h-14 px-6 text-lg font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                          onClick={(e) => {
                            e.stopPropagation()
                            handleDeleteCuenta(cuenta.id)
                          }}
                        >
                          <Trash2 className="h-6 w-6" strokeWidth={2.5} />
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
            </div>
          )}
        </div>
      </div>

      <CuentaModal
        open={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedCuenta(null)
        }}
        cuenta={selectedCuenta}
        empresaId={empresaId}
        onSuccess={loadData}
      />
    </MainLayout>
  )
}
