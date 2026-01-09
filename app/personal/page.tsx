'use client'

export const dynamic = 'force-dynamic'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuentas, deleteCuenta, getDocumentosFinancieros, deleteDocumentoFinanciero } from '@/lib/firestore'
import type { CuentaBancaria, DocumentoFinanciero } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Plus, Edit, Trash2, CreditCard, Wallet, DollarSign, User, Calendar, FileText, Download, Eye } from 'lucide-react'
import { CuentaModal } from '@/components/cuenta-modal'
import { DocumentoFinancieroModal } from '@/components/documento-financiero-modal'
import { MainLayout } from '@/components/main-layout'
import Image from 'next/image'

export default function PersonalPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selectedCuenta, setSelectedCuenta] = useState<CuentaBancaria | null>(null)
  const [documentos, setDocumentos] = useState<DocumentoFinanciero[]>([])
  const [showDocumentoModal, setShowDocumentoModal] = useState(false)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadCuentas = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const data = await getCuentas(user.uid, 'personal')
      setCuentas(data)
    } catch (error) {
      console.error('Error al cargar cuentas:', error)
    } finally {
      setLoading(false)
    }
  }, [user])

  const loadDocumentos = useCallback(async () => {
    if (!user) return

    try {
      const data = await getDocumentosFinancieros(user.uid)
      setDocumentos(data)
    } catch (error) {
      console.error('Error al cargar documentos:', error)
    }
  }, [user])

  useEffect(() => {
    if (user) {
      loadCuentas()
      loadDocumentos()
    }
  }, [user, loadCuentas, loadDocumentos])

  const handleDeleteCuenta = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar esta cuenta?')) return

    try {
      await deleteCuenta(id)
      await loadCuentas()
    } catch (error) {
      console.error('Error al eliminar cuenta:', error)
    }
  }

  const handleDeleteDocumento = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar este documento?')) return

    try {
      await deleteDocumentoFinanciero(id)
      await loadDocumentos()
    } catch (error) {
      console.error('Error al eliminar documento:', error)
    }
  }

  const getTipoDocumentoLabel = (tipo: string) => {
    const tipos: Record<string, string> = {
      buro_credito: 'Buró de Crédito',
      declaracion_anual: 'Declaración Anual',
      declaracion_mensual: 'Declaración Mensual',
      constancia_fiscal: 'Constancia Fiscal',
      otro: 'Otro'
    }
    return tipos[tipo] || tipo
  }

  const getTipoDocumentoBadge = (tipo: string) => {
    const variants: Record<string, string> = {
      buro_credito: 'bg-amber-500/20 text-amber-300 border-amber-500/50',
      declaracion_anual: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/50',
      declaracion_mensual: 'bg-cyan-500/20 text-cyan-300 border-cyan-500/50',
      constancia_fiscal: 'bg-purple-500/20 text-purple-300 border-purple-500/50',
      otro: 'bg-slate-500/20 text-slate-300 border-slate-500/50'
    }
    return variants[tipo] || variants.otro
  }

  const formatFileSize = (bytes: number) => {
    if (bytes < 1024) return bytes + ' B'
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB'
    return (bytes / 1024 / 1024).toFixed(2) + ' MB'
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
          <div className="animate-spin rounded-full h-24 w-24 border-4 border-emerald-500 border-t-transparent mx-auto"></div>
          <p className="mt-8 text-3xl font-black text-white">Cargando finanzas personales...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  // Agrupar cuentas por moneda
  const saldosPorMoneda = cuentas.reduce((acc, cuenta) => {
    const moneda = cuenta.moneda
    if (!acc[moneda]) {
      acc[moneda] = { total: 0, cuentas: 0 }
    }
    acc[moneda].total += cuenta.saldoActual || 0
    acc[moneda].cuentas += 1
    return acc
  }, {} as Record<string, { total: number; cuentas: number }>)

  // Calcular pagos por tarjeta de crédito
  const hoy = new Date()
  const diaActual = hoy.getDate()
  const mesActual = hoy.getMonth()
  const añoActual = hoy.getFullYear()

  const pagosPorTarjeta = cuentas
    .filter(c => c.tipoCuenta === 'credito' && c.diaLimitePago)
    .map(cuenta => {
      const diaLimite = cuenta.diaLimitePago!
      let fechaLimite = new Date(añoActual, mesActual, diaLimite)

      if (diaLimite < diaActual) {
        fechaLimite = new Date(añoActual, mesActual + 1, diaLimite)
      }

      const diasHasta = Math.ceil((fechaLimite.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

      return {
        fecha: diasHasta === 0 ? 'Hoy' : diasHasta === 1 ? 'Mañana' : `${diasHasta} días`,
        cuenta: cuenta.nombre,
        diasNumerico: diasHasta,
        monto: cuenta.limiteCredito ? cuenta.limiteCredito - cuenta.saldoActual : Math.abs(cuenta.saldoActual),
        moneda: cuenta.moneda
      }
    })
    .sort((a, b) => a.diasNumerico - b.diasNumerico)

  return (
    <MainLayout>
      <div className="space-y-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-fuchsia-400 flex items-center gap-5">
              <div className="p-5 rounded-2xl bg-gradient-to-br from-purple-500 via-pink-500 to-fuchsia-500 shadow-2xl shadow-purple-500/30">
                <User className="h-14 w-14 text-white" strokeWidth={2.5} />
              </div>
              Finanzas Personales
            </h1>
            <p className="text-2xl text-purple-300 mt-3 font-semibold">
              Gestiona y administra tus cuentas personales
            </p>
          </div>
          <Button
            onClick={() => setShowModal(true)}
            className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-purple-600 via-pink-600 to-fuchsia-600 hover:from-purple-700 hover:via-pink-700 hover:to-fuchsia-700 text-white shadow-2xl shadow-purple-500/30 hover:shadow-purple-500/50 transition-all"
          >
            <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
            Nueva Cuenta
          </Button>
        </div>

        {/* KPIs Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
          {/* Total Cuentas */}
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-purple-500/30 shadow-2xl backdrop-blur-sm lg:col-span-1">
            <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-purple-500 to-pink-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
            <CardContent className="p-8">
              <div className="bg-purple-500/10 border-2 border-purple-500/30 rounded-xl p-5">
                <div className="flex items-center gap-4 mb-3">
                  <Wallet className="h-9 w-9 text-purple-400" strokeWidth={2.5} />
                  <span className="text-2xl text-purple-300 font-bold">Total Cuentas</span>
                </div>
                <p className="text-5xl font-black text-white ml-12">{cuentas.length}</p>
              </div>
            </CardContent>
          </Card>

          {/* Saldos por Moneda */}
          {Object.entries(saldosPorMoneda).slice(0, 1).map(([moneda, datos]) => {
            const monedaSymbol = moneda === 'MXN' ? '🇲🇽' : moneda === 'USD' ? '🇺🇸' : '🇪🇺'
            return (
              <Card key={moneda} className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl backdrop-blur-sm lg:col-span-1">
                <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                <CardContent className="p-8">
                  <div className="bg-cyan-500/10 border-2 border-cyan-500/30 rounded-xl p-5">
                    <div className="flex items-center gap-4 mb-4">
                      <DollarSign className="h-9 w-9 text-cyan-400" strokeWidth={2.5} />
                      <span className="text-2xl text-cyan-300 font-bold">Saldo {monedaSymbol}</span>
                    </div>
                    <div className="ml-12">
                      <span className="text-4xl font-black text-white">
                        {new Intl.NumberFormat('es-MX', {
                          style: 'currency',
                          currency: moneda,
                          minimumFractionDigits: 2
                        }).format(datos.total)}
                      </span>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )
          })}

          {/* Pagos de Tarjetas de Crédito */}
          {pagosPorTarjeta.length > 0 && (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-emerald-500/30 shadow-2xl backdrop-blur-sm lg:col-span-2">
              <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-emerald-500 to-green-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
              <CardContent className="p-8">
                <div className="bg-emerald-500/10 border-2 border-emerald-500/30 rounded-xl p-5">
                  <div className="flex items-center gap-4 mb-4">
                    <Calendar className="h-7 w-7 text-emerald-400" strokeWidth={2.5} />
                    <span className="text-xl text-emerald-300 font-bold">Próximos Pagos</span>
                  </div>
                  <div className="ml-12 space-y-3">
                    {pagosPorTarjeta.map((pago, index) => (
                      <div key={index} className="border-b border-emerald-500/20 last:border-0 pb-3 last:pb-0">
                        <div className="flex items-center justify-between gap-4">
                          <p className="text-lg text-white font-black flex-1">{pago.cuenta}</p>
                          <p className="text-xl font-black text-emerald-300">{pago.fecha}</p>
                          <p className="text-lg text-emerald-300 font-black text-right">
                            {formatMoney(pago.monto, pago.moneda)}
                          </p>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </div>

        {/* Cuentas Section */}
        {cuentas.length === 0 ? (
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-purple-500/30 shadow-2xl backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-purple-500 to-pink-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
            <CardContent className="flex flex-col items-center justify-center py-28">
              <div className="p-10 rounded-3xl bg-gradient-to-br from-purple-500 via-pink-500 to-fuchsia-500 mb-10 shadow-2xl shadow-purple-500/30">
                <Wallet className="h-28 w-28 text-white" strokeWidth={2.5} />
              </div>
              <h3 className="text-5xl font-black text-white mb-5">
                No hay cuentas personales registradas
              </h3>
              <p className="text-2xl text-purple-300 mb-12 font-semibold">
                Comienza creando tu primera cuenta personal
              </p>
              <Button
                onClick={() => setShowModal(true)}
                className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-purple-600 via-pink-600 to-fuchsia-600 hover:from-purple-700 hover:via-pink-700 hover:to-fuchsia-700 text-white shadow-2xl shadow-purple-500/30"
              >
                <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
                Crear Primera Cuenta
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-10">
            {/* Cuentas de Cheques y Ahorro */}
            {cuentas.filter(c => c.tipoCuenta === 'cheques' || c.tipoCuenta === 'ahorro').length > 0 && (
              <div>
                <h2 className="text-4xl font-black text-white mb-6 flex items-center gap-3">
                  <Wallet className="h-10 w-10 text-blue-400" strokeWidth={2.5} />
                  Cuentas de Cheques y Ahorro
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                  {cuentas.filter(c => c.tipoCuenta === 'cheques' || c.tipoCuenta === 'ahorro').map((cuenta) => (
                    <Card
                      key={cuenta.id}
                      className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                      onClick={() => router.push(`/cuentas/${cuenta.id}`)}
                    >
                      <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                      <CardHeader className="pb-6">
                        <div className="flex flex-col items-center gap-4 mb-4">
                          <div className="relative w-32 h-32 flex items-center justify-center">
                            {cuenta.logo ? (
                              <Image
                                src={cuenta.logo}
                                alt={cuenta.banco}
                                fill
                                className="object-contain scale-[2.24]"
                              />
                            ) : (
                              <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-2xl shadow-cyan-500/30">
                                <CreditCard className="h-16 w-16 text-white" strokeWidth={2.5} />
                              </div>
                            )}
                          </div>
                          <div className="flex items-center gap-3">
                            <span className="text-5xl">
                              {cuenta.moneda === 'MXN' ? '🇲🇽' : cuenta.moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                            </span>
                            {getTipoCuentaBadge(cuenta.tipoCuenta)}
                          </div>
                        </div>
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1 text-center">
                            <CardTitle className="text-3xl font-black text-white mb-3">
                              {cuenta.nombre}
                            </CardTitle>
                            <CardDescription className="text-xl text-cyan-300 font-semibold">
                              {cuenta.banco} • {cuenta.numeroCuenta}
                            </CardDescription>
                          </div>
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
              </div>
            )}

            {/* Tarjetas de Crédito */}
            {cuentas.filter(c => c.tipoCuenta === 'credito').length > 0 && (
              <div>
                <h2 className="text-4xl font-black text-white mb-6 flex items-center gap-3">
                  <CreditCard className="h-10 w-10 text-purple-400" strokeWidth={2.5} />
                  Tarjetas de Crédito
                </h2>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8">
                  {cuentas.filter(c => c.tipoCuenta === 'credito').map((cuenta) => (
              <Card
                key={cuenta.id}
                className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                onClick={() => router.push(`/cuentas/${cuenta.id}`)}
              >
                <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                <CardHeader className="pb-6 pt-8">
                  <div className="flex flex-col items-center gap-4 mb-4">
                    <div className="relative w-28 h-28 flex items-center justify-center">
                      {cuenta.logo ? (
                        <Image
                          src={cuenta.logo}
                          alt={cuenta.banco}
                          fill
                          className="object-contain scale-[2.0]"
                        />
                      ) : (
                        <div className="p-3 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-500 shadow-2xl shadow-cyan-500/30">
                          <CreditCard className="h-14 w-14 text-white" strokeWidth={2.5} />
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="text-5xl">
                        {cuenta.moneda === 'MXN' ? '🇲🇽' : cuenta.moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                      </span>
                      {getTipoCuentaBadge(cuenta.tipoCuenta)}
                    </div>
                  </div>
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 text-center">
                      <CardTitle className="text-3xl font-black text-white mb-3">
                        {cuenta.nombre}
                      </CardTitle>
                      <CardDescription className="text-xl text-cyan-300 font-semibold">
                        {cuenta.banco} • {cuenta.numeroCuenta}
                      </CardDescription>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pb-8">
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
              </div>
            )}
          </div>
        )}

        {/* Documentos Financieros */}
        <div>
          <div className="flex items-center justify-between mb-6">
            <h2 className="text-4xl font-black text-white flex items-center gap-3">
              <FileText className="h-10 w-10 text-amber-400" strokeWidth={2.5} />
              Documentos Financieros
            </h2>
            <Button
              onClick={() => setShowDocumentoModal(true)}
              className="h-16 px-8 text-xl font-black bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-700 hover:via-orange-700 hover:to-red-700 text-white shadow-2xl shadow-amber-500/30 hover:shadow-amber-500/50 transition-all"
            >
              <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
              Subir Documento
            </Button>
          </div>

          {documentos.length === 0 ? (
            <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-amber-500/30 shadow-2xl backdrop-blur-sm">
              <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-amber-500 to-orange-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
              <CardContent className="flex flex-col items-center justify-center py-20">
                <div className="p-8 rounded-3xl bg-gradient-to-br from-amber-500 via-orange-500 to-red-500 mb-8 shadow-2xl shadow-amber-500/30">
                  <FileText className="h-20 w-20 text-white" strokeWidth={2.5} />
                </div>
                <h3 className="text-4xl font-black text-white mb-4">
                  No hay documentos financieros
                </h3>
                <p className="text-xl text-amber-300 mb-10 font-semibold">
                  Sube tu buró de crédito, declaraciones fiscales y más
                </p>
                <Button
                  onClick={() => setShowDocumentoModal(true)}
                  className="h-16 px-10 text-xl font-black bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-700 hover:via-orange-700 hover:to-red-700 text-white shadow-2xl shadow-amber-500/30"
                >
                  <Plus className="mr-3 h-7 w-7" strokeWidth={2.5} />
                  Subir Primer Documento
                </Button>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {documentos.map((documento) => (
                <Card
                  key={documento.id}
                  className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-amber-500/30 shadow-2xl hover:shadow-amber-500/20 transition-all duration-300 hover:-translate-y-2 hover:border-amber-500/50 backdrop-blur-sm"
                >
                  <div className="absolute top-0 right-0 w-40 h-40 bg-gradient-to-br from-amber-500 to-orange-500 opacity-10 rounded-full -mr-20 -mt-20"></div>
                  <CardHeader className="pb-4">
                    <div className="flex items-start justify-between gap-3">
                      <div className="p-3 rounded-xl bg-gradient-to-br from-amber-500 via-orange-500 to-red-500 shadow-lg shadow-amber-500/30">
                        <FileText className="h-8 w-8 text-white" strokeWidth={2.5} />
                      </div>
                      <Badge className={`${getTipoDocumentoBadge(documento.tipoDocumento)} text-sm font-bold px-3 py-1`}>
                        {getTipoDocumentoLabel(documento.tipoDocumento)}
                      </Badge>
                    </div>
                    <CardTitle className="text-2xl font-black text-white mt-4">
                      {documento.nombre}
                    </CardTitle>
                    {documento.descripcion && (
                      <CardDescription className="text-base text-amber-300 font-semibold">
                        {documento.descripcion}
                      </CardDescription>
                    )}
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex flex-wrap gap-2 text-sm">
                        {documento.año && (
                          <span className="px-3 py-1 bg-slate-800/50 rounded-lg text-slate-300 font-semibold">
                            Año: {documento.año}
                          </span>
                        )}
                        {documento.mes && (
                          <span className="px-3 py-1 bg-slate-800/50 rounded-lg text-slate-300 font-semibold">
                            Mes: {documento.mes}
                          </span>
                        )}
                      </div>
                      <div className="text-sm text-slate-400">
                        <p className="font-semibold truncate" title={documento.nombreArchivo}>
                          {documento.nombreArchivo}
                        </p>
                        <p>{formatFileSize(documento.tamanioArchivo)}</p>
                      </div>
                      <div className="flex gap-2 pt-3">
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex-1 h-12 text-base font-bold bg-amber-500/10 border-2 border-amber-500/50 text-amber-300 hover:bg-amber-500/20 hover:border-amber-400 hover:text-white"
                          onClick={() => window.open(documento.archivoUrl, '_blank')}
                        >
                          <Eye className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Ver
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="flex-1 h-12 text-base font-bold bg-emerald-500/10 border-2 border-emerald-500/50 text-emerald-300 hover:bg-emerald-500/20 hover:border-emerald-400 hover:text-white"
                          onClick={() => {
                            const link = document.createElement('a')
                            link.href = documento.archivoUrl
                            link.download = documento.nombreArchivo
                            link.click()
                          }}
                        >
                          <Download className="h-5 w-5 mr-2" strokeWidth={2.5} />
                          Descargar
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          className="h-12 px-4 text-base font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                          onClick={() => handleDeleteDocumento(documento.id)}
                        >
                          <Trash2 className="h-5 w-5" strokeWidth={2.5} />
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
        empresaId="personal"
        onSuccess={loadCuentas}
      />

      <DocumentoFinancieroModal
        open={showDocumentoModal}
        onClose={() => setShowDocumentoModal(false)}
        onSuccess={loadDocumentos}
      />
    </MainLayout>
  )
}
