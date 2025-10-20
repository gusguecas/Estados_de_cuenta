'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getEmpresas, deleteEmpresa, getCuentas } from '@/lib/firestore'
import type { Empresa, CuentaBancaria } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Building2, Plus, Edit, Trash2, Wallet, DollarSign, CreditCard, Calendar } from 'lucide-react'
import { EmpresaModal } from '@/components/empresa-modal'
import { MainLayout } from '@/components/main-layout'
import Image from 'next/image'

interface EmpresaWithKPIs extends Empresa {
  cuentas: CuentaBancaria[]
  totalCuentas: number
  saldosPorMoneda: Record<string, number>
  proximoPago?: { fecha: string; cuenta: string }
}

export default function EmpresasPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [empresas, setEmpresas] = useState<EmpresaWithKPIs[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [selectedEmpresa, setSelectedEmpresa] = useState<Empresa | null>(null)

  useEffect(() => {
    if (!authLoading && !user) {
      router.push('/auth/login')
    }
  }, [user, authLoading, router])

  const loadEmpresas = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const empresasData = await getEmpresas(user.uid)

      // Cargar cuentas y calcular KPIs para cada empresa
      const empresasWithKPIs: EmpresaWithKPIs[] = await Promise.all(
        empresasData.map(async (empresa) => {
          const cuentas = await getCuentas(user.uid, empresa.id)

          // Calcular saldos por moneda
          const saldosPorMoneda = cuentas.reduce((acc, cuenta) => {
            if (!acc[cuenta.moneda]) {
              acc[cuenta.moneda] = 0
            }
            acc[cuenta.moneda] += cuenta.saldoActual || 0
            return acc
          }, {} as Record<string, number>)

          // Encontrar próximo pago urgente (tarjetas de crédito)
          const hoy = new Date()
          const diaActual = hoy.getDate()
          const mesActual = hoy.getMonth()
          const añoActual = hoy.getFullYear()

          let proximoPago: { fecha: string; cuenta: string } | undefined
          let proximoDias = Infinity

          cuentas
            .filter(c => c.tipoCuenta === 'credito' && c.diaLimitePago)
            .forEach(cuenta => {
              const diaLimite = cuenta.diaLimitePago!
              let fechaLimite = new Date(añoActual, mesActual, diaLimite)

              // Si ya pasó este mes, calcular para el próximo mes
              if (diaLimite < diaActual) {
                fechaLimite = new Date(añoActual, mesActual + 1, diaLimite)
              }

              const diasHasta = Math.ceil((fechaLimite.getTime() - hoy.getTime()) / (1000 * 60 * 60 * 24))

              if (diasHasta < proximoDias && diasHasta >= 0) {
                proximoDias = diasHasta
                proximoPago = {
                  fecha: diasHasta === 0 ? 'Hoy' : diasHasta === 1 ? 'Mañana' : `${diasHasta} días`,
                  cuenta: cuenta.nombre
                }
              }
            })

          return {
            ...empresa,
            cuentas,
            totalCuentas: cuentas.length,
            saldosPorMoneda,
            proximoPago
          }
        })
      )

      setEmpresas(empresasWithKPIs)
    } catch (error) {
      console.error('Error al cargar empresas:', error)
    } finally {
      setLoading(false)
    }
  }, [user])

  useEffect(() => {
    if (user) {
      loadEmpresas()
    }
  }, [user, loadEmpresas])

  const handleDelete = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar esta empresa?')) return

    try {
      await deleteEmpresa(id)
      await loadEmpresas()
    } catch (error) {
      console.error('Error al eliminar empresa:', error)
    }
  }

  const handleEdit = (empresa: Empresa) => {
    setSelectedEmpresa(empresa)
    setShowModal(true)
  }

  const handleCreate = () => {
    setSelectedEmpresa(null)
    setShowModal(true)
  }

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center bg-gradient-to-br from-slate-950 via-blue-950 to-slate-900">
        <div className="text-center">
          <div className="animate-spin rounded-full h-24 w-24 border-4 border-emerald-500 border-t-transparent mx-auto"></div>
          <p className="mt-8 text-3xl font-black text-white">Cargando empresas...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  return (
    <MainLayout>
      <div className="space-y-10">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-6xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 via-cyan-400 to-blue-400 flex items-center gap-5">
              <div className="p-5 rounded-2xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 shadow-2xl shadow-emerald-500/30">
                <Building2 className="h-14 w-14 text-white" strokeWidth={2.5} />
              </div>
              Empresas
            </h1>
            <p className="text-2xl text-emerald-300 mt-3 font-semibold">
              Gestiona y administra tus empresas
            </p>
          </div>
          <Button
            onClick={handleCreate}
            className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-700 hover:via-green-700 hover:to-teal-700 text-white shadow-2xl shadow-emerald-500/30 hover:shadow-emerald-500/50 transition-all"
          >
            <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
            Nueva Empresa
          </Button>
        </div>

        {empresas.length === 0 ? (
          <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-emerald-500/30 shadow-2xl backdrop-blur-sm">
            <div className="absolute top-0 right-0 w-64 h-64 bg-gradient-to-br from-emerald-500 to-cyan-500 opacity-5 rounded-full -mr-32 -mt-32"></div>
            <CardContent className="flex flex-col items-center justify-center py-28">
              <div className="p-10 rounded-3xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 mb-10 shadow-2xl shadow-emerald-500/30">
                <Building2 className="h-28 w-28 text-white" strokeWidth={2.5} />
              </div>
              <h3 className="text-5xl font-black text-white mb-5">
                No hay empresas registradas
              </h3>
              <p className="text-2xl text-emerald-300 mb-12 font-semibold">
                Comienza creando tu primera empresa
              </p>
              <Button
                onClick={handleCreate}
                className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-700 hover:via-green-700 hover:to-teal-700 text-white shadow-2xl shadow-emerald-500/30"
              >
                <Plus className="mr-4 h-9 w-9" strokeWidth={2.5} />
                Crear Primera Empresa
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
            {empresas.map((empresa) => (
              <Card
                key={empresa.id}
                className="group relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-cyan-500/30 shadow-2xl hover:shadow-cyan-500/20 transition-all duration-300 cursor-pointer hover:-translate-y-2 hover:border-cyan-500/50 backdrop-blur-sm"
                onClick={() => router.push(`/empresas/${empresa.id}`)}
              >
                <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-cyan-500 to-blue-500 opacity-10 rounded-full -mr-24 -mt-24"></div>
                <CardHeader className="pb-8">
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="flex items-center gap-5 text-4xl font-black text-white">
                        <div className="relative w-22 h-22 rounded-2xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 flex items-center justify-center overflow-hidden shadow-2xl shadow-cyan-500/30">
                          {empresa.logo ? (
                            <Image
                              src={empresa.logo}
                              alt={empresa.nombre}
                              fill
                              className="object-contain p-2"
                            />
                          ) : (
                            <Building2 className="h-12 w-12 text-white" strokeWidth={2.5} />
                          )}
                        </div>
                        {empresa.nombre}
                      </CardTitle>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-7 mb-10">
                    {/* Total de Cuentas */}
                    <div className="bg-emerald-500/10 border-2 border-emerald-500/30 rounded-xl p-5">
                      <div className="flex items-center gap-4 mb-3">
                        <Wallet className="h-9 w-9 text-emerald-400" strokeWidth={2.5} />
                        <span className="text-2xl text-emerald-300 font-bold">Total Cuentas</span>
                      </div>
                      <p className="text-5xl font-black text-white ml-12">{empresa.totalCuentas}</p>
                    </div>

                    {/* Saldos por Moneda */}
                    {Object.keys(empresa.saldosPorMoneda).length > 0 && (
                      <div className="bg-cyan-500/10 border-2 border-cyan-500/30 rounded-xl p-5">
                        <div className="flex items-center gap-4 mb-4">
                          <DollarSign className="h-9 w-9 text-cyan-400" strokeWidth={2.5} />
                          <span className="text-2xl text-cyan-300 font-bold">Saldos</span>
                        </div>
                        <div className="space-y-3 ml-12">
                          {Object.entries(empresa.saldosPorMoneda).map(([moneda, saldo]) => (
                            <div key={moneda} className="flex items-baseline gap-3">
                              <span className="text-lg text-cyan-300 font-semibold">
                                {moneda === 'MXN' ? '🇲🇽' : moneda === 'USD' ? '🇺🇸' : '🇪🇺'}
                              </span>
                              <span className="text-3xl font-black text-white">
                                {new Intl.NumberFormat('es-MX', {
                                  style: 'currency',
                                  currency: moneda,
                                  minimumFractionDigits: 2
                                }).format(saldo)}
                              </span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Próximo Pago */}
                    {empresa.proximoPago && (
                      <div className="bg-orange-500/10 border-2 border-orange-500/30 rounded-xl p-5">
                        <div className="flex items-center gap-4 mb-3">
                          <Calendar className="h-9 w-9 text-orange-400" strokeWidth={2.5} />
                          <span className="text-2xl text-orange-300 font-bold">Próximo Pago</span>
                        </div>
                        <div className="ml-12">
                          <p className="text-4xl font-black text-orange-300">{empresa.proximoPago.fecha}</p>
                          <p className="text-lg text-orange-400 font-semibold mt-2">{empresa.proximoPago.cuenta}</p>
                        </div>
                      </div>
                    )}
                  </div>
                  <div className="flex gap-4">
                    <Button
                      variant="outline"
                      size="lg"
                      className="flex-1 h-18 text-xl font-bold bg-blue-500/10 border-2 border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleEdit(empresa)
                      }}
                    >
                      <Edit className="h-7 w-7 mr-3" strokeWidth={2.5} />
                      Editar
                    </Button>
                    <Button
                      variant="outline"
                      size="lg"
                      className="h-18 px-8 text-xl font-bold bg-red-500/10 border-2 border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleDelete(empresa.id)
                      }}
                    >
                      <Trash2 className="h-7 w-7" strokeWidth={2.5} />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>

      <EmpresaModal
        open={showModal}
        onClose={() => {
          setShowModal(false)
          setSelectedEmpresa(null)
        }}
        empresa={selectedEmpresa}
        onSuccess={loadEmpresas}
      />
    </MainLayout>
  )
}
