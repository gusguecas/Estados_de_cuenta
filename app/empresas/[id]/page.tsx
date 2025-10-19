'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getEmpresa, getCuentas, deleteCuenta } from '@/lib/firestore'
import type { Empresa, CuentaBancaria } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Building2, Plus, Edit, Trash2, ArrowLeft, CreditCard, Wallet } from 'lucide-react'
import { CuentaModal } from '@/components/cuenta-modal'

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
      cheques: { label: 'Cheques', className: 'bg-blue-100 text-blue-800' },
      credito: { label: 'Crédito', className: 'bg-purple-100 text-purple-800' },
      prestamo: { label: 'Préstamo', className: 'bg-orange-100 text-orange-800' },
      ahorro: { label: 'Ahorro', className: 'bg-green-100 text-green-800' }
    }
    const config = variants[tipo] || variants.cheques
    return <Badge className={config.className}>{config.label}</Badge>
  }

  if (authLoading || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
          <p className="mt-4 text-gray-600">Cargando...</p>
        </div>
      </div>
    )
  }

  if (!user || !empresa) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => router.push('/empresas')}
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-gray-900 flex items-center gap-2">
              <Building2 className="h-8 w-8" />
              {empresa.nombre}
            </h1>
            {empresa.nombreComercial && (
              <p className="text-gray-600 mt-1">{empresa.nombreComercial}</p>
            )}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Información General</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {empresa.rfc && (
                <div className="flex justify-between">
                  <span className="text-gray-500">RFC:</span>
                  <span className="font-medium">{empresa.rfc}</span>
                </div>
              )}
              {empresa.giro && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Giro:</span>
                  <span className="font-medium">{empresa.giro}</span>
                </div>
              )}
              {empresa.email && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Email:</span>
                  <span className="font-medium">{empresa.email}</span>
                </div>
              )}
              {empresa.telefono && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Teléfono:</span>
                  <span className="font-medium">{empresa.telefono}</span>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Ubicación</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              {empresa.direccion && (
                <div>
                  <span className="text-gray-500">Dirección:</span>
                  <p className="font-medium">{empresa.direccion}</p>
                </div>
              )}
              {empresa.ciudad && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Ciudad:</span>
                  <span className="font-medium">{empresa.ciudad}</span>
                </div>
              )}
              {empresa.estado && (
                <div className="flex justify-between">
                  <span className="text-gray-500">Estado:</span>
                  <span className="font-medium">{empresa.estado}</span>
                </div>
              )}
              {empresa.codigoPostal && (
                <div className="flex justify-between">
                  <span className="text-gray-500">C.P.:</span>
                  <span className="font-medium">{empresa.codigoPostal}</span>
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Resumen Financiero</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex justify-between">
                <span className="text-gray-500">Total Cuentas:</span>
                <span className="font-bold text-xl">{cuentas.length}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-gray-500">Saldo Total:</span>
                <span className="font-bold text-xl text-green-600">
                  {formatMoney(
                    cuentas.reduce((sum, c) => sum + c.saldoActual, 0),
                    'MXN'
                  )}
                </span>
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Cuentas Bancarias</h2>
          <Button onClick={() => setShowModal(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Nueva Cuenta
          </Button>
        </div>

        {cuentas.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Wallet className="h-16 w-16 text-gray-400 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                No hay cuentas bancarias registradas
              </h3>
              <p className="text-gray-500 mb-6">
                Agrega la primera cuenta bancaria para esta empresa
              </p>
              <Button onClick={() => setShowModal(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Crear Primera Cuenta
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            {cuentas.map((cuenta) => (
              <Card
                key={cuenta.id}
                className="hover:shadow-lg transition-shadow cursor-pointer"
                onClick={() => router.push(`/cuentas/${cuenta.id}`)}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="flex items-center gap-2">
                        <CreditCard className="h-5 w-5" />
                        {cuenta.nombre}
                      </CardTitle>
                      <CardDescription className="mt-1">
                        {cuenta.banco} • {cuenta.numeroCuenta}
                      </CardDescription>
                    </div>
                    {getTipoCuentaBadge(cuenta.tipoCuenta)}
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div>
                      <p className="text-sm text-gray-500">Saldo Actual</p>
                      <p className="text-2xl font-bold text-green-600">
                        {formatMoney(cuenta.saldoActual, cuenta.moneda)}
                      </p>
                    </div>
                    {cuenta.limiteCredito && cuenta.tipoCuenta === 'credito' && (
                      <div className="flex justify-between text-sm">
                        <span className="text-gray-500">Límite:</span>
                        <span className="font-medium">
                          {formatMoney(cuenta.limiteCredito, cuenta.moneda)}
                        </span>
                      </div>
                    )}
                    <div className="flex gap-2 mt-4">
                      <Button
                        variant="outline"
                        size="sm"
                        className="flex-1"
                        onClick={(e) => {
                          e.stopPropagation()
                          setSelectedCuenta(cuenta)
                          setShowModal(true)
                        }}
                      >
                        <Edit className="h-4 w-4 mr-1" />
                        Editar
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleDeleteCuenta(cuenta.id)
                        }}
                      >
                        <Trash2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
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
    </div>
  )
}
