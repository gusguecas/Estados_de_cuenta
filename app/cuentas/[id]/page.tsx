'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getCuenta, getMovimientos, deleteMovimiento, getCategorias } from '@/lib/firestore'
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
import { ArrowLeft, Plus, Edit, Trash2, TrendingUp, TrendingDown } from 'lucide-react'
import { MovimientoModal } from '@/components/movimiento-modal'

interface PageProps {
  params: Promise<{ id: string }>
}

export default function CuentaDetailPage({ params }: PageProps) {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [cuenta, setCuenta] = useState<CuentaBancaria | null>(null)
  const [movimientos, setMovimientos] = useState<Movimiento[]>([])
  const [categorias, setCategorias] = useState<Categoria[]>([])
  const [loading, setLoading] = useState(true)
  const [cuentaId, setCuentaId] = useState<string>('')
  const [showModal, setShowModal] = useState(false)
  const [selectedMovimiento, setSelectedMovimiento] = useState<Movimiento | null>(null)

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
      const [cuentaData, movimientosData, categoriasData] = await Promise.all([
        getCuenta(cuentaId),
        getMovimientos(cuentaId),
        getCategorias(user.uid)
      ])
      setCuenta(cuentaData)
      setMovimientos(movimientosData)
      setCategorias(categoriasData)
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
    if (!categoriaId) return '-'
    const categoria = categorias.find(c => c.id === categoriaId)
    return categoria?.nombre || '-'
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

  if (!user || !cuenta) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => router.back()}
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-gray-900">{cuenta.nombre}</h1>
            <p className="text-gray-600 mt-1">{cuenta.banco} • {cuenta.numeroCuenta}</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-8">
          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Saldo Actual</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-3xl font-bold text-green-600">
                {formatMoney(cuenta.saldoActual, cuenta.moneda)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Saldo Inicial</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold text-gray-700">
                {formatMoney(cuenta.saldoInicial, cuenta.moneda)}
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-lg">Movimientos</CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-2xl font-semibold text-gray-700">
                {movimientos.length}
              </p>
            </CardContent>
          </Card>
        </div>

        <div className="flex items-center justify-between mb-6">
          <h2 className="text-2xl font-bold text-gray-900">Movimientos</h2>
          <Button onClick={() => setShowModal(true)}>
            <Plus className="mr-2 h-4 w-4" />
            Nuevo Movimiento
          </Button>
        </div>

        {movimientos.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <TrendingUp className="h-16 w-16 text-gray-400 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                No hay movimientos registrados
              </h3>
              <p className="text-gray-500 mb-6">
                Comienza registrando el primer movimiento de esta cuenta
              </p>
              <Button onClick={() => setShowModal(true)}>
                <Plus className="mr-2 h-4 w-4" />
                Crear Primer Movimiento
              </Button>
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Fecha</TableHead>
                    <TableHead>Descripción</TableHead>
                    <TableHead>Categoría</TableHead>
                    <TableHead>Referencia</TableHead>
                    <TableHead className="text-right">Cargo</TableHead>
                    <TableHead className="text-right">Abono</TableHead>
                    <TableHead className="text-right">Saldo</TableHead>
                    <TableHead className="text-right">Acciones</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {movimientos.map((movimiento) => (
                    <TableRow key={movimiento.id}>
                      <TableCell className="whitespace-nowrap">
                        {formatDate(movimiento.fecha)}
                      </TableCell>
                      <TableCell>
                        <div>
                          <p className="font-medium">{movimiento.descripcion}</p>
                          {movimiento.beneficiario && (
                            <p className="text-sm text-gray-500">{movimiento.beneficiario}</p>
                          )}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline">
                          {getCategoriaNombre(movimiento.categoriaId)}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-gray-600">
                        {movimiento.referencia || '-'}
                      </TableCell>
                      <TableCell className="text-right">
                        {movimiento.tipo === 'egreso' && (
                          <span className="text-red-600 font-medium flex items-center justify-end gap-1">
                            <TrendingDown className="h-4 w-4" />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        {movimiento.tipo === 'ingreso' && (
                          <span className="text-green-600 font-medium flex items-center justify-end gap-1">
                            <TrendingUp className="h-4 w-4" />
                            {formatMoney(movimiento.monto, cuenta.moneda)}
                          </span>
                        )}
                      </TableCell>
                      <TableCell className="text-right font-medium">
                        {formatMoney(movimiento.saldoDespues, cuenta.moneda)}
                      </TableCell>
                      <TableCell className="text-right">
                        <div className="flex gap-2 justify-end">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedMovimiento(movimiento)
                              setShowModal(true)
                            }}
                          >
                            <Edit className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => handleDeleteMovimiento(movimiento.id)}
                          >
                            <Trash2 className="h-4 w-4" />
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
    </div>
  )
}
