'use client'

import { useEffect, useState, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth-context'
import { getEmpresas, deleteEmpresa } from '@/lib/firestore'
import type { Empresa } from '@/lib/types'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Building2, Plus, Edit, Trash2, ArrowLeft } from 'lucide-react'
import { EmpresaModal } from '@/components/empresa-modal'

export default function EmpresasPage() {
  const { user, loading: authLoading } = useAuth()
  const router = useRouter()
  const [empresas, setEmpresas] = useState<Empresa[]>([])
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
      const data = await getEmpresas(user.uid)
      setEmpresas(data)
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
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-gray-900 mx-auto"></div>
          <p className="mt-4 text-gray-600">Cargando...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-8">
      <div className="max-w-7xl mx-auto">
        <div className="flex items-center gap-4 mb-8">
          <Button
            variant="ghost"
            size="icon"
            onClick={() => router.push('/dashboard')}
          >
            <ArrowLeft className="h-5 w-5" />
          </Button>
          <div className="flex-1">
            <h1 className="text-3xl font-bold text-gray-900">Empresas</h1>
            <p className="text-gray-600 mt-1">Gestiona tus empresas</p>
          </div>
          <Button onClick={handleCreate}>
            <Plus className="mr-2 h-4 w-4" />
            Nueva Empresa
          </Button>
        </div>

        {empresas.length === 0 ? (
          <Card>
            <CardContent className="flex flex-col items-center justify-center py-12">
              <Building2 className="h-16 w-16 text-gray-400 mb-4" />
              <h3 className="text-xl font-semibold text-gray-900 mb-2">
                No hay empresas registradas
              </h3>
              <p className="text-gray-500 mb-6">
                Comienza creando tu primera empresa
              </p>
              <Button onClick={handleCreate}>
                <Plus className="mr-2 h-4 w-4" />
                Crear Primera Empresa
              </Button>
            </CardContent>
          </Card>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {empresas.map((empresa) => (
              <Card
                key={empresa.id}
                className="hover:shadow-lg transition-shadow cursor-pointer"
                onClick={() => router.push(`/empresas/${empresa.id}`)}
              >
                <CardHeader>
                  <div className="flex items-start justify-between">
                    <div className="flex-1">
                      <CardTitle className="flex items-center gap-2">
                        <Building2 className="h-5 w-5" />
                        {empresa.nombre}
                      </CardTitle>
                      {empresa.nombreComercial && (
                        <CardDescription className="mt-1">
                          {empresa.nombreComercial}
                        </CardDescription>
                      )}
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 text-sm">
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
                    {empresa.ciudad && (
                      <div className="flex justify-between">
                        <span className="text-gray-500">Ciudad:</span>
                        <span className="font-medium">{empresa.ciudad}</span>
                      </div>
                    )}
                  </div>
                  <div className="flex gap-2 mt-4">
                    <Button
                      variant="outline"
                      size="sm"
                      className="flex-1"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleEdit(empresa)
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
                        handleDelete(empresa.id)
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
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
    </div>
  )
}
