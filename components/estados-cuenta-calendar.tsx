'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/lib/auth-context'
import { getEstadosCuenta, deleteEstadoCuenta } from '@/lib/firestore'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { CheckCircle2, XCircle, Download, Trash2, FileText } from 'lucide-react'

interface EstadoCuenta {
  id: string
  mes: number
  ano: number
  archivoUrl: string
  fechaCarga: Date
}

interface EstadosCuentaCalendarProps {
  cuentaId: string
  onUploadClick: () => void
  refreshTrigger?: number
}

export function EstadosCuentaCalendar({ cuentaId, onUploadClick, refreshTrigger }: EstadosCuentaCalendarProps) {
  const { user } = useAuth()
  const [estadosCuenta, setEstadosCuenta] = useState<EstadoCuenta[]>([])
  const [loading, setLoading] = useState(true)
  const [anoSeleccionado, setAnoSeleccionado] = useState(new Date().getFullYear())

  const meses = [
    { num: 1, nombre: 'Enero' },
    { num: 2, nombre: 'Febrero' },
    { num: 3, nombre: 'Marzo' },
    { num: 4, nombre: 'Abril' },
    { num: 5, nombre: 'Mayo' },
    { num: 6, nombre: 'Junio' },
    { num: 7, nombre: 'Julio' },
    { num: 8, nombre: 'Agosto' },
    { num: 9, nombre: 'Septiembre' },
    { num: 10, nombre: 'Octubre' },
    { num: 11, nombre: 'Noviembre' },
    { num: 12, nombre: 'Diciembre' },
  ]

  const loadEstadosCuenta = useCallback(async () => {
    if (!user) return

    try {
      setLoading(true)
      const data = await getEstadosCuenta(cuentaId)
      setEstadosCuenta(data as EstadoCuenta[])
    } catch (error) {
      console.error('Error al cargar estados de cuenta:', error)
    } finally {
      setLoading(false)
    }
  }, [user, cuentaId])

  useEffect(() => {
    if (user && cuentaId) {
      loadEstadosCuenta()
    }
  }, [user, cuentaId, loadEstadosCuenta, refreshTrigger])

  const tieneEstadoCuenta = (mes: number, ano: number): EstadoCuenta | undefined => {
    return estadosCuenta.find(e => e.mes === mes && e.ano === ano)
  }

  const handleDelete = async (id: string) => {
    if (!confirm('¿Estás seguro de eliminar este estado de cuenta?')) return

    try {
      await deleteEstadoCuenta(id)
      await loadEstadosCuenta()
    } catch (error) {
      console.error('Error al eliminar estado de cuenta:', error)
      alert('Error al eliminar el estado de cuenta')
    }
  }

  const handleDownload = (url: string, mes: number, ano: number) => {
    const mesNombre = meses.find(m => m.num === mes)?.nombre || mes
    const link = document.createElement('a')
    link.href = url
    link.download = `estado-cuenta-${mesNombre}-${ano}.pdf`
    link.target = '_blank'
    document.body.appendChild(link)
    link.click()
    document.body.removeChild(link)
  }

  const formatDate = (date: Date) => {
    return new Intl.DateTimeFormat('es-MX', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    }).format(date)
  }

  if (loading) {
    return (
      <Card className="bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-blue-500/30 shadow-2xl backdrop-blur-sm">
        <CardContent className="py-8">
          <div className="flex flex-col items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-4 border-blue-500 border-t-transparent mb-4"></div>
            <p className="text-lg font-black text-white">Cargando estados de cuenta...</p>
          </div>
        </CardContent>
      </Card>
    )
  }

  const anosDisponibles = [anoSeleccionado - 2, anoSeleccionado - 1, anoSeleccionado, anoSeleccionado + 1]
  const estadosCuentaDelAno = estadosCuenta.filter(e => e.ano === anoSeleccionado)

  return (
    <div className="space-y-6">
      <Card className="relative overflow-hidden bg-gradient-to-br from-slate-950/50 to-blue-950/50 border-blue-500/30 shadow-2xl backdrop-blur-sm">
        <div className="absolute top-0 right-0 w-48 h-48 bg-gradient-to-br from-blue-500 to-cyan-500 opacity-5 rounded-full -mr-24 -mt-24"></div>
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-purple-400 flex items-center gap-3">
              <FileText className="h-6 w-6 text-blue-400" strokeWidth={2.5} />
              Estados de Cuenta Mensuales
            </CardTitle>
            <div className="flex gap-3">
              <select
                value={anoSeleccionado}
                onChange={(e) => setAnoSeleccionado(parseInt(e.target.value))}
                className="h-10 px-4 text-sm font-bold bg-slate-900/50 border-2 border-slate-700 text-white rounded-lg focus:border-cyan-500 focus:ring-cyan-500/20 focus:outline-none"
              >
                {anosDisponibles.map(ano => (
                  <option key={ano} value={ano} className="bg-slate-900 text-white">{ano}</option>
                ))}
              </select>
              <Button
                onClick={onUploadClick}
                className="h-10 px-4 text-sm font-black bg-gradient-to-r from-blue-600 via-cyan-600 to-purple-600 hover:from-blue-500 hover:via-cyan-500 hover:to-purple-500 text-white shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50 transform hover:scale-105 transition-all"
              >
                <FileText className="mr-2 h-5 w-5" strokeWidth={2.5} />
                Subir
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-3 md:grid-cols-4 lg:grid-cols-6 gap-3">
            {meses.map(mes => {
              const estado = tieneEstadoCuenta(mes.num, anoSeleccionado)
              return (
                <div
                  key={mes.num}
                  className={`
                    relative p-3 rounded-lg border-2 transition-all duration-300 backdrop-blur-sm
                    ${estado
                      ? 'border-emerald-500/50 bg-gradient-to-br from-emerald-500/10 to-green-500/10 hover:border-emerald-400 hover:shadow-lg hover:shadow-emerald-500/20'
                      : 'border-slate-700/50 bg-gradient-to-br from-slate-900/50 to-slate-800/50 hover:border-slate-600 hover:bg-slate-800/50'
                    }
                  `}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-black text-sm text-white">{mes.nombre}</span>
                    {estado ? (
                      <CheckCircle2 className="h-5 w-5 text-emerald-400" strokeWidth={2.5} />
                    ) : (
                      <XCircle className="h-5 w-5 text-slate-500" strokeWidth={2.5} />
                    )}
                  </div>
                  {estado ? (
                    <div className="space-y-2">
                      <p className="text-xs text-emerald-300 font-semibold">
                        {formatDate(estado.fechaCarga)}
                      </p>
                      <div className="flex gap-1">
                        <Button
                          variant="outline"
                          className="flex-1 h-8 text-xs font-bold bg-cyan-500/10 border border-cyan-500/50 text-cyan-300 hover:bg-cyan-500/20 hover:border-cyan-400 hover:text-white p-0"
                          onClick={() => handleDownload(estado.archivoUrl, mes.num, anoSeleccionado)}
                        >
                          <Download className="h-4 w-4" strokeWidth={2.5} />
                        </Button>
                        <Button
                          variant="outline"
                          className="h-8 px-2 bg-red-500/10 border border-red-500/50 text-red-300 hover:bg-red-500/20 hover:border-red-400 hover:text-white"
                          onClick={() => handleDelete(estado.id)}
                        >
                          <Trash2 className="h-4 w-4" strokeWidth={2.5} />
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-500 font-semibold">Sin cargar</p>
                  )}
                </div>
              )
            })}
          </div>

          <div className="mt-6 pt-4 border-t border-slate-700 flex items-center gap-6 text-sm">
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-emerald-500/10 border border-emerald-500/30">
              <CheckCircle2 className="h-5 w-5 text-emerald-400" strokeWidth={2.5} />
              <span className="font-bold text-emerald-300">Cargado: <span className="text-white font-black">{estadosCuentaDelAno.length}</span></span>
            </div>
            <div className="flex items-center gap-2 px-4 py-2 rounded-lg bg-slate-700/20 border border-slate-600/30">
              <XCircle className="h-5 w-5 text-slate-400" strokeWidth={2.5} />
              <span className="font-bold text-slate-400">Faltante: <span className="text-white font-black">{12 - estadosCuentaDelAno.length}</span></span>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
