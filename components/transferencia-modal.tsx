'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createTransferencia, getCuentas, uploadMovimientoAdjunto, getCategorias, createCategoria, updateCategoria, deleteCategoria } from '@/lib/firestore'
import type { TransferenciaFormData, CuentaBancaria, Categoria } from '@/lib/types'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import {
  ArrowRight,
  AlertCircle,
  ArrowLeftRight,
  Building2,
  Calendar,
  DollarSign,
  FileText,
  Hash,
  StickyNote,
  Paperclip,
  Tag,
  Pencil,
  Trash2,
  User
} from 'lucide-react'

interface TransferenciaModalProps {
  open: boolean
  onClose: () => void
  cuentaOrigenPreseleccionada?: string
  onSuccess: () => void
}

export function TransferenciaModal({
  open,
  onClose,
  cuentaOrigenPreseleccionada,
  onSuccess
}: TransferenciaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [categorias, setCategorias] = useState<Categoria[]>([])
  const [showNewCategoria, setShowNewCategoria] = useState(false)
  const [newCategoriaNombre, setNewCategoriaNombre] = useState('')
  const [editingCategoriaId, setEditingCategoriaId] = useState<string | null>(null)
  const [editingCategoriaNombre, setEditingCategoriaNombre] = useState('')
  const [showCategoriaActions, setShowCategoriaActions] = useState(false)
  const [formData, setFormData] = useState<TransferenciaFormData>({
    fecha: new Date().toISOString().split('T')[0],
    monto: 0,
    cuentaOrigenId: '',
    cuentaDestinoId: '',
    descripcion: '',
    categoriaId: '',
    referencia: '',
    beneficiario: '',
    notas: '',
  })
  const [archivosAdjuntos, setArchivosAdjuntos] = useState<File[]>([])

  const loadCategorias = useCallback(async () => {
    if (!user) return
    try {
      const data = await getCategorias(user.uid)
      setCategorias(data)
    } catch (error) {
      console.error('Error al cargar categorías:', error)
    }
  }, [user])

  const loadCuentas = useCallback(async () => {
    if (!user) return
    try {
      const data = await getCuentas(user.uid)
      setCuentas(data.filter(c => c.activo))
    } catch (error) {
      console.error('Error al cargar cuentas:', error)
    }
  }, [user])

  const handleCreateCategoria = async () => {
    if (!user || !newCategoriaNombre.trim()) return

    try {
      setLoading(true)
      const newCategoriaId = await createCategoria(user.uid, newCategoriaNombre.trim(), 'egreso')
      await loadCategorias()
      setFormData(prev => ({ ...prev, categoriaId: newCategoriaId }))
      setNewCategoriaNombre('')
      setShowNewCategoria(false)
    } catch (error) {
      console.error('Error al crear categoría:', error)
      alert('Error al crear la categoría')
    } finally {
      setLoading(false)
    }
  }

  const handleEditCategoria = async () => {
    if (!editingCategoriaId || !editingCategoriaNombre.trim()) return

    try {
      setLoading(true)
      await updateCategoria(editingCategoriaId, editingCategoriaNombre.trim())
      await loadCategorias()
      setEditingCategoriaId(null)
      setEditingCategoriaNombre('')
    } catch (error) {
      console.error('Error al editar categoría:', error)
      alert('Error al editar la categoría')
    } finally {
      setLoading(false)
    }
  }

  const handleDeleteCategoria = async (categoriaId: string) => {
    if (!confirm('¿Estás seguro de que deseas eliminar esta categoría? No se eliminarán los movimientos asociados.')) {
      return
    }

    try {
      setLoading(true)
      await deleteCategoria(categoriaId)
      await loadCategorias()
      if (formData.categoriaId === categoriaId) {
        setFormData(prev => ({ ...prev, categoriaId: '' }))
      }
    } catch (error) {
      console.error('Error al eliminar categoría:', error)
      alert('Error al eliminar la categoría')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    if (user && open) {
      loadCategorias()
      loadCuentas()
    }
  }, [user, open, loadCategorias, loadCuentas])

  useEffect(() => {
    if (cuentaOrigenPreseleccionada) {
      setFormData(prev => ({ ...prev, cuentaOrigenId: cuentaOrigenPreseleccionada }))
    }
  }, [cuentaOrigenPreseleccionada])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    if (formData.cuentaOrigenId === formData.cuentaDestinoId) {
      alert('No puedes transferir a la misma cuenta')
      return
    }

    if (formData.monto <= 0) {
      alert('El monto debe ser mayor a 0')
      return
    }

    try {
      setLoading(true)

      // Subir archivos adjuntos si existen
      const adjuntosUrls: string[] = []
      if (archivosAdjuntos.length > 0) {
        for (const archivo of archivosAdjuntos) {
          const url = await uploadMovimientoAdjunto(archivo, user.uid, formData.cuentaOrigenId)
          adjuntosUrls.push(url)
        }
      }

      // Crear transferencia con adjuntos
      await createTransferencia(user.uid, {
        ...formData,
        adjuntos: adjuntosUrls.length > 0 ? adjuntosUrls : undefined
      })
      onSuccess()
      onClose()
      // Resetear form
      setFormData({
        fecha: new Date().toISOString().split('T')[0],
        monto: 0,
        cuentaOrigenId: cuentaOrigenPreseleccionada || '',
        cuentaDestinoId: '',
        descripcion: '',
        categoriaId: '',
        referencia: '',
        beneficiario: '',
        notas: '',
      })
      setArchivosAdjuntos([])
      setShowNewCategoria(false)
      setNewCategoriaNombre('')
      setEditingCategoriaId(null)
      setEditingCategoriaNombre('')
      setShowCategoriaActions(false)
    } catch (error) {
      console.error('Error al crear transferencia:', error)
      alert('Error al crear la transferencia')
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof TransferenciaFormData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  const cuentaOrigen = cuentas.find(c => c.id === formData.cuentaOrigenId)
  const cuentaDestino = cuentas.find(c => c.id === formData.cuentaDestinoId)
  const categoriasDisponibles = categorias.filter(c => c.tipo === 'egreso')

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[60vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-emerald-500/30 shadow-2xl shadow-emerald-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-emerald-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-blue-500 via-cyan-500 to-emerald-500 shadow-xl shadow-blue-500/30">
              <ArrowLeftRight className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
                Nueva Transferencia
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                Transfiere dinero entre tus cuentas de forma automática
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Selector de Cuentas */}
            <div className="grid md:grid-cols-3 gap-6 items-center">
              <div className="grid gap-4">
                <Label htmlFor="cuentaOrigen" className="text-2xl font-black text-white flex items-center gap-3">
                  <Building2 className="h-7 w-7 text-blue-400" />
                  Cuenta Origen *
                </Label>
                <Select
                  value={formData.cuentaOrigenId}
                  onValueChange={(value) => handleChange('cuentaOrigenId', value)}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-blue-500 focus:ring-blue-500/20">
                    <SelectValue placeholder="Seleccionar cuenta" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    {cuentas.map((cuenta) => (
                      <SelectItem key={cuenta.id} value={cuenta.id} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        {cuenta.nombre} - {cuenta.banco}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {cuentaOrigen && (
                  <p className="text-xl text-emerald-400 font-bold pl-2">
                    Saldo: ${cuentaOrigen.saldoActual.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                )}
              </div>

              <div className="flex justify-center">
                <div className="p-4 rounded-full bg-gradient-to-r from-blue-500 to-cyan-500 shadow-lg shadow-blue-500/30">
                  <ArrowRight className="h-12 w-12 text-white" strokeWidth={2.5} />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="cuentaDestino" className="text-2xl font-black text-white flex items-center gap-3">
                  <Building2 className="h-7 w-7 text-cyan-400" />
                  Cuenta Destino *
                </Label>
                <Select
                  value={formData.cuentaDestinoId}
                  onValueChange={(value) => handleChange('cuentaDestinoId', value)}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-cyan-500 focus:ring-cyan-500/20">
                    <SelectValue placeholder="Seleccionar cuenta" />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    {cuentas
                      .filter(c => c.id !== formData.cuentaOrigenId)
                      .map((cuenta) => (
                        <SelectItem key={cuenta.id} value={cuenta.id} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                          {cuenta.nombre} - {cuenta.banco}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
                {cuentaDestino && (
                  <p className="text-xl text-emerald-400 font-bold pl-2">
                    Saldo: ${cuentaDestino.saldoActual.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                )}
              </div>
            </div>

            {/* Advertencia de saldo insuficiente */}
            {cuentaOrigen && formData.monto > cuentaOrigen.saldoActual && (
              <div className="flex items-center gap-4 p-6 bg-yellow-500/10 border-2 border-yellow-500/30 rounded-xl shadow-lg shadow-yellow-500/10">
                <AlertCircle className="h-10 w-10 text-yellow-400 flex-shrink-0" strokeWidth={2.5} />
                <p className="text-xl text-yellow-300 font-bold">
                  Advertencia: El monto excede el saldo disponible en la cuenta origen
                </p>
              </div>
            )}

            {/* Monto y Fecha */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="monto" className="text-2xl font-black text-white flex items-center gap-3">
                  <DollarSign className="h-7 w-7 text-yellow-400" />
                  Monto *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <DollarSign className="h-8 w-8 text-yellow-400" />
                  </div>
                  <Input
                    id="monto"
                    type="number"
                    step="0.01"
                    min="0.01"
                    placeholder="0.00"
                    value={formData.monto || ''}
                    onChange={(e) => handleChange('monto', parseFloat(e.target.value) || 0)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-yellow-500 focus:ring-yellow-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="fecha" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-blue-400" />
                  Fecha *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Calendar className="h-8 w-8 text-blue-400" />
                  </div>
                  <Input
                    id="fecha"
                    type="date"
                    value={formData.fecha}
                    onChange={(e) => handleChange('fecha', e.target.value)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-blue-500 focus:ring-blue-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Categoría */}
            <div className="grid gap-4">
                <div className="flex items-center justify-between">
                  <Label htmlFor="categoriaId" className="text-2xl font-black text-white flex items-center gap-3">
                    <Tag className="h-7 w-7 text-purple-400" />
                    Categoría (opcional)
                  </Label>
                  <div className="flex gap-2">
                    {!showNewCategoria && !editingCategoriaId && (
                      <>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowCategoriaActions(!showCategoriaActions)}
                          disabled={loading}
                          className="h-10 px-4 text-base font-bold text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                        >
                          {showCategoriaActions ? 'Ocultar' : 'Gestionar'}
                        </Button>
                        <Button
                          type="button"
                          variant="ghost"
                          size="sm"
                          onClick={() => setShowNewCategoria(true)}
                          disabled={loading}
                          className="h-10 px-4 text-base font-bold text-purple-400 hover:text-purple-300 hover:bg-purple-500/10"
                        >
                          + Nueva
                        </Button>
                      </>
                    )}
                  </div>
                </div>

                  {showNewCategoria ? (
                    <div className="flex gap-3">
                      <Input
                        placeholder="Nombre de la categoría"
                        value={newCategoriaNombre}
                        onChange={(e) => setNewCategoriaNombre(e.target.value)}
                        disabled={loading}
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            handleCreateCategoria()
                          }
                        }}
                        className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500"
                      />
                      <Button
                        type="button"
                        size="lg"
                        onClick={handleCreateCategoria}
                        disabled={loading || !newCategoriaNombre.trim()}
                        className="h-16 px-8 text-lg font-bold bg-purple-600 hover:bg-purple-500"
                      >
                        Crear
                      </Button>
                      <Button
                        type="button"
                        size="lg"
                        variant="outline"
                        onClick={() => {
                          setShowNewCategoria(false)
                          setNewCategoriaNombre('')
                        }}
                        disabled={loading}
                        className="h-16 px-8 text-lg font-bold bg-slate-900/50 text-slate-300 border-slate-600"
                      >
                        Cancelar
                      </Button>
                    </div>
                  ) : editingCategoriaId ? (
                    <div className="flex gap-3">
                      <Input
                        placeholder="Nombre de la categoría"
                        value={editingCategoriaNombre}
                        onChange={(e) => setEditingCategoriaNombre(e.target.value)}
                        disabled={loading}
                        onKeyPress={(e) => {
                          if (e.key === 'Enter') {
                            e.preventDefault()
                            handleEditCategoria()
                          }
                        }}
                        className="h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500"
                      />
                      <Button
                        type="button"
                        size="lg"
                        onClick={handleEditCategoria}
                        disabled={loading || !editingCategoriaNombre.trim()}
                        className="h-16 px-8 text-lg font-bold bg-blue-600 hover:bg-blue-500"
                      >
                        Guardar
                      </Button>
                      <Button
                        type="button"
                        size="lg"
                        variant="outline"
                        onClick={() => {
                          setEditingCategoriaId(null)
                          setEditingCategoriaNombre('')
                        }}
                        disabled={loading}
                        className="h-16 px-8 text-lg font-bold bg-slate-900/50 text-slate-300 border-slate-600"
                      >
                        Cancelar
                      </Button>
                    </div>
                  ) : (
                    <>
                      <Select
                        value={formData.categoriaId}
                        onValueChange={(value) => handleChange('categoriaId', value)}
                        disabled={loading}
                      >
                        <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-purple-500 focus:ring-purple-500/20">
                          <div className="flex items-center gap-3">
                            <Tag className="h-8 w-8 text-purple-400" />
                            <SelectValue placeholder="Selecciona una categoría" />
                          </div>
                        </SelectTrigger>
                        <SelectContent className="bg-slate-900 border-slate-700">
                          {Array.from(new Map(categoriasDisponibles.map(c => [c.nombre, c])).values()).map((cat) => (
                            <SelectItem key={cat.id} value={cat.id} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                              {cat.nombre}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>

                      {showCategoriaActions && categoriasDisponibles.length > 0 && (
                        <div className="mt-4 p-4 bg-slate-900/70 border border-slate-700 rounded-lg">
                          <h4 className="text-lg font-bold text-white mb-3 flex items-center gap-2">
                            <Tag className="h-5 w-5 text-purple-400" />
                            Gestionar Categorías
                          </h4>
                          <div className="space-y-2 max-h-64 overflow-y-auto">
                            {Array.from(new Map(categoriasDisponibles.map(c => [c.nombre, c])).values()).map((cat) => (
                              <div key={cat.id} className="flex items-center justify-between p-3 bg-slate-800/50 rounded-lg hover:bg-slate-800 transition-colors">
                                <span className="text-white font-semibold">{cat.nombre}</span>
                                <div className="flex gap-2">
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => {
                                      setEditingCategoriaId(cat.id)
                                      setEditingCategoriaNombre(cat.nombre)
                                      setShowCategoriaActions(false)
                                    }}
                                    disabled={loading}
                                    className="h-8 px-3 text-sm text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                                  >
                                    <Pencil className="h-4 w-4" />
                                  </Button>
                                  <Button
                                    type="button"
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => handleDeleteCategoria(cat.id)}
                                    disabled={loading}
                                    className="h-8 px-3 text-sm text-red-400 hover:text-red-300 hover:bg-red-500/10"
                                  >
                                    <Trash2 className="h-4 w-4" />
                                  </Button>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  )}
              </div>

            {/* Descripción */}
            <div className="grid gap-4">
              <Label htmlFor="descripcion" className="text-2xl font-black text-white flex items-center gap-3">
                <FileText className="h-7 w-7 text-cyan-400" />
                Descripción *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <FileText className="h-8 w-8 text-cyan-400" />
                </div>
                <Input
                  id="descripcion"
                  placeholder="Ej: Pago de tarjeta de crédito, Transferencia para gastos, etc."
                  value={formData.descripcion}
                  onChange={(e) => handleChange('descripcion', e.target.value)}
                  required
                  disabled={loading}
                  className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {/* Beneficiario */}
            <div className="grid gap-4">
              <Label htmlFor="beneficiario" className="text-2xl font-black text-white flex items-center gap-3">
                <User className="h-7 w-7 text-pink-400" />
                Beneficiario / Destinatario
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <User className="h-8 w-8 text-pink-400" />
                </div>
                <Input
                  id="beneficiario"
                  placeholder="Nombre del beneficiario o destinatario"
                  value={formData.beneficiario}
                  onChange={(e) => handleChange('beneficiario', e.target.value)}
                  disabled={loading}
                  className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                />
              </div>
            </div>

            {/* Referencia y Notas */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="referencia" className="text-2xl font-black text-white flex items-center gap-3">
                  <Hash className="h-7 w-7 text-emerald-400" />
                  Referencia
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Hash className="h-8 w-8 text-emerald-400" />
                  </div>
                  <Input
                    id="referencia"
                    placeholder="Número de referencia"
                    value={formData.referencia}
                    onChange={(e) => handleChange('referencia', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="notas" className="text-2xl font-black text-white flex items-center gap-3">
                  <StickyNote className="h-7 w-7 text-orange-400" />
                  Notas
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <StickyNote className="h-8 w-8 text-orange-400" />
                  </div>
                  <Input
                    id="notas"
                    placeholder="Notas adicionales"
                    value={formData.notas}
                    onChange={(e) => handleChange('notas', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-orange-500 focus:ring-orange-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Archivos Adjuntos */}
            <div className="grid gap-4">
              <Label htmlFor="adjuntos" className="text-2xl font-black text-white flex items-center gap-3">
                <Paperclip className="h-7 w-7 text-purple-400" />
                Comprobantes / Adjuntos
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Paperclip className="h-8 w-8 text-purple-400" />
                </div>
                <Input
                  id="adjuntos"
                  type="file"
                  accept=".pdf,.jpg,.jpeg,.png"
                  multiple
                  onChange={(e) => {
                    const files = Array.from(e.target.files || [])
                    if (files.length > 0) {
                      setArchivosAdjuntos(prev => [...prev, ...files])
                      // Limpiar el input para permitir seleccionar los mismos archivos de nuevo
                      e.target.value = ''
                    }
                  }}
                  disabled={loading}
                  className="pl-20 h-20 py-6 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-purple-600 file:text-white hover:file:bg-purple-500 focus:border-purple-500 focus:ring-purple-500/20"
                />
              </div>

              {/* Mostrar archivos nuevos seleccionados */}
              {archivosAdjuntos.length > 0 && (
                <div className="space-y-2">
                  <p className="text-lg font-bold text-purple-300">Archivos a subir ({archivosAdjuntos.length}):</p>
                  {archivosAdjuntos.map((archivo, index) => (
                    <div key={index} className="p-4 bg-purple-500/10 border-2 border-purple-500/30 rounded-xl flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Paperclip className="h-6 w-6 text-purple-400" />
                        <div>
                          <p className="text-lg text-white font-semibold">
                            {archivo.name}
                          </p>
                          <p className="text-base text-purple-400">
                            Tamaño: {(archivo.size / 1024 / 1024).toFixed(2)} MB
                          </p>
                        </div>
                      </div>
                      <Button
                        type="button"
                        variant="ghost"
                        size="sm"
                        onClick={() => {
                          setArchivosAdjuntos(prev => prev.filter((_, i) => i !== index))
                        }}
                        disabled={loading}
                        className="text-red-400 hover:text-red-300 hover:bg-red-500/10 font-bold"
                      >
                        Eliminar
                      </Button>
                    </div>
                  ))}
                </div>
              )}

              {archivosAdjuntos.length === 0 && (
                <p className="text-base text-slate-400 italic">
                  Puedes seleccionar múltiples archivos a la vez (PDF, JPG, PNG)
                </p>
              )}
            </div>

            {/* Preview de la transferencia */}
            {formData.cuentaOrigenId && formData.cuentaDestinoId && formData.monto > 0 && cuentaOrigen && cuentaDestino && (
              <div className="p-6 bg-blue-500/10 border-2 border-blue-500/30 rounded-2xl space-y-4 shadow-xl shadow-blue-500/10">
                <h4 className="text-2xl font-black text-blue-300 mb-4 flex items-center gap-3">
                  <ArrowLeftRight className="h-7 w-7" strokeWidth={2.5} />
                  Resumen de Transferencia
                </h4>
                <div className="grid grid-cols-2 gap-6">
                  <div className="space-y-2">
                    <p className="text-xl text-slate-400 font-bold">Se debitará de:</p>
                    <p className="text-2xl font-black text-white">{cuentaOrigen.nombre}</p>
                    <p className="text-lg text-slate-500 font-semibold">
                      {cuentaOrigen.banco}
                    </p>
                    <p className="text-xl text-red-400 font-bold">
                      Nuevo saldo: ${(cuentaOrigen.saldoActual - formData.monto).toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                    </p>
                  </div>
                  <div className="space-y-2">
                    <p className="text-xl text-slate-400 font-bold">Se acreditará a:</p>
                    <p className="text-2xl font-black text-white">{cuentaDestino.nombre}</p>
                    <p className="text-lg text-slate-500 font-semibold">
                      {cuentaDestino.banco}
                    </p>
                    <p className="text-xl text-emerald-400 font-bold">
                      Nuevo saldo: ${(cuentaDestino.saldoActual + formData.monto).toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          <DialogFooter className="gap-4 pt-8 border-t border-slate-700">
            <Button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="h-20 px-12 text-2xl font-black border-2 border-slate-600 bg-slate-900/50 text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={loading || !formData.cuentaOrigenId || !formData.cuentaDestinoId || formData.monto <= 0}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-blue-600 via-cyan-600 to-emerald-600 hover:from-blue-500 hover:via-cyan-500 hover:to-emerald-500 text-white shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50 transform hover:scale-105 transition-all"
            >
              {loading ? 'Procesando...' : 'Realizar Transferencia'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
