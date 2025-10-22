'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createMovimiento, updateMovimiento, getCategorias, createCategoria, getCuentas, createTransferencia, uploadMovimientoAdjunto } from '@/lib/firestore'
import type { Movimiento, MovimientoFormData, Categoria, TipoMovimiento, CuentaBancaria } from '@/lib/types'
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
import { ArrowLeftRight, AlertCircle, DollarSign, Calendar, FileText, Hash, User, MessageSquare, StickyNote, TrendingUp, TrendingDown, ArrowUpCircle, ArrowDownCircle, Tag, Building2, Paperclip } from 'lucide-react'

interface MovimientoModalProps {
  open: boolean
  onClose: () => void
  movimiento?: Movimiento | null
  cuentaId: string
  onSuccess: () => void
}

export function MovimientoModal({
  open,
  onClose,
  movimiento,
  cuentaId,
  onSuccess
}: MovimientoModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [categorias, setCategorias] = useState<Categoria[]>([])
  const [cuentas, setCuentas] = useState<CuentaBancaria[]>([])
  const [showNewCategoria, setShowNewCategoria] = useState(false)
  const [newCategoriaNombre, setNewCategoriaNombre] = useState('')
  const [esTransferencia, setEsTransferencia] = useState(false)
  const [cuentaDestinoId, setCuentaDestinoId] = useState('')
  const [archivoAdjunto, setArchivoAdjunto] = useState<File | null>(null)
  const [formData, setFormData] = useState<MovimientoFormData>({
    fecha: new Date().toISOString().split('T')[0],
    tipo: 'egreso',
    monto: 0,
    descripcion: '',
    categoriaId: '',
    referencia: '',
    beneficiario: '',
    comentarios: '',
    notas: '',
  })

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
      setCuentas(data.filter(c => c.activo && c.id !== cuentaId))
    } catch (error) {
      console.error('Error al cargar cuentas:', error)
    }
  }, [user, cuentaId])

  const handleCreateCategoria = async () => {
    if (!user || !newCategoriaNombre.trim()) return

    try {
      setLoading(true)
      const tipoCategoria = formData.tipo === 'transferencia' ? 'egreso' : formData.tipo
      const newCategoriaId = await createCategoria(user.uid, newCategoriaNombre.trim(), tipoCategoria)
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

  useEffect(() => {
    if (user && open) {
      loadCategorias()
      loadCuentas()
    }
  }, [user, open, loadCategorias, loadCuentas])

  useEffect(() => {
    if (movimiento) {
      // Extraer fecha en UTC para evitar problemas de zona horaria
      const fechaDate = movimiento.fecha
      const year = fechaDate.getUTCFullYear()
      const month = String(fechaDate.getUTCMonth() + 1).padStart(2, '0')
      const day = String(fechaDate.getUTCDate()).padStart(2, '0')
      const fechaString = `${year}-${month}-${day}`

      setFormData({
        fecha: fechaString,
        tipo: movimiento.tipo,
        monto: movimiento.monto,
        descripcion: movimiento.descripcion,
        categoriaId: movimiento.categoriaId || '',
        referencia: movimiento.referencia || '',
        beneficiario: movimiento.beneficiario || '',
        comentarios: movimiento.comentarios || '',
        notas: movimiento.notas || '',
      })
      setEsTransferencia(false)
      setCuentaDestinoId('')
      setArchivoAdjunto(null)
    } else {
      setFormData({
        fecha: new Date().toISOString().split('T')[0],
        tipo: 'egreso',
        monto: 0,
        descripcion: '',
        categoriaId: '',
        referencia: '',
        beneficiario: '',
        comentarios: '',
        notas: '',
      })
      setEsTransferencia(false)
      setCuentaDestinoId('')
      setArchivoAdjunto(null)
    }
  }, [movimiento, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    // Si es una transferencia, validar que haya cuenta destino
    if (esTransferencia && !movimiento) {
      if (!cuentaDestinoId) {
        alert('Debes seleccionar una cuenta destino')
        return
      }

      try {
        setLoading(true)
        // Crear transferencia
        await createTransferencia(user.uid, {
          fecha: formData.fecha,
          monto: formData.monto,
          cuentaOrigenId: cuentaId,
          cuentaDestinoId: cuentaDestinoId,
          descripcion: formData.descripcion,
          referencia: formData.referencia,
          notas: formData.notas
        })
        onSuccess()
        onClose()
      } catch (error) {
        console.error('Error al crear transferencia:', error)
        alert('Error al crear la transferencia')
      } finally {
        setLoading(false)
      }
      return
    }

    try {
      setLoading(true)

      // Subir archivo adjunto si existe (tanto para crear como para editar)
      let adjuntoUrl: string | undefined
      if (archivoAdjunto) {
        adjuntoUrl = await uploadMovimientoAdjunto(archivoAdjunto, user.uid, cuentaId)
      }

      if (movimiento) {
        // Si hay nuevo adjunto, actualizarlo
        const updateData = adjuntoUrl ? { ...formData, adjunto: adjuntoUrl } : formData
        await updateMovimiento(movimiento.id, updateData)
      } else {
        await createMovimiento(user.uid, cuentaId, formData, adjuntoUrl)
      }
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error al guardar movimiento:', error)
      alert('Error al guardar el movimiento')
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof MovimientoFormData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  const categoriasDisponibles = categorias.filter(
    (c) => c.tipo === formData.tipo
  )

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[60vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-emerald-500/30 shadow-2xl shadow-emerald-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-emerald-500/20">
          <div className="flex items-center gap-4">
            <div className={`p-4 rounded-2xl bg-gradient-to-br ${esTransferencia ? 'from-cyan-500 via-blue-500 to-purple-500' : 'from-emerald-500 via-green-500 to-teal-500'} shadow-xl shadow-emerald-500/30`}>
              {esTransferencia ? (
                <ArrowLeftRight className="h-10 w-10 text-white" strokeWidth={2.5} />
              ) : (
                <DollarSign className="h-10 w-10 text-white" strokeWidth={2.5} />
              )}
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">
                {movimiento ? 'Editar Movimiento' : esTransferencia ? 'Nueva Transferencia' : 'Nuevo Movimiento'}
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                {movimiento
                  ? 'Actualiza la información del movimiento'
                  : esTransferencia
                  ? 'Transfiere dinero entre tus cuentas'
                  : 'Registra un nuevo movimiento en la cuenta'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Pregunta si es transferencia */}
            {!movimiento && (
              <div className="p-6 bg-gradient-to-r from-cyan-950/50 to-blue-950/50 border-2 border-cyan-500/30 rounded-2xl shadow-lg shadow-cyan-500/20">
                <div className="flex items-start gap-4">
                  <input
                    type="checkbox"
                    id="esTransferencia"
                    checked={esTransferencia}
                    onChange={(e) => {
                      setEsTransferencia(e.target.checked)
                      if (e.target.checked) {
                        handleChange('tipo', 'egreso')
                      }
                    }}
                    disabled={loading}
                    className="mt-2 w-7 h-7 text-cyan-500 bg-slate-900 border-slate-600 rounded focus:ring-cyan-500 focus:ring-2"
                  />
                  <div className="flex-1">
                    <label htmlFor="esTransferencia" className="text-2xl font-black text-cyan-300 cursor-pointer flex items-center gap-3">
                      <ArrowLeftRight className="h-8 w-8" strokeWidth={2.5} />
                      ¿Es una transferencia entre cuentas?
                    </label>
                    <p className="text-lg text-slate-300 mt-2 font-semibold">
                      Marcar esta opción si el dinero va de esta cuenta a otra cuenta tuya (pago de tarjeta, préstamo entre cuentas, etc.)
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Selector de cuenta destino si es transferencia */}
            {esTransferencia && !movimiento && (
              <div className="grid gap-4">
                <Label htmlFor="cuentaDestino" className="text-2xl font-black text-white flex items-center gap-3">
                  <Building2 className="h-7 w-7 text-purple-400" />
                  Cuenta Destino *
                </Label>
                <Select
                  value={cuentaDestinoId}
                  onValueChange={setCuentaDestinoId}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-purple-500 focus:ring-purple-500/20">
                    <div className="flex items-center gap-3">
                      <Building2 className="h-8 w-8 text-purple-400" />
                      <SelectValue placeholder="Selecciona la cuenta destino" />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    {cuentas.map((cuenta) => (
                      <SelectItem key={cuenta.id} value={cuenta.id} className="text-xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        {cuenta.nombre} - {cuenta.banco} (${cuenta.saldoActual.toLocaleString('es-MX', { minimumFractionDigits: 2 })})
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            {/* Primera fila: Fecha y Tipo */}
            <div className="grid grid-cols-2 gap-6">
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

              {!esTransferencia && (
                <div className="grid gap-4">
                  <Label htmlFor="tipo" className="text-2xl font-black text-white flex items-center gap-3">
                    {formData.tipo === 'ingreso' ? <TrendingUp className="h-7 w-7 text-green-400" /> : <TrendingDown className="h-7 w-7 text-red-400" />}
                    Tipo *
                  </Label>
                  <Select
                    value={formData.tipo}
                    onValueChange={(value) => {
                      handleChange('tipo', value as TipoMovimiento)
                      handleChange('categoriaId', '')
                    }}
                    disabled={loading}
                  >
                    <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-emerald-500 focus:ring-emerald-500/20">
                      <div className="flex items-center gap-3">
                        {formData.tipo === 'ingreso' ? <ArrowUpCircle className="h-8 w-8 text-green-400" /> : <ArrowDownCircle className="h-8 w-8 text-red-400" />}
                        <SelectValue />
                      </div>
                    </SelectTrigger>
                    <SelectContent className="bg-slate-900 border-slate-700">
                      <SelectItem value="ingreso" className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        <div className="flex items-center gap-3">
                          <ArrowUpCircle className="h-6 w-6 text-green-400" />
                          Ingreso (Abono)
                        </div>
                      </SelectItem>
                      <SelectItem value="egreso" className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        <div className="flex items-center gap-3">
                          <ArrowDownCircle className="h-6 w-6 text-red-400" />
                          Egreso (Cargo)
                        </div>
                      </SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}
            </div>

            {/* Segunda fila: Monto y Categoría */}
            <div className={esTransferencia ? "grid gap-4" : "grid grid-cols-2 gap-6"}>
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
                    min="0"
                    value={formData.monto}
                    onChange={(e) => handleChange('monto', parseFloat(e.target.value) || 0)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-yellow-500 focus:ring-yellow-500/20"
                  />
                </div>
              </div>

              {!esTransferencia && (
                <div className="grid gap-4">
                  <div className="flex items-center justify-between">
                    <Label htmlFor="categoriaId" className="text-2xl font-black text-white flex items-center gap-3">
                      <Tag className="h-7 w-7 text-purple-400" />
                      Categoría
                    </Label>
                    {!showNewCategoria && (
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
                    )}
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
                  ) : (
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
                  )}
                </div>
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
                  placeholder={esTransferencia ? "Ej: Pago de tarjeta de crédito, préstamo entre cuentas, etc." : "Concepto del movimiento"}
                  value={formData.descripcion}
                  onChange={(e) => handleChange('descripcion', e.target.value)}
                  required
                  disabled={loading}
                  className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {!esTransferencia && (
              <>
                {/* Referencia y Beneficiario */}
                <div className="grid grid-cols-2 gap-6">
                  <div className="grid gap-4">
                    <Label htmlFor="referencia" className="text-2xl font-black text-white flex items-center gap-3">
                      <Hash className="h-7 w-7 text-emerald-400" />
                      Referencia / No. Cheque
                    </Label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                        <Hash className="h-8 w-8 text-emerald-400" />
                      </div>
                      <Input
                        id="referencia"
                        placeholder="Ej: 12345"
                        value={formData.referencia}
                        onChange={(e) => handleChange('referencia', e.target.value)}
                        disabled={loading}
                        className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20"
                      />
                    </div>
                  </div>

                  <div className="grid gap-4">
                    <Label htmlFor="beneficiario" className="text-2xl font-black text-white flex items-center gap-3">
                      <User className="h-7 w-7 text-pink-400" />
                      Beneficiario
                    </Label>
                    <div className="relative">
                      <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                        <User className="h-8 w-8 text-pink-400" />
                      </div>
                      <Input
                        id="beneficiario"
                        placeholder="Nombre del beneficiario"
                        value={formData.beneficiario}
                        onChange={(e) => handleChange('beneficiario', e.target.value)}
                        disabled={loading}
                        className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                      />
                    </div>
                  </div>
                </div>

                {/* Comentarios */}
                <div className="grid gap-4">
                  <Label htmlFor="comentarios" className="text-2xl font-black text-white flex items-center gap-3">
                    <MessageSquare className="h-7 w-7 text-indigo-400" />
                    Comentarios
                  </Label>
                  <div className="relative">
                    <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                      <MessageSquare className="h-8 w-8 text-indigo-400" />
                    </div>
                    <Input
                      id="comentarios"
                      placeholder="Comentarios sobre el movimiento"
                      value={formData.comentarios}
                      onChange={(e) => handleChange('comentarios', e.target.value)}
                      disabled={loading}
                      className="pl-20 h-20 !text-3xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-indigo-500 focus:ring-indigo-500/20"
                    />
                  </div>
                </div>
              </>
            )}

            {/* Notas */}
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

            {/* Archivo Adjunto */}
            <div className="grid gap-4">
              <Label htmlFor="adjunto" className="text-2xl font-black text-white flex items-center gap-3">
                <Paperclip className="h-7 w-7 text-purple-400" />
                Comprobante / Adjunto
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Paperclip className="h-8 w-8 text-purple-400" />
                </div>
                <Input
                  id="adjunto"
                  type="file"
                  accept=".pdf,.jpg,.jpeg,.png"
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (file) {
                      setArchivoAdjunto(file)
                    }
                  }}
                  disabled={loading}
                  className="pl-20 h-20 py-6 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-purple-600 file:text-white hover:file:bg-purple-500 focus:border-purple-500 focus:ring-purple-500/20"
                />
              </div>
              {archivoAdjunto && (
                <div className="p-4 bg-purple-500/10 border-2 border-purple-500/30 rounded-xl">
                  <p className="text-lg text-purple-300 font-semibold">
                    Archivo: <span className="text-white font-black">{archivoAdjunto.name}</span>
                  </p>
                  <p className="text-base text-purple-400 mt-1">
                    Tamaño: {(archivoAdjunto.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              )}
            </div>
          </div>

          <DialogFooter className="gap-4 pt-8 border-t border-slate-700">
            <Button
              type="button"
              variant="outline"
              onClick={onClose}
              disabled={loading}
              className="h-20 px-12 text-2xl font-black border-2 border-slate-600 bg-slate-900/50 text-slate-300 hover:bg-slate-800 hover:text-white"
            >
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={loading}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-500 hover:via-green-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-500/30 hover:shadow-emerald-500/50 transform hover:scale-105 transition-all"
            >
              {loading ? 'Guardando...' : movimiento ? 'Actualizar Movimiento' : esTransferencia ? 'Realizar Transferencia' : 'Crear Movimiento'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
