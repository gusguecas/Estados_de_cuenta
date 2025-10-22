'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createTransferencia, getCuentas } from '@/lib/firestore'
import type { TransferenciaFormData, CuentaBancaria } from '@/lib/types'
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
  StickyNote
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
  const [formData, setFormData] = useState<TransferenciaFormData>({
    fecha: new Date().toISOString().split('T')[0],
    monto: 0,
    cuentaOrigenId: '',
    cuentaDestinoId: '',
    descripcion: '',
    referencia: '',
    notas: '',
  })

  useEffect(() => {
    if (user && open) {
      loadCuentas()
    }
  }, [user, open])

  useEffect(() => {
    if (cuentaOrigenPreseleccionada) {
      setFormData(prev => ({ ...prev, cuentaOrigenId: cuentaOrigenPreseleccionada }))
    }
  }, [cuentaOrigenPreseleccionada])

  const loadCuentas = async () => {
    if (!user) return
    try {
      const data = await getCuentas(user.uid)
      setCuentas(data.filter(c => c.activo))
    } catch (error) {
      console.error('Error al cargar cuentas:', error)
    }
  }

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
      await createTransferencia(user.uid, formData)
      onSuccess()
      onClose()
      // Resetear form
      setFormData({
        fecha: new Date().toISOString().split('T')[0],
        monto: 0,
        cuentaOrigenId: cuentaOrigenPreseleccionada || '',
        cuentaDestinoId: '',
        descripcion: '',
        referencia: '',
        notas: '',
      })
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
