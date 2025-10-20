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
import { ArrowRight, AlertCircle } from 'lucide-react'

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
      <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="text-2xl">Nueva Transferencia</DialogTitle>
          <DialogDescription>
            Transfiere dinero entre tus cuentas de forma automática
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-4">
            {/* Selector de Cuentas */}
            <div className="grid md:grid-cols-3 gap-4 items-center">
              <div className="grid gap-2">
                <Label htmlFor="cuentaOrigen">Cuenta Origen *</Label>
                <Select
                  value={formData.cuentaOrigenId}
                  onValueChange={(value) => handleChange('cuentaOrigenId', value)}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Seleccionar cuenta" />
                  </SelectTrigger>
                  <SelectContent>
                    {cuentas.map((cuenta) => (
                      <SelectItem key={cuenta.id} value={cuenta.id}>
                        {cuenta.nombre} - {cuenta.banco}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {cuentaOrigen && (
                  <p className="text-sm text-gray-600">
                    Saldo: ${cuentaOrigen.saldoActual.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                )}
              </div>

              <div className="flex justify-center">
                <ArrowRight className="h-8 w-8 text-blue-600" />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="cuentaDestino">Cuenta Destino *</Label>
                <Select
                  value={formData.cuentaDestinoId}
                  onValueChange={(value) => handleChange('cuentaDestinoId', value)}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Seleccionar cuenta" />
                  </SelectTrigger>
                  <SelectContent>
                    {cuentas
                      .filter(c => c.id !== formData.cuentaOrigenId)
                      .map((cuenta) => (
                        <SelectItem key={cuenta.id} value={cuenta.id}>
                          {cuenta.nombre} - {cuenta.banco}
                        </SelectItem>
                      ))}
                  </SelectContent>
                </Select>
                {cuentaDestino && (
                  <p className="text-sm text-gray-600">
                    Saldo: ${cuentaDestino.saldoActual.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                )}
              </div>
            </div>

            {/* Advertencia de saldo insuficiente */}
            {cuentaOrigen && formData.monto > cuentaOrigen.saldoActual && (
              <div className="flex items-center gap-2 p-3 bg-yellow-50 border border-yellow-200 rounded-lg">
                <AlertCircle className="h-5 w-5 text-yellow-600" />
                <p className="text-sm text-yellow-800">
                  Advertencia: El monto excede el saldo disponible en la cuenta origen
                </p>
              </div>
            )}

            {/* Monto y Fecha */}
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="monto">Monto *</Label>
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
                  className="text-lg font-semibold"
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="fecha">Fecha *</Label>
                <Input
                  id="fecha"
                  type="date"
                  value={formData.fecha}
                  onChange={(e) => handleChange('fecha', e.target.value)}
                  required
                  disabled={loading}
                />
              </div>
            </div>

            {/* Descripción */}
            <div className="grid gap-2">
              <Label htmlFor="descripcion">Descripción *</Label>
              <Input
                id="descripcion"
                placeholder="Ej: Pago de tarjeta de crédito, Transferencia para gastos, etc."
                value={formData.descripcion}
                onChange={(e) => handleChange('descripcion', e.target.value)}
                required
                disabled={loading}
              />
            </div>

            {/* Referencia y Notas */}
            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="referencia">Referencia</Label>
                <Input
                  id="referencia"
                  placeholder="Número de referencia"
                  value={formData.referencia}
                  onChange={(e) => handleChange('referencia', e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="notas">Notas</Label>
                <Input
                  id="notas"
                  placeholder="Notas adicionales"
                  value={formData.notas}
                  onChange={(e) => handleChange('notas', e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>

            {/* Preview de la transferencia */}
            {formData.cuentaOrigenId && formData.cuentaDestinoId && formData.monto > 0 && cuentaOrigen && cuentaDestino && (
              <div className="p-4 bg-blue-50 border border-blue-200 rounded-lg space-y-2">
                <h4 className="font-semibold text-blue-900 mb-3">Resumen de Transferencia</h4>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-gray-600">Se debitará de:</p>
                    <p className="font-semibold text-gray-900">{cuentaOrigen.nombre}</p>
                    <p className="text-xs text-gray-500">
                      Nuevo saldo: ${(cuentaOrigen.saldoActual - formData.monto).toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                    </p>
                  </div>
                  <div>
                    <p className="text-gray-600">Se acreditará a:</p>
                    <p className="font-semibold text-gray-900">{cuentaDestino.nombre}</p>
                    <p className="text-xs text-gray-500">
                      Nuevo saldo: ${(cuentaDestino.saldoActual + formData.monto).toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                    </p>
                  </div>
                </div>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
              Cancelar
            </Button>
            <Button
              type="submit"
              disabled={loading || !formData.cuentaOrigenId || !formData.cuentaDestinoId || formData.monto <= 0}
              className="bg-gradient-to-r from-blue-600 to-cyan-600 hover:from-blue-700 hover:to-cyan-700"
            >
              {loading ? 'Procesando...' : 'Realizar Transferencia'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
