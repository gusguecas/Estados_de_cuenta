'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createCuenta, updateCuenta } from '@/lib/firestore'
import type { CuentaBancaria, CuentaBancariaFormData, Moneda, TipoCuenta } from '@/lib/types'
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

interface CuentaModalProps {
  open: boolean
  onClose: () => void
  cuenta?: CuentaBancaria | null
  empresaId: string
  onSuccess: () => void
}

export function CuentaModal({ open, onClose, cuenta, empresaId, onSuccess }: CuentaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [formData, setFormData] = useState<CuentaBancariaFormData>({
    nombre: '',
    banco: '',
    numeroCuenta: '',
    clabe: '',
    tipoCuenta: 'cheques',
    moneda: 'MXN',
    saldoInicial: 0,
    beneficiario: '',
    sucursal: '',
    notas: '',
  })

  useEffect(() => {
    if (cuenta) {
      setFormData({
        nombre: cuenta.nombre,
        banco: cuenta.banco,
        numeroCuenta: cuenta.numeroCuenta,
        clabe: cuenta.clabe || '',
        tipoCuenta: cuenta.tipoCuenta,
        moneda: cuenta.moneda,
        saldoInicial: cuenta.saldoInicial,
        beneficiario: cuenta.beneficiario || '',
        sucursal: cuenta.sucursal || '',
        notas: cuenta.notas || '',
      })
    } else {
      setFormData({
        nombre: '',
        banco: '',
        numeroCuenta: '',
        clabe: '',
        tipoCuenta: 'cheques',
        moneda: 'MXN',
        saldoInicial: 0,
        beneficiario: '',
        sucursal: '',
        notas: '',
      })
    }
  }, [cuenta, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    try {
      setLoading(true)
      if (cuenta) {
        await updateCuenta(cuenta.id, formData)
      } else {
        await createCuenta(user.uid, empresaId, formData)
      }
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error al guardar cuenta:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof CuentaBancariaFormData, value: string | number) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {cuenta ? 'Editar Cuenta Bancaria' : 'Nueva Cuenta Bancaria'}
          </DialogTitle>
          <DialogDescription>
            {cuenta
              ? 'Actualiza la información de la cuenta bancaria'
              : 'Completa los datos de la nueva cuenta'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="nombre">Nombre de la Cuenta *</Label>
              <Input
                id="nombre"
                placeholder="Ej: Cuenta Cheques Principal"
                value={formData.nombre}
                onChange={(e) => handleChange('nombre', e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="banco">Banco *</Label>
                <Input
                  id="banco"
                  placeholder="Ej: BBVA"
                  value={formData.banco}
                  onChange={(e) => handleChange('banco', e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="tipoCuenta">Tipo de Cuenta *</Label>
                <Select
                  value={formData.tipoCuenta}
                  onValueChange={(value) => handleChange('tipoCuenta', value as TipoCuenta)}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="cheques">Cheques</SelectItem>
                    <SelectItem value="credito">Crédito</SelectItem>
                    <SelectItem value="prestamo">Préstamo</SelectItem>
                    <SelectItem value="ahorro">Ahorro</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="numeroCuenta">Número de Cuenta *</Label>
                <Input
                  id="numeroCuenta"
                  placeholder="1234567890"
                  value={formData.numeroCuenta}
                  onChange={(e) => handleChange('numeroCuenta', e.target.value)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="clabe">CLABE</Label>
                <Input
                  id="clabe"
                  placeholder="012345678901234567"
                  value={formData.clabe}
                  onChange={(e) => handleChange('clabe', e.target.value)}
                  maxLength={18}
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="moneda">Moneda *</Label>
                <Select
                  value={formData.moneda}
                  onValueChange={(value) => handleChange('moneda', value as Moneda)}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="MXN">MXN - Pesos Mexicanos</SelectItem>
                    <SelectItem value="USD">USD - Dólares</SelectItem>
                    <SelectItem value="EUR">EUR - Euros</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-2">
                <Label htmlFor="saldoInicial">Saldo Inicial *</Label>
                <Input
                  id="saldoInicial"
                  type="number"
                  step="0.01"
                  value={formData.saldoInicial}
                  onChange={(e) => handleChange('saldoInicial', parseFloat(e.target.value) || 0)}
                  required
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="beneficiario">Beneficiario</Label>
                <Input
                  id="beneficiario"
                  value={formData.beneficiario}
                  onChange={(e) => handleChange('beneficiario', e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="sucursal">Sucursal</Label>
                <Input
                  id="sucursal"
                  value={formData.sucursal}
                  onChange={(e) => handleChange('sucursal', e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="notas">Notas</Label>
              <Input
                id="notas"
                placeholder="Notas adicionales sobre esta cuenta"
                value={formData.notas}
                onChange={(e) => handleChange('notas', e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
              Cancelar
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Guardando...' : cuenta ? 'Actualizar' : 'Crear'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
