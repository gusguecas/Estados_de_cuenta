'use client'

import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createMovimiento, updateMovimiento, getCategorias } from '@/lib/firestore'
import type { Movimiento, MovimientoFormData, Categoria, TipoMovimiento } from '@/lib/types'
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
  const [formData, setFormData] = useState<MovimientoFormData>({
    fecha: new Date().toISOString().split('T')[0],
    tipo: 'egreso',
    monto: 0,
    descripcion: '',
    categoriaId: '',
    referencia: '',
    beneficiario: '',
    comentarios: '',
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

  useEffect(() => {
    if (user && open) {
      loadCategorias()
    }
  }, [user, open, loadCategorias])

  useEffect(() => {
    if (movimiento) {
      setFormData({
        fecha: movimiento.fecha.toISOString().split('T')[0],
        tipo: movimiento.tipo,
        monto: movimiento.monto,
        descripcion: movimiento.descripcion,
        categoriaId: movimiento.categoriaId || '',
        referencia: movimiento.referencia || '',
        beneficiario: movimiento.beneficiario || '',
        comentarios: movimiento.comentarios || '',
      })
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
      })
    }
  }, [movimiento, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    try {
      setLoading(true)
      if (movimiento) {
        await updateMovimiento(movimiento.id, formData)
      } else {
        await createMovimiento(user.uid, cuentaId, formData)
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
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {movimiento ? 'Editar Movimiento' : 'Nuevo Movimiento'}
          </DialogTitle>
          <DialogDescription>
            {movimiento
              ? 'Actualiza la información del movimiento'
              : 'Registra un nuevo movimiento en la cuenta'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid grid-cols-2 gap-4">
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

              <div className="grid gap-2">
                <Label htmlFor="tipo">Tipo *</Label>
                <Select
                  value={formData.tipo}
                  onValueChange={(value) => {
                    handleChange('tipo', value as TipoMovimiento)
                    handleChange('categoriaId', '')
                  }}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ingreso">Ingreso (Abono)</SelectItem>
                    <SelectItem value="egreso">Egreso (Cargo)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="monto">Monto *</Label>
                <Input
                  id="monto"
                  type="number"
                  step="0.01"
                  min="0"
                  value={formData.monto}
                  onChange={(e) => handleChange('monto', parseFloat(e.target.value) || 0)}
                  required
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="categoriaId">Categoría</Label>
                <Select
                  value={formData.categoriaId}
                  onValueChange={(value) => handleChange('categoriaId', value)}
                  disabled={loading}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Selecciona una categoría" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="">Sin categoría</SelectItem>
                    {categoriasDisponibles.map((cat) => (
                      <SelectItem key={cat.id} value={cat.id}>
                        {cat.nombre}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="descripcion">Descripción *</Label>
              <Input
                id="descripcion"
                placeholder="Concepto del movimiento"
                value={formData.descripcion}
                onChange={(e) => handleChange('descripcion', e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="referencia">Referencia / No. Cheque</Label>
                <Input
                  id="referencia"
                  placeholder="Ej: 12345"
                  value={formData.referencia}
                  onChange={(e) => handleChange('referencia', e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="beneficiario">Beneficiario</Label>
                <Input
                  id="beneficiario"
                  placeholder="Nombre del beneficiario"
                  value={formData.beneficiario}
                  onChange={(e) => handleChange('beneficiario', e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="comentarios">Comentarios / Notas</Label>
              <Input
                id="comentarios"
                placeholder="Notas adicionales"
                value={formData.comentarios}
                onChange={(e) => handleChange('comentarios', e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
              Cancelar
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Guardando...' : movimiento ? 'Actualizar' : 'Crear'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
