'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createEmpresa, updateEmpresa } from '@/lib/firestore'
import type { Empresa, EmpresaFormData } from '@/lib/types'
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

interface EmpresaModalProps {
  open: boolean
  onClose: () => void
  empresa?: Empresa | null
  onSuccess: () => void
}

export function EmpresaModal({ open, onClose, empresa, onSuccess }: EmpresaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [formData, setFormData] = useState<EmpresaFormData>({
    nombre: '',
    nombreComercial: '',
    rfc: '',
    direccion: '',
    ciudad: '',
    estado: '',
    codigoPostal: '',
    telefono: '',
    email: '',
    giro: '',
  })

  useEffect(() => {
    if (empresa) {
      setFormData({
        nombre: empresa.nombre,
        nombreComercial: empresa.nombreComercial || '',
        rfc: empresa.rfc || '',
        direccion: empresa.direccion || '',
        ciudad: empresa.ciudad || '',
        estado: empresa.estado || '',
        codigoPostal: empresa.codigoPostal || '',
        telefono: empresa.telefono || '',
        email: empresa.email || '',
        giro: empresa.giro || '',
      })
    } else {
      setFormData({
        nombre: '',
        nombreComercial: '',
        rfc: '',
        direccion: '',
        ciudad: '',
        estado: '',
        codigoPostal: '',
        telefono: '',
        email: '',
        giro: '',
      })
    }
  }, [empresa, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    try {
      setLoading(true)
      if (empresa) {
        await updateEmpresa(empresa.id, formData)
      } else {
        await createEmpresa(user.uid, formData)
      }
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error al guardar empresa:', error)
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof EmpresaFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[90vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {empresa ? 'Editar Empresa' : 'Nueva Empresa'}
          </DialogTitle>
          <DialogDescription>
            {empresa
              ? 'Actualiza la información de la empresa'
              : 'Completa los datos de la nueva empresa'}
          </DialogDescription>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-4 py-4">
            <div className="grid gap-2">
              <Label htmlFor="nombre">Nombre de la Empresa *</Label>
              <Input
                id="nombre"
                value={formData.nombre}
                onChange={(e) => handleChange('nombre', e.target.value)}
                required
                disabled={loading}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="nombreComercial">Nombre Comercial</Label>
              <Input
                id="nombreComercial"
                value={formData.nombreComercial}
                onChange={(e) => handleChange('nombreComercial', e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="rfc">RFC</Label>
              <Input
                id="rfc"
                value={formData.rfc}
                onChange={(e) => handleChange('rfc', e.target.value.toUpperCase())}
                maxLength={13}
                disabled={loading}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="giro">Giro</Label>
              <Input
                id="giro"
                value={formData.giro}
                onChange={(e) => handleChange('giro', e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="grid gap-2">
              <Label htmlFor="direccion">Dirección</Label>
              <Input
                id="direccion"
                value={formData.direccion}
                onChange={(e) => handleChange('direccion', e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="ciudad">Ciudad</Label>
                <Input
                  id="ciudad"
                  value={formData.ciudad}
                  onChange={(e) => handleChange('ciudad', e.target.value)}
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="estado">Estado</Label>
                <Input
                  id="estado"
                  value={formData.estado}
                  onChange={(e) => handleChange('estado', e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div className="grid gap-2">
                <Label htmlFor="codigoPostal">Código Postal</Label>
                <Input
                  id="codigoPostal"
                  value={formData.codigoPostal}
                  onChange={(e) => handleChange('codigoPostal', e.target.value)}
                  maxLength={5}
                  disabled={loading}
                />
              </div>

              <div className="grid gap-2">
                <Label htmlFor="telefono">Teléfono</Label>
                <Input
                  id="telefono"
                  value={formData.telefono}
                  onChange={(e) => handleChange('telefono', e.target.value)}
                  disabled={loading}
                />
              </div>
            </div>

            <div className="grid gap-2">
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                value={formData.email}
                onChange={(e) => handleChange('email', e.target.value)}
                disabled={loading}
              />
            </div>
          </div>

          <DialogFooter>
            <Button type="button" variant="outline" onClick={onClose} disabled={loading}>
              Cancelar
            </Button>
            <Button type="submit" disabled={loading}>
              {loading ? 'Guardando...' : empresa ? 'Actualizar' : 'Crear'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
