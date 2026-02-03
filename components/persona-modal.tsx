'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createPersona, updatePersona } from '@/lib/firestore'
import type { Persona, PersonaFormData } from '@/lib/types'
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
import { UserPlus, User, Users, Calendar, Mail, Phone, FileText } from 'lucide-react'

interface PersonaModalProps {
  open: boolean
  onClose: () => void
  persona?: Persona | null
  onSuccess: () => void
}

export function PersonaModal({
  open,
  onClose,
  persona,
  onSuccess
}: PersonaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [nombre, setNombre] = useState('')
  const [apellidos, setApellidos] = useState('')
  const [parentesco, setParentesco] = useState<PersonaFormData['parentesco'] | ''>('')
  const [fechaNacimiento, setFechaNacimiento] = useState('')
  const [email, setEmail] = useState('')
  const [telefono, setTelefono] = useState('')
  const [notas, setNotas] = useState('')

  const parentescos = [
    { value: 'titular', label: 'Titular (Yo)' },
    { value: 'esposa', label: 'Esposa' },
    { value: 'esposo', label: 'Esposo' },
    { value: 'hijo', label: 'Hijo' },
    { value: 'hija', label: 'Hija' },
    { value: 'padre', label: 'Padre' },
    { value: 'madre', label: 'Madre' },
    { value: 'otro', label: 'Otro' },
  ]

  useEffect(() => {
    if (persona) {
      setNombre(persona.nombre)
      setApellidos(persona.apellidos)
      setParentesco(persona.parentesco)
      setFechaNacimiento(persona.fechaNacimiento ? persona.fechaNacimiento.toISOString().split('T')[0] : '')
      setEmail(persona.email || '')
      setTelefono(persona.telefono || '')
      setNotas(persona.notas || '')
    } else {
      resetForm()
    }
  }, [persona, open])

  const resetForm = () => {
    setNombre('')
    setApellidos('')
    setParentesco('')
    setFechaNacimiento('')
    setEmail('')
    setTelefono('')
    setNotas('')
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user || !nombre || !apellidos || !parentesco) return

    try {
      setLoading(true)

      const formData: PersonaFormData = {
        nombre,
        apellidos,
        parentesco: parentesco as PersonaFormData['parentesco'],
        fechaNacimiento: fechaNacimiento || undefined,
        email: email || undefined,
        telefono: telefono || undefined,
        notas: notas || undefined,
      }

      if (persona) {
        await updatePersona(persona.id, formData)
        alert('Persona actualizada exitosamente')
      } else {
        await createPersona(user.uid, formData)
        alert('Persona agregada exitosamente')
      }

      onSuccess()
      onClose()
      resetForm()
    } catch (error) {
      console.error('Error al guardar persona:', error)
      alert('Error al guardar la persona')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[55vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-pink-500/30 shadow-2xl shadow-pink-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-pink-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-pink-500 via-rose-500 to-red-500 shadow-xl shadow-pink-500/30">
              {persona ? (
                <User className="h-10 w-10 text-white" strokeWidth={2.5} />
              ) : (
                <UserPlus className="h-10 w-10 text-white" strokeWidth={2.5} />
              )}
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-pink-400 to-rose-400">
                {persona ? 'Editar Persona' : 'Agregar Persona'}
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                {persona ? 'Modifica los datos de la persona' : 'Agrega un familiar o persona para sus documentos'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Nombre */}
            <div className="grid gap-4">
              <Label htmlFor="nombre" className="text-2xl font-black text-white flex items-center gap-3">
                <User className="h-7 w-7 text-pink-400" />
                Nombre(s) *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <User className="h-8 w-8 text-pink-400" />
                </div>
                <Input
                  id="nombre"
                  value={nombre}
                  onChange={(e) => setNombre(e.target.value)}
                  disabled={loading}
                  required
                  placeholder="Ej: Juan Carlos"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                />
              </div>
            </div>

            {/* Apellidos */}
            <div className="grid gap-4">
              <Label htmlFor="apellidos" className="text-2xl font-black text-white flex items-center gap-3">
                <User className="h-7 w-7 text-rose-400" />
                Apellidos *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <User className="h-8 w-8 text-rose-400" />
                </div>
                <Input
                  id="apellidos"
                  value={apellidos}
                  onChange={(e) => setApellidos(e.target.value)}
                  disabled={loading}
                  required
                  placeholder="Ej: Pérez López"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-rose-500 focus:ring-rose-500/20"
                />
              </div>
            </div>

            {/* Parentesco */}
            <div className="grid gap-4">
              <Label htmlFor="parentesco" className="text-2xl font-black text-white flex items-center gap-3">
                <Users className="h-7 w-7 text-purple-400" />
                Parentesco *
              </Label>
              <Select value={parentesco} onValueChange={(value) => setParentesco(value as PersonaFormData['parentesco'])} disabled={loading}>
                <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-purple-500 focus:ring-purple-500/20">
                  <div className="flex items-center gap-3">
                    <Users className="h-8 w-8 text-purple-400" />
                    <SelectValue placeholder="Selecciona parentesco" />
                  </div>
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700">
                  {parentescos.map((p) => (
                    <SelectItem key={p.value} value={p.value} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      {p.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Fecha de Nacimiento */}
            <div className="grid gap-4">
              <Label htmlFor="fechaNacimiento" className="text-2xl font-black text-white flex items-center gap-3">
                <Calendar className="h-7 w-7 text-cyan-400" />
                Fecha de Nacimiento (opcional)
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Calendar className="h-8 w-8 text-cyan-400" />
                </div>
                <Input
                  id="fechaNacimiento"
                  type="date"
                  value={fechaNacimiento}
                  onChange={(e) => setFechaNacimiento(e.target.value)}
                  disabled={loading}
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {/* Email y Teléfono */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="email" className="text-2xl font-black text-white flex items-center gap-3">
                  <Mail className="h-7 w-7 text-emerald-400" />
                  Email (opcional)
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Mail className="h-8 w-8 text-emerald-400" />
                  </div>
                  <Input
                    id="email"
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    disabled={loading}
                    placeholder="correo@ejemplo.com"
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="telefono" className="text-2xl font-black text-white flex items-center gap-3">
                  <Phone className="h-7 w-7 text-amber-400" />
                  Teléfono (opcional)
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Phone className="h-8 w-8 text-amber-400" />
                  </div>
                  <Input
                    id="telefono"
                    type="tel"
                    value={telefono}
                    onChange={(e) => setTelefono(e.target.value)}
                    disabled={loading}
                    placeholder="55 1234 5678"
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-amber-500 focus:ring-amber-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Notas */}
            <div className="grid gap-4">
              <Label htmlFor="notas" className="text-2xl font-black text-white flex items-center gap-3">
                <FileText className="h-7 w-7 text-slate-400" />
                Notas (opcional)
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <FileText className="h-8 w-8 text-slate-400" />
                </div>
                <Input
                  id="notas"
                  value={notas}
                  onChange={(e) => setNotas(e.target.value)}
                  disabled={loading}
                  placeholder="Notas adicionales..."
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-slate-500 focus:ring-slate-500/20"
                />
              </div>
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
              disabled={loading || !nombre || !apellidos || !parentesco}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-pink-600 via-rose-600 to-red-600 hover:from-pink-500 hover:via-rose-500 hover:to-red-500 text-white shadow-lg shadow-pink-500/30 hover:shadow-pink-500/50 transform hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Guardando...' : persona ? 'Guardar Cambios' : 'Agregar Persona'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
