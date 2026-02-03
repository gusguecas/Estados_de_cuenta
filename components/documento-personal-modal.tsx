'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createDocumentoPersonal, updateDocumentoPersonal, uploadDocumentoPersonalArchivo } from '@/lib/firestore'
import type { DocumentoPersonal, DocumentoPersonalFormData, TipoDocumentoPersonal, Persona } from '@/lib/types'
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
  FileText,
  Upload,
  Calendar,
  Hash,
  MapPin,
  Building2,
  User,
  CreditCard,
  Plane,
  Car,
  FileCheck,
  Shield,
  Heart,
  Home,
  GraduationCap,
  Tag
} from 'lucide-react'

interface DocumentoPersonalModalProps {
  open: boolean
  onClose: () => void
  documento?: DocumentoPersonal | null
  personas: Persona[]
  onSuccess: () => void
}

export function DocumentoPersonalModal({
  open,
  onClose,
  documento,
  personas,
  onSuccess
}: DocumentoPersonalModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [personaId, setPersonaId] = useState('')
  const [tipoDocumento, setTipoDocumento] = useState<TipoDocumentoPersonal | ''>('')
  const [nombre, setNombre] = useState('')
  const [numeroDocumento, setNumeroDocumento] = useState('')
  const [fechaExpedicion, setFechaExpedicion] = useState('')
  const [fechaVencimiento, setFechaVencimiento] = useState('')
  const [lugarExpedicion, setLugarExpedicion] = useState('')
  const [entidadEmisora, setEntidadEmisora] = useState('')
  const [notas, setNotas] = useState('')

  const tiposDocumento = [
    { value: 'pasaporte', label: 'Pasaporte', icon: Plane },
    { value: 'visa', label: 'Visa', icon: Plane },
    { value: 'ine', label: 'INE / Credencial de Elector', icon: CreditCard },
    { value: 'licencia_conducir', label: 'Licencia de Conducir', icon: Car },
    { value: 'curp', label: 'CURP', icon: FileCheck },
    { value: 'acta_nacimiento', label: 'Acta de Nacimiento', icon: FileText },
    { value: 'acta_matrimonio', label: 'Acta de Matrimonio', icon: Heart },
    { value: 'rfc', label: 'RFC / Constancia de Situación Fiscal', icon: Building2 },
    { value: 'comprobante_domicilio', label: 'Comprobante de Domicilio', icon: Home },
    { value: 'poliza_seguro_auto', label: 'Póliza de Seguro de Auto', icon: Car },
    { value: 'poliza_seguro_vida', label: 'Póliza de Seguro de Vida', icon: Shield },
    { value: 'poliza_gastos_medicos', label: 'Póliza de Gastos Médicos', icon: Heart },
    { value: 'poliza_seguro_hogar', label: 'Póliza de Seguro de Hogar', icon: Home },
    { value: 'cartilla_militar', label: 'Cartilla Militar', icon: Shield },
    { value: 'cedula_profesional', label: 'Cédula Profesional', icon: GraduationCap },
    { value: 'titulo_profesional', label: 'Título Profesional', icon: GraduationCap },
    { value: 'seguro_social', label: 'Seguro Social (IMSS/ISSSTE)', icon: Shield },
    { value: 'otro', label: 'Otro', icon: FileText },
  ]

  // Documentos que típicamente tienen fecha de vencimiento
  const documentosConVencimiento = [
    'pasaporte', 'visa', 'ine', 'licencia_conducir',
    'poliza_seguro_auto', 'poliza_seguro_vida', 'poliza_gastos_medicos', 'poliza_seguro_hogar'
  ]

  useEffect(() => {
    if (documento) {
      setPersonaId(documento.personaId)
      setTipoDocumento(documento.tipoDocumento)
      setNombre(documento.nombre)
      setNumeroDocumento(documento.numeroDocumento || '')
      setFechaExpedicion(documento.fechaExpedicion ? documento.fechaExpedicion.toISOString().split('T')[0] : '')
      setFechaVencimiento(documento.fechaVencimiento ? documento.fechaVencimiento.toISOString().split('T')[0] : '')
      setLugarExpedicion(documento.lugarExpedicion || '')
      setEntidadEmisora(documento.entidadEmisora || '')
      setNotas(documento.notas || '')
    } else {
      resetForm()
    }
  }, [documento, open])

  const resetForm = () => {
    setFile(null)
    setPersonaId('')
    setTipoDocumento('')
    setNombre('')
    setNumeroDocumento('')
    setFechaExpedicion('')
    setFechaVencimiento('')
    setLugarExpedicion('')
    setEntidadEmisora('')
    setNotas('')
  }

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
    }
  }

  // Auto-completar nombre basado en tipo de documento y persona
  const handleTipoChange = (value: TipoDocumentoPersonal) => {
    setTipoDocumento(value)
    const tipo = tiposDocumento.find(t => t.value === value)
    const persona = personas.find(p => p.id === personaId)
    if (tipo && persona && !nombre) {
      setNombre(`${tipo.label} - ${persona.nombre} ${persona.apellidos}`)
    }
  }

  const handlePersonaChange = (value: string) => {
    setPersonaId(value)
    const tipo = tiposDocumento.find(t => t.value === tipoDocumento)
    const persona = personas.find(p => p.id === value)
    if (tipo && persona && !nombre) {
      setNombre(`${tipo.label} - ${persona.nombre} ${persona.apellidos}`)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user || !personaId || !tipoDocumento || !nombre) return

    try {
      setLoading(true)

      let archivoUrl: string | undefined
      let nombreArchivo: string | undefined
      let tamanioArchivo: number | undefined

      // Subir archivo si hay uno nuevo
      if (file) {
        archivoUrl = await uploadDocumentoPersonalArchivo(file, user.uid, personaId)
        nombreArchivo = file.name
        tamanioArchivo = file.size
      }

      const formData: DocumentoPersonalFormData = {
        personaId,
        tipoDocumento: tipoDocumento as TipoDocumentoPersonal,
        nombre,
        numeroDocumento: numeroDocumento || undefined,
        fechaExpedicion: fechaExpedicion || undefined,
        fechaVencimiento: fechaVencimiento || undefined,
        lugarExpedicion: lugarExpedicion || undefined,
        entidadEmisora: entidadEmisora || undefined,
        notas: notas || undefined,
      }

      if (documento) {
        await updateDocumentoPersonal(documento.id, formData, archivoUrl, nombreArchivo, tamanioArchivo)
        alert('Documento actualizado exitosamente')
      } else {
        if (!file) {
          // Permitir crear sin archivo pero con advertencia
          const confirmar = confirm('No has seleccionado un archivo. ¿Deseas continuar sin adjuntar documento?')
          if (!confirmar) {
            setLoading(false)
            return
          }
        }
        await createDocumentoPersonal(user.uid, formData, archivoUrl, nombreArchivo, tamanioArchivo)
        alert('Documento agregado exitosamente')
      }

      onSuccess()
      onClose()
      resetForm()
    } catch (error) {
      console.error('Error al guardar documento:', error)
      alert('Error al guardar el documento')
    } finally {
      setLoading(false)
    }
  }

  const tieneVencimiento = documentosConVencimiento.includes(tipoDocumento)

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[65vw] max-h-[90vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-teal-500/30 shadow-2xl shadow-teal-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-teal-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-teal-500 via-cyan-500 to-blue-500 shadow-xl shadow-teal-500/30">
              {documento ? (
                <FileText className="h-10 w-10 text-white" strokeWidth={2.5} />
              ) : (
                <Upload className="h-10 w-10 text-white" strokeWidth={2.5} />
              )}
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-teal-400 to-cyan-400">
                {documento ? 'Editar Documento Personal' : 'Agregar Documento Personal'}
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                {documento ? 'Modifica los datos del documento' : 'Registra documentos importantes como pasaportes, INE, pólizas, etc.'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Persona */}
            <div className="grid gap-4">
              <Label htmlFor="persona" className="text-2xl font-black text-white flex items-center gap-3">
                <User className="h-7 w-7 text-pink-400" />
                Persona *
              </Label>
              <Select value={personaId} onValueChange={handlePersonaChange} disabled={loading}>
                <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-pink-500 focus:ring-pink-500/20">
                  <div className="flex items-center gap-3">
                    <User className="h-8 w-8 text-pink-400" />
                    <SelectValue placeholder="Selecciona a quién pertenece" />
                  </div>
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700">
                  {personas.map((p) => (
                    <SelectItem key={p.id} value={p.id} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      {p.nombre} {p.apellidos} ({p.parentesco === 'titular' ? 'Yo' : p.parentesco})
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {personas.length === 0 && (
                <p className="text-lg text-amber-400 font-semibold">
                  Primero debes agregar personas para poder registrar documentos.
                </p>
              )}
            </div>

            {/* Tipo de Documento */}
            <div className="grid gap-4">
              <Label htmlFor="tipo" className="text-2xl font-black text-white flex items-center gap-3">
                <FileCheck className="h-7 w-7 text-teal-400" />
                Tipo de Documento *
              </Label>
              <Select value={tipoDocumento} onValueChange={handleTipoChange} disabled={loading}>
                <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-teal-500 focus:ring-teal-500/20">
                  <div className="flex items-center gap-3">
                    <FileCheck className="h-8 w-8 text-teal-400" />
                    <SelectValue placeholder="Selecciona tipo de documento" />
                  </div>
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700 max-h-80">
                  {tiposDocumento.map((t) => {
                    const IconComponent = t.icon
                    return (
                      <SelectItem key={t.value} value={t.value} className="text-xl font-bold text-white hover:bg-slate-800 cursor-pointer py-3">
                        <div className="flex items-center gap-3">
                          <IconComponent className="h-5 w-5 text-teal-400" />
                          {t.label}
                        </div>
                      </SelectItem>
                    )
                  })}
                </SelectContent>
              </Select>
            </div>

            {/* Nombre del Documento */}
            <div className="grid gap-4">
              <Label htmlFor="nombre" className="text-2xl font-black text-white flex items-center gap-3">
                <Tag className="h-7 w-7 text-cyan-400" />
                Nombre del Documento *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Tag className="h-8 w-8 text-cyan-400" />
                </div>
                <Input
                  id="nombre"
                  value={nombre}
                  onChange={(e) => setNombre(e.target.value)}
                  disabled={loading}
                  required
                  placeholder="Ej: Pasaporte - Juan Pérez"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {/* Número de Documento */}
            <div className="grid gap-4">
              <Label htmlFor="numeroDocumento" className="text-2xl font-black text-white flex items-center gap-3">
                <Hash className="h-7 w-7 text-purple-400" />
                Número de Documento (opcional)
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Hash className="h-8 w-8 text-purple-400" />
                </div>
                <Input
                  id="numeroDocumento"
                  value={numeroDocumento}
                  onChange={(e) => setNumeroDocumento(e.target.value)}
                  disabled={loading}
                  placeholder="Ej: G12345678"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20"
                />
              </div>
            </div>

            {/* Fechas */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="fechaExpedicion" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-emerald-400" />
                  Fecha de Expedición
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Calendar className="h-8 w-8 text-emerald-400" />
                  </div>
                  <Input
                    id="fechaExpedicion"
                    type="date"
                    value={fechaExpedicion}
                    onChange={(e) => setFechaExpedicion(e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-emerald-500 focus:ring-emerald-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="fechaVencimiento" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-red-400" />
                  Fecha de Vencimiento {tieneVencimiento && <span className="text-red-400 text-lg">(Importante)</span>}
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Calendar className="h-8 w-8 text-red-400" />
                  </div>
                  <Input
                    id="fechaVencimiento"
                    type="date"
                    value={fechaVencimiento}
                    onChange={(e) => setFechaVencimiento(e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-red-500 focus:ring-red-500/20"
                  />
                </div>
              </div>
            </div>

            {/* Lugar de Expedición y Entidad Emisora */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="lugarExpedicion" className="text-2xl font-black text-white flex items-center gap-3">
                  <MapPin className="h-7 w-7 text-orange-400" />
                  Lugar de Expedición
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <MapPin className="h-8 w-8 text-orange-400" />
                  </div>
                  <Input
                    id="lugarExpedicion"
                    value={lugarExpedicion}
                    onChange={(e) => setLugarExpedicion(e.target.value)}
                    disabled={loading}
                    placeholder="Ej: Ciudad de México"
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-orange-500 focus:ring-orange-500/20"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="entidadEmisora" className="text-2xl font-black text-white flex items-center gap-3">
                  <Building2 className="h-7 w-7 text-blue-400" />
                  Entidad Emisora
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Building2 className="h-8 w-8 text-blue-400" />
                  </div>
                  <Input
                    id="entidadEmisora"
                    value={entidadEmisora}
                    onChange={(e) => setEntidadEmisora(e.target.value)}
                    disabled={loading}
                    placeholder="Ej: SRE, INE, SAT, GNP Seguros"
                    className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-blue-500 focus:ring-blue-500/20"
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
                  placeholder="Información adicional..."
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-slate-500 focus:ring-slate-500/20"
                />
              </div>
            </div>

            {/* Archivo */}
            <div className="grid gap-4">
              <Label htmlFor="file" className="text-2xl font-black text-white flex items-center gap-3">
                <Upload className="h-7 w-7 text-amber-400" />
                Archivo (PDF o Imagen) {!documento && '(opcional)'}
              </Label>
              <div className="flex items-center gap-4">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Upload className="h-8 w-8 text-amber-400" />
                  </div>
                  <Input
                    id="file"
                    type="file"
                    accept=".pdf,.jpg,.jpeg,.png,.webp"
                    onChange={handleFileChange}
                    disabled={loading}
                    className="pl-20 h-20 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-amber-600 file:text-white hover:file:bg-amber-500 focus:border-amber-500 focus:ring-amber-500/20"
                  />
                </div>
              </div>
              {file && (
                <div className="p-4 bg-amber-500/10 border-2 border-amber-500/30 rounded-xl">
                  <p className="text-lg text-amber-300 font-semibold">
                    Archivo: <span className="text-white font-black">{file.name}</span>
                  </p>
                  <p className="text-base text-amber-400 mt-1">
                    Tamaño: {(file.size / 1024 / 1024).toFixed(2)} MB
                  </p>
                </div>
              )}
              {documento?.archivoUrl && !file && (
                <div className="p-4 bg-teal-500/10 border-2 border-teal-500/30 rounded-xl">
                  <p className="text-lg text-teal-300 font-semibold">
                    Archivo actual: <span className="text-white font-black">{documento.nombreArchivo}</span>
                  </p>
                  <p className="text-base text-teal-400 mt-1">
                    Sube un nuevo archivo para reemplazarlo
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
              disabled={loading || !personaId || !tipoDocumento || !nombre || personas.length === 0}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-teal-600 via-cyan-600 to-blue-600 hover:from-teal-500 hover:via-cyan-500 hover:to-blue-500 text-white shadow-lg shadow-teal-500/30 hover:shadow-teal-500/50 transform hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Guardando...' : documento ? 'Guardar Cambios' : 'Agregar Documento'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
