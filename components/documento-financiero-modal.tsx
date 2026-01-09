'use client'

import { useState } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createDocumentoFinanciero, uploadDocumentoFinancieroPDF } from '@/lib/firestore'
import type { TipoDocumentoFinanciero } from '@/lib/types'
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
import { FileText, Upload, Calendar, FileCheck, Tag } from 'lucide-react'

interface DocumentoFinancieroModalProps {
  open: boolean
  onClose: () => void
  onSuccess: () => void
}

export function DocumentoFinancieroModal({
  open,
  onClose,
  onSuccess
}: DocumentoFinancieroModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [nombre, setNombre] = useState('')
  const [tipoDocumento, setTipoDocumento] = useState<TipoDocumentoFinanciero | ''>('')
  const [descripcion, setDescripcion] = useState('')
  const [mes, setMes] = useState('')
  const [ano, setAno] = useState('')

  const tiposDocumento = [
    { value: 'buro_credito', label: 'Buró de Crédito' },
    { value: 'declaracion_anual', label: 'Declaración Anual' },
    { value: 'declaracion_mensual', label: 'Declaración Mensual' },
    { value: 'constancia_fiscal', label: 'Constancia de Situación Fiscal' },
    { value: 'otro', label: 'Otro' },
  ]

  const meses = [
    { value: '1', label: 'Enero' },
    { value: '2', label: 'Febrero' },
    { value: '3', label: 'Marzo' },
    { value: '4', label: 'Abril' },
    { value: '5', label: 'Mayo' },
    { value: '6', label: 'Junio' },
    { value: '7', label: 'Julio' },
    { value: '8', label: 'Agosto' },
    { value: '9', label: 'Septiembre' },
    { value: '10', label: 'Octubre' },
    { value: '11', label: 'Noviembre' },
    { value: '12', label: 'Diciembre' },
  ]

  const currentYear = new Date().getFullYear()
  const anos = Array.from({ length: 10 }, (_, i) => currentYear - i)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
    }
  }

  const resetForm = () => {
    setFile(null)
    setNombre('')
    setTipoDocumento('')
    setDescripcion('')
    setMes('')
    setAno('')
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user || !file || !nombre || !tipoDocumento) return

    try {
      setLoading(true)

      // Subir PDF a Storage
      const downloadURL = await uploadDocumentoFinancieroPDF(file, user.uid)

      // Crear registro en Firestore
      await createDocumentoFinanciero(
        user.uid,
        {
          nombre,
          tipoDocumento: tipoDocumento as TipoDocumentoFinanciero,
          descripcion: descripcion || undefined,
          año: ano ? parseInt(ano) : undefined,
          mes: mes ? parseInt(mes) : undefined,
        },
        downloadURL,
        file.name,
        file.size
      )

      alert('Documento subido exitosamente')
      onSuccess()
      onClose()
      resetForm()
    } catch (error) {
      console.error('Error al subir documento:', error)
      alert('Error al subir el documento')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[55vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-amber-500/30 shadow-2xl shadow-amber-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-amber-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-amber-500 via-orange-500 to-red-500 shadow-xl shadow-amber-500/30">
              <Upload className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-amber-400 to-orange-400">
                Subir Documento Financiero
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                Sube documentos como buró de crédito, declaraciones fiscales, etc.
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Nombre del documento */}
            <div className="grid gap-4">
              <Label htmlFor="nombre" className="text-2xl font-black text-white flex items-center gap-3">
                <Tag className="h-7 w-7 text-amber-400" />
                Nombre del Documento *
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Tag className="h-8 w-8 text-amber-400" />
                </div>
                <Input
                  id="nombre"
                  value={nombre}
                  onChange={(e) => setNombre(e.target.value)}
                  disabled={loading}
                  required
                  placeholder="Ej: Buró de Crédito Enero 2024"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-amber-500 focus:ring-amber-500/20"
                />
              </div>
            </div>

            {/* Tipo de Documento */}
            <div className="grid gap-4">
              <Label htmlFor="tipo" className="text-2xl font-black text-white flex items-center gap-3">
                <FileCheck className="h-7 w-7 text-orange-400" />
                Tipo de Documento *
              </Label>
              <Select value={tipoDocumento} onValueChange={(value) => setTipoDocumento(value as TipoDocumentoFinanciero)} disabled={loading}>
                <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-orange-500 focus:ring-orange-500/20">
                  <div className="flex items-center gap-3">
                    <FileCheck className="h-8 w-8 text-orange-400" />
                    <SelectValue placeholder="Selecciona tipo" />
                  </div>
                </SelectTrigger>
                <SelectContent className="bg-slate-900 border-slate-700">
                  {tiposDocumento.map((t) => (
                    <SelectItem key={t.value} value={t.value} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Descripción */}
            <div className="grid gap-4">
              <Label htmlFor="descripcion" className="text-2xl font-black text-white flex items-center gap-3">
                <FileText className="h-7 w-7 text-cyan-400" />
                Descripción (opcional)
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <FileText className="h-8 w-8 text-cyan-400" />
                </div>
                <Input
                  id="descripcion"
                  value={descripcion}
                  onChange={(e) => setDescripcion(e.target.value)}
                  disabled={loading}
                  placeholder="Notas o descripción adicional"
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                />
              </div>
            </div>

            {/* Mes y Año */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="mes" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-emerald-400" />
                  Mes (opcional)
                </Label>
                <Select value={mes} onValueChange={setMes} disabled={loading}>
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-emerald-500 focus:ring-emerald-500/20">
                    <div className="flex items-center gap-3">
                      <Calendar className="h-8 w-8 text-emerald-400" />
                      <SelectValue placeholder="Selecciona mes" />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    {meses.map((m) => (
                      <SelectItem key={m.value} value={m.value} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        {m.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="ano" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-purple-400" />
                  Año (opcional)
                </Label>
                <Select value={ano} onValueChange={setAno} disabled={loading}>
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-purple-500 focus:ring-purple-500/20">
                    <div className="flex items-center gap-3">
                      <Calendar className="h-8 w-8 text-purple-400" />
                      <SelectValue placeholder="Selecciona año" />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    {anos.map((a) => (
                      <SelectItem key={a} value={a.toString()} className="text-2xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                        {a}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Archivo PDF */}
            <div className="grid gap-4">
              <Label htmlFor="file" className="text-2xl font-black text-white flex items-center gap-3">
                <FileText className="h-7 w-7 text-red-400" />
                Archivo PDF *
              </Label>
              <div className="flex items-center gap-4">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <FileText className="h-8 w-8 text-red-400" />
                  </div>
                  <Input
                    id="file"
                    type="file"
                    accept=".pdf"
                    onChange={handleFileChange}
                    disabled={loading}
                    required
                    className="pl-20 h-20 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-red-600 file:text-white hover:file:bg-red-500 focus:border-red-500 focus:ring-red-500/20"
                  />
                </div>
              </div>
              {file && (
                <div className="p-4 bg-red-500/10 border-2 border-red-500/30 rounded-xl">
                  <p className="text-lg text-red-300 font-semibold">
                    Archivo: <span className="text-white font-black">{file.name}</span>
                  </p>
                  <p className="text-base text-red-400 mt-1">
                    Tamaño: {(file.size / 1024 / 1024).toFixed(2)} MB
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
              disabled={loading || !file || !nombre || !tipoDocumento}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-amber-600 via-orange-600 to-red-600 hover:from-amber-500 hover:via-orange-500 hover:to-red-500 text-white shadow-lg shadow-amber-500/30 hover:shadow-amber-500/50 transform hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Subiendo...' : 'Subir Documento'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
