'use client'

import { useState } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createEstadoCuenta, uploadEstadoCuentaPDF } from '@/lib/firestore'
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
import { FileText, Upload, Calendar } from 'lucide-react'

interface EstadoCuentaModalProps {
  open: boolean
  onClose: () => void
  cuentaId: string
  onSuccess: () => void
}

export function EstadoCuentaModal({
  open,
  onClose,
  cuentaId,
  onSuccess
}: EstadoCuentaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [mes, setMes] = useState('')
  const [ano, setAno] = useState(new Date().getFullYear().toString())

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
  const anos = Array.from({ length: 5 }, (_, i) => currentYear - i)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user || !file || !mes) return

    try {
      setLoading(true)

      // Subir PDF a Storage
      const downloadURL = await uploadEstadoCuentaPDF(file, cuentaId, parseInt(mes), parseInt(ano))

      // Crear registro en Firestore
      await createEstadoCuenta(user.uid, cuentaId, parseInt(mes), parseInt(ano), downloadURL)

      alert('Estado de cuenta subido exitosamente')
      onSuccess()
      onClose()
      setFile(null)
      setMes('')
    } catch (error) {
      console.error('Error al subir estado de cuenta:', error)
      alert('Error al subir el estado de cuenta')
    } finally {
      setLoading(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[55vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-blue-500/30 shadow-2xl shadow-blue-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-blue-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-blue-500 via-cyan-500 to-purple-500 shadow-xl shadow-blue-500/30">
              <Upload className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-blue-400 to-cyan-400">
                Subir Estado de Cuenta
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                Selecciona el archivo PDF del estado de cuenta mensual
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Mes y Año */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="mes" className="text-2xl font-black text-white flex items-center gap-3">
                  <Calendar className="h-7 w-7 text-emerald-400" />
                  Mes *
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
                  <Calendar className="h-7 w-7 text-cyan-400" />
                  Año *
                </Label>
                <Select value={ano} onValueChange={setAno} disabled={loading}>
                  <SelectTrigger className="h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-cyan-500 focus:ring-cyan-500/20">
                    <div className="flex items-center gap-3">
                      <Calendar className="h-8 w-8 text-cyan-400" />
                      <SelectValue />
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
                <FileText className="h-7 w-7 text-purple-400" />
                Archivo PDF *
              </Label>
              <div className="flex items-center gap-4">
                <div className="relative flex-1">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <FileText className="h-8 w-8 text-purple-400" />
                  </div>
                  <Input
                    id="file"
                    type="file"
                    accept=".pdf"
                    onChange={handleFileChange}
                    disabled={loading}
                    required
                    className="pl-20 h-20 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-purple-600 file:text-white hover:file:bg-purple-500 focus:border-purple-500 focus:ring-purple-500/20"
                  />
                </div>
              </div>
              {file && (
                <div className="p-4 bg-purple-500/10 border-2 border-purple-500/30 rounded-xl">
                  <p className="text-lg text-purple-300 font-semibold">
                    Archivo: <span className="text-white font-black">{file.name}</span>
                  </p>
                  <p className="text-base text-purple-400 mt-1">
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
              disabled={loading || !file || !mes}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-blue-600 via-cyan-600 to-purple-600 hover:from-blue-500 hover:via-cyan-500 hover:to-purple-500 text-white shadow-lg shadow-blue-500/30 hover:shadow-blue-500/50 transform hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? 'Subiendo...' : 'Subir Estado de Cuenta'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
