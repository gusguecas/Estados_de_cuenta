'use client'

import { useState, useEffect } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createEmpresa, updateEmpresa, uploadEmpresaLogo } from '@/lib/firestore'
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
import { Upload, X, Building2, Store, FileText, MapPin, Globe, Phone, Mail, Briefcase, Hash, DollarSign } from 'lucide-react'
import Image from 'next/image'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

interface EmpresaModalProps {
  open: boolean
  onClose: () => void
  empresa?: Empresa | null
  onSuccess: () => void
}

export function EmpresaModal({ open, onClose, empresa, onSuccess }: EmpresaModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [logoFile, setLogoFile] = useState<File | null>(null)
  const [logoPreview, setLogoPreview] = useState<string | null>(null)
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
    logo: '',
    moneda: 'MXN',
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
        logo: empresa.logo || '',
        moneda: empresa.moneda || 'MXN',
      })
      setLogoPreview(empresa.logo || null)
      setLogoFile(null)
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
        logo: '',
        moneda: 'MXN',
      })
      setLogoPreview(null)
      setLogoFile(null)
    }
  }, [empresa, open])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!user) return

    try {
      setLoading(true)
      let logoUrl = formData.logo

      if (empresa) {
        // Si hay un nuevo logo, subirlo
        if (logoFile) {
          logoUrl = await uploadEmpresaLogo(logoFile, empresa.id)
        }
        await updateEmpresa(empresa.id, { ...formData, logo: logoUrl })
      } else {
        // Crear empresa primero
        const empresaId = await createEmpresa(user.uid, formData)

        // Si hay logo, subirlo y actualizar
        if (logoFile) {
          logoUrl = await uploadEmpresaLogo(logoFile, empresaId)
          await updateEmpresa(empresaId, { logo: logoUrl })
        }
      }
      onSuccess()
      onClose()
    } catch (error) {
      console.error('Error al guardar empresa:', error)
      alert('Error al guardar la empresa')
    } finally {
      setLoading(false)
    }
  }

  const handleChange = (field: keyof EmpresaFormData, value: string) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
  }

  const handleLogoChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      // Validar que sea imagen
      if (!file.type.startsWith('image/')) {
        alert('Por favor selecciona un archivo de imagen')
        return
      }

      // Validar tamaño (máx 2MB)
      if (file.size > 2 * 1024 * 1024) {
        alert('La imagen debe ser menor a 2MB')
        return
      }

      setLogoFile(file)

      // Crear preview
      const reader = new FileReader()
      reader.onloadend = () => {
        setLogoPreview(reader.result as string)
      }
      reader.readAsDataURL(file)
    }
  }

  const handleRemoveLogo = () => {
    setLogoFile(null)
    setLogoPreview(null)
    setFormData(prev => ({ ...prev, logo: '' }))
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[60vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-blue-950 to-slate-950 border-emerald-500/30 shadow-2xl shadow-emerald-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-emerald-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-emerald-500 via-cyan-500 to-blue-500 shadow-xl shadow-emerald-500/30">
              <Building2 className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">
                {empresa ? 'Editar Empresa' : 'Nueva Empresa'}
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                {empresa
                  ? 'Actualiza la información de la empresa'
                  : 'Completa los datos de la nueva empresa'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <form onSubmit={handleSubmit}>
          <div className="grid gap-6 py-6">
            {/* Primera fila: Nombre y Nombre Comercial */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="nombre" className="text-2xl font-black text-white flex items-center gap-3">
                  <Building2 className="h-7 w-7 text-emerald-400" />
                  Nombre de la Empresa *
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Store className="h-8 w-8 text-emerald-400" />
                  </div>
                  <Input
                    id="nombre"
                    value={formData.nombre}
                    onChange={(e) => handleChange('nombre', e.target.value)}
                    required
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-emerald-500 focus:ring-emerald-500/20"
                    placeholder="Ej: Acme Corporation"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="nombreComercial" className="text-2xl font-black text-white flex items-center gap-3">
                  <FileText className="h-7 w-7 text-cyan-400" />
                  Nombre Comercial
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Store className="h-8 w-8 text-cyan-400" />
                  </div>
                  <Input
                    id="nombreComercial"
                    value={formData.nombreComercial}
                    onChange={(e) => handleChange('nombreComercial', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-cyan-500 focus:ring-cyan-500/20"
                    placeholder="Nombre público de la empresa"
                  />
                </div>
              </div>
            </div>

            {/* Segunda fila: RFC y Logo */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="rfc" className="text-2xl font-black text-white flex items-center gap-3">
                  <Hash className="h-7 w-7 text-purple-400" />
                  {formData.moneda === 'MXN'
                    ? 'RFC'
                    : formData.moneda === 'EUR'
                      ? 'NIF / CIF / NIE'
                      : 'EIN / Tax ID'}
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <FileText className="h-8 w-8 text-purple-400" />
                  </div>
                  <Input
                    id="rfc"
                    value={formData.rfc}
                    onChange={(e) => handleChange('rfc', e.target.value.toUpperCase())}
                    maxLength={formData.moneda === 'MXN' ? 13 : formData.moneda === 'EUR' ? 9 : 10}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-purple-500 focus:ring-purple-500/20 uppercase"
                    placeholder={
                      formData.moneda === 'MXN'
                        ? 'XAXX010101000'
                        : formData.moneda === 'EUR'
                          ? 'A12345678'
                          : '12-3456789'
                    }
                  />
                </div>
              </div>

              {/* Logo Upload */}
              <div className="grid gap-4">
                <Label htmlFor="logo" className="text-2xl font-black text-white flex items-center gap-3">
                  <Upload className="h-7 w-7 text-cyan-400" />
                  Logo de la Empresa
                </Label>
                <div className="flex flex-col gap-4">
                  {logoPreview ? (
                    <div className="relative w-40 h-40 border-2 border-emerald-500/30 rounded-2xl overflow-hidden bg-slate-900/50 shadow-xl shadow-emerald-500/20">
                      <Image
                        src={logoPreview}
                        alt="Logo preview"
                        fill
                        className="object-contain p-3"
                      />
                      <button
                        type="button"
                        onClick={handleRemoveLogo}
                        className="absolute top-2 right-2 bg-red-500 hover:bg-red-600 text-white rounded-full p-2 transition-all shadow-lg hover:scale-110"
                        disabled={loading}
                      >
                        <X className="h-5 w-5" />
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-4">
                      <label
                        htmlFor="logo-upload"
                        className="flex items-center gap-3 px-6 py-4 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-xl cursor-pointer transition-all shadow-lg shadow-cyan-500/30 hover:shadow-cyan-500/50 font-bold text-base transform hover:scale-105"
                      >
                        <Upload className="h-6 w-6" />
                        <span>Subir Logo</span>
                      </label>
                      <input
                        id="logo-upload"
                        type="file"
                        accept="image/*"
                        onChange={handleLogoChange}
                        className="hidden"
                        disabled={loading}
                      />
                    </div>
                  )}
                </div>
              </div>
            </div>

            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="giro" className="text-2xl font-black text-white flex items-center gap-3">
                  <Briefcase className="h-7 w-7 text-blue-400" />
                  Giro
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Briefcase className="h-8 w-8 text-blue-400" />
                  </div>
                  <Input
                    id="giro"
                    value={formData.giro}
                    onChange={(e) => handleChange('giro', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-blue-500 focus:ring-blue-500/20"
                    placeholder="Ej: Tecnología, Retail"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="moneda" className="text-2xl font-black text-white flex items-center gap-3">
                  <DollarSign className="h-7 w-7 text-emerald-400" />
                  Moneda *
                </Label>
                <Select
                  value={formData.moneda}
                  onValueChange={(value) => handleChange('moneda', value)}
                  disabled={loading}
                >
                  <SelectTrigger className="h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white focus:border-emerald-500 focus:ring-emerald-500/20">
                    <div className="flex items-center gap-3">
                      <DollarSign className="h-8 w-8 text-emerald-400" />
                      <SelectValue />
                    </div>
                  </SelectTrigger>
                  <SelectContent className="bg-slate-900 border-slate-700">
                    <SelectItem value="MXN" className="text-4xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇲🇽 Peso Mexicano (MXN)
                    </SelectItem>
                    <SelectItem value="USD" className="text-4xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇺🇸 Dólar Americano (USD)
                    </SelectItem>
                    <SelectItem value="EUR" className="text-4xl font-bold text-white hover:bg-slate-800 cursor-pointer py-4">
                      🇪🇺 Euro (EUR)
                    </SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {/* Tercera fila: Ciudad, Estado, CP */}
            <div className="grid grid-cols-3 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="ciudad" className="text-2xl font-black text-white flex items-center gap-3">
                  <Globe className="h-7 w-7 text-pink-400" />
                  Ciudad
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Globe className="h-8 w-8 text-pink-400" />
                  </div>
                  <Input
                    id="ciudad"
                    value={formData.ciudad}
                    onChange={(e) => handleChange('ciudad', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                    placeholder="Ciudad"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="estado" className="text-2xl font-black text-white flex items-center gap-3">
                  <MapPin className="h-7 w-7 text-pink-400" />
                  {formData.moneda === 'MXN' ? 'Estado' : formData.moneda === 'EUR' ? 'Provincia' : 'State'}
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <MapPin className="h-8 w-8 text-pink-400" />
                  </div>
                  <Input
                    id="estado"
                    value={formData.estado}
                    onChange={(e) => handleChange('estado', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-pink-500 focus:ring-pink-500/20"
                    placeholder={formData.moneda === 'MXN' ? 'Estado' : formData.moneda === 'EUR' ? 'Madrid' : 'State'}
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="codigoPostal" className="text-2xl font-black text-white flex items-center gap-3">
                  <Hash className="h-7 w-7 text-yellow-400" />
                  {formData.moneda === 'USD' ? 'ZIP Code' : 'C.P.'}
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Hash className="h-8 w-8 text-yellow-400" />
                  </div>
                  <Input
                    id="codigoPostal"
                    value={formData.codigoPostal}
                    onChange={(e) => handleChange('codigoPostal', e.target.value)}
                    maxLength={formData.moneda === 'USD' ? 10 : 5}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-yellow-500 focus:ring-yellow-500/20"
                    placeholder={formData.moneda === 'USD' ? '12345' : '00000'}
                  />
                </div>
              </div>
            </div>

            {/* Cuarta fila: Dirección y Email */}
            <div className="grid grid-cols-2 gap-6">
              <div className="grid gap-4">
                <Label htmlFor="direccion" className="text-2xl font-black text-white flex items-center gap-3">
                  <MapPin className="h-7 w-7 text-orange-400" />
                  Dirección
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <MapPin className="h-8 w-8 text-orange-400" />
                  </div>
                  <Input
                    id="direccion"
                    value={formData.direccion}
                    onChange={(e) => handleChange('direccion', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-orange-500 focus:ring-orange-500/20"
                    placeholder="Calle, número, colonia"
                  />
                </div>
              </div>

              <div className="grid gap-4">
                <Label htmlFor="email" className="text-2xl font-black text-white flex items-center gap-3">
                  <Mail className="h-7 w-7 text-indigo-400" />
                  Email
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <Mail className="h-8 w-8 text-indigo-400" />
                  </div>
                  <Input
                    id="email"
                    type="email"
                    value={formData.email}
                    onChange={(e) => handleChange('email', e.target.value)}
                    disabled={loading}
                    className="pl-20 h-20 text-4xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-indigo-500 focus:ring-indigo-500/20"
                    placeholder="contacto@empresa.com"
                  />
                </div>
              </div>
            </div>

            {/* Quinta fila: Teléfono */}
            <div className="grid gap-4">
              <Label htmlFor="telefono" className="text-2xl font-black text-white flex items-center gap-3">
                <Phone className="h-7 w-7 text-green-400" />
                Teléfono
              </Label>
              <div className="relative">
                <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                  <Phone className="h-8 w-8 text-green-400" />
                </div>
                <Input
                  id="telefono"
                  value={formData.telefono}
                  onChange={(e) => handleChange('telefono', e.target.value)}
                  disabled={loading}
                  className="pl-20 h-20 text-2xl font-bold bg-slate-900/50 border-slate-700 text-white placeholder:text-slate-500 focus:border-green-500 focus:ring-green-500/20"
                  placeholder="+52 123 456 7890"
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
              disabled={loading}
              className="h-20 px-12 text-2xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-teal-600 hover:from-emerald-500 hover:via-green-500 hover:to-teal-500 text-white shadow-lg shadow-emerald-500/30 hover:shadow-emerald-500/50 transform hover:scale-105 transition-all"
            >
              {loading ? 'Guardando...' : empresa ? 'Actualizar Empresa' : 'Crear Empresa'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}
