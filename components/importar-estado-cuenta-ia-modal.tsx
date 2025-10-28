'use client'

import { useState } from 'react'
import { useAuth } from '@/lib/auth-context'
import { createMovimiento, getCuenta } from '@/lib/firestore'
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
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from '@/components/ui/table'
import { Upload, FileText, Sparkles, CheckCircle2, XCircle, Loader2 } from 'lucide-react'
import { Badge } from '@/components/ui/badge'

interface ImportarEstadoCuentaIAModalProps {
  open: boolean
  onClose: () => void
  cuentaId: string
  onSuccess: () => void
}

interface Transaccion {
  fecha: string
  descripcion: string
  referencia: string | null
  cargo: number
  abono: number
  saldo: number
  tipo: string
}

interface ResultadoIA {
  banco: string
  cuenta: string
  titular: string
  periodo_inicio: string
  periodo_fin: string
  saldo_inicial: number
  saldo_final: number
  total_cargos: number
  total_abonos: number
  empresa: string
  num_transacciones: number
  transacciones: Transaccion[]
  procesado_con_ia: boolean
  modelo_ia: string
}

export function ImportarEstadoCuentaIAModal({
  open,
  onClose,
  cuentaId,
  onSuccess
}: ImportarEstadoCuentaIAModalProps) {
  const { user } = useAuth()
  const [loading, setLoading] = useState(false)
  const [file, setFile] = useState<File | null>(null)
  const [resultado, setResultado] = useState<ResultadoIA | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [importando, setImportando] = useState(false)

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      setFile(e.target.files[0])
      setResultado(null)
      setError(null)
    }
  }

  const procesarConIA = async () => {
    if (!file || !user) return

    try {
      setLoading(true)
      setError(null)

      // Obtener nombre de la cuenta/empresa
      const cuenta = await getCuenta(cuentaId)
      const empresaNombre = cuenta?.nombre || 'Mi Empresa'

      const formData = new FormData()
      formData.append('pdf', file)
      formData.append('empresa', empresaNombre)

      // En desarrollo usa Flask local, en producción usará la API de Next.js
      const apiUrl = process.env.NODE_ENV === 'development'
        ? 'http://localhost:5001/api/procesar'
        : '/api/procesar-pdf'

      // Flask necesita la API key en el form data
      if (process.env.NODE_ENV === 'development') {
        const apiKey = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY
        if (apiKey) {
          formData.append('api_key', apiKey)
        }
      }

      const response = await fetch(apiUrl, {
        method: 'POST',
        body: formData
      })

      const data = await response.json()

      if (data.error) {
        setError(data.error + (data.detalle ? `: ${data.detalle}` : ''))
        return
      }

      setResultado(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error al procesar el PDF')
      console.error('Error:', err)
    } finally {
      setLoading(false)
    }
  }

  const importarTransacciones = async () => {
    if (!resultado || !user) return

    try {
      setImportando(true)

      let importadas = 0
      let errores = 0

      // Función para redondear a 2 decimales y evitar errores de precisión
      const roundMoney = (value: number) => Math.round(value * 100) / 100

      for (const tx of resultado.transacciones) {
        try {
          const monto = tx.abono > 0 ? tx.abono : -tx.cargo
          const tipo = monto > 0 ? 'ingreso' : 'egreso'

          await createMovimiento(user.uid, cuentaId, {
            fecha: tx.fecha,
            descripcion: tx.descripcion,
            monto: roundMoney(Math.abs(monto)),
            tipo: tipo as 'ingreso' | 'egreso',
            notas: tx.referencia ? `Ref: ${tx.referencia} - Tipo: ${tx.tipo}` : `Tipo: ${tx.tipo}`
          })

          importadas++
        } catch (err) {
          console.error('Error al importar transacción:', tx, err)
          errores++
        }
      }

      alert(`✅ Importación completada!\n\n${importadas} transacciones importadas\n${errores} errores`)
      onSuccess()
      onClose()
      resetForm()
    } catch (err) {
      console.error('Error al importar:', err)
      alert('Error al importar las transacciones')
    } finally {
      setImportando(false)
    }
  }

  const resetForm = () => {
    setFile(null)
    setResultado(null)
    setError(null)
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[90vw] max-h-[90vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-purple-950 to-slate-950 border-purple-500/30 shadow-2xl shadow-purple-500/20">
        <DialogHeader className="space-y-4 pb-6 border-b border-purple-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-purple-500 via-pink-500 to-purple-500 shadow-xl shadow-purple-500/30 animate-pulse">
              <Sparkles className="h-10 w-10 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-3xl font-black text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">
                🤖 Importar con IA
              </DialogTitle>
              <DialogDescription className="text-lg text-slate-400 font-semibold mt-1">
                Extrae todas las transacciones automáticamente usando Claude AI
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-6 py-6">
          {/* Upload Section */}
          {!resultado && (
            <div className="space-y-6">
              <div className="grid gap-4">
                <Label htmlFor="pdf" className="text-2xl font-black text-white flex items-center gap-3">
                  <FileText className="h-7 w-7 text-purple-400" />
                  Estado de Cuenta PDF
                </Label>
                <div className="relative">
                  <div className="absolute inset-y-0 left-0 pl-5 flex items-center pointer-events-none">
                    <FileText className="h-8 w-8 text-purple-400" />
                  </div>
                  <Input
                    id="pdf"
                    type="file"
                    accept=".pdf"
                    onChange={handleFileChange}
                    disabled={loading}
                    className="pl-20 h-20 text-xl font-bold bg-slate-900/50 border-slate-700 text-white file:mr-4 file:py-2 file:px-4 file:rounded-lg file:border-0 file:text-lg file:font-bold file:bg-purple-600 file:text-white hover:file:bg-purple-500 focus:border-purple-500 focus:ring-purple-500/20"
                  />
                </div>
                {file && (
                  <div className="p-4 bg-purple-500/10 border-2 border-purple-500/30 rounded-xl">
                    <p className="text-lg text-purple-300 font-semibold">
                      📄 Archivo: <span className="text-white font-black">{file.name}</span>
                    </p>
                    <p className="text-base text-purple-400 mt-1">
                      📦 Tamaño: {(file.size / 1024 / 1024).toFixed(2)} MB
                    </p>
                  </div>
                )}
              </div>

              <div className="p-6 bg-gradient-to-br from-purple-950/50 to-pink-950/50 border-2 border-purple-500/30 rounded-2xl">
                <h3 className="text-xl font-black text-purple-300 mb-3 flex items-center gap-2">
                  <Sparkles className="h-6 w-6" />
                  ¿Cómo funciona?
                </h3>
                <ul className="space-y-2 text-base text-slate-300">
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">1.</span>
                    <span>Sube tu estado de cuenta en PDF (cualquier banco)</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">2.</span>
                    <span>Claude AI analiza el documento y extrae todas las transacciones</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">3.</span>
                    <span>Revisa los datos extraídos antes de importar</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <span className="text-purple-400 font-bold">4.</span>
                    <span>Importa todo con un clic</span>
                  </li>
                </ul>
                <div className="mt-4 pt-4 border-t border-purple-500/20">
                  <p className="text-sm text-purple-400 font-semibold">
                    💰 Costo aproximado: $0.03 - $0.10 USD por estado de cuenta
                  </p>
                </div>
              </div>

              {error && (
                <div className="p-6 bg-red-950/50 border-2 border-red-500/50 rounded-xl flex items-start gap-4">
                  <XCircle className="h-8 w-8 text-red-400 flex-shrink-0 mt-1" />
                  <div>
                    <h4 className="text-xl font-black text-red-300 mb-2">Error al procesar</h4>
                    <p className="text-base text-red-200">{error}</p>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Results Section */}
          {resultado && (
            <div className="space-y-6">
              {/* Summary Cards */}
              <div className="grid grid-cols-4 gap-4">
                <div className="p-4 bg-gradient-to-br from-emerald-950/50 to-green-950/50 border-2 border-emerald-500/30 rounded-xl">
                  <p className="text-sm text-emerald-400 font-bold mb-1">Banco</p>
                  <p className="text-xl font-black text-white">{resultado.banco}</p>
                </div>
                <div className="p-4 bg-gradient-to-br from-blue-950/50 to-cyan-950/50 border-2 border-blue-500/30 rounded-xl">
                  <p className="text-sm text-blue-400 font-bold mb-1">Cuenta</p>
                  <p className="text-xl font-black text-white">{resultado.cuenta}</p>
                </div>
                <div className="p-4 bg-gradient-to-br from-purple-950/50 to-pink-950/50 border-2 border-purple-500/30 rounded-xl">
                  <p className="text-sm text-purple-400 font-bold mb-1">Periodo</p>
                  <p className="text-lg font-black text-white">{resultado.periodo_inicio} → {resultado.periodo_fin}</p>
                </div>
                <div className="p-4 bg-gradient-to-br from-orange-950/50 to-amber-950/50 border-2 border-orange-500/30 rounded-xl">
                  <p className="text-sm text-orange-400 font-bold mb-1">Transacciones</p>
                  <p className="text-3xl font-black text-white">{resultado.num_transacciones}</p>
                </div>
              </div>

              {/* Transactions Table */}
              <div className="border-2 border-purple-500/30 rounded-xl overflow-hidden">
                <div className="bg-gradient-to-r from-purple-950 to-pink-950 p-4 border-b-2 border-purple-500/30">
                  <h3 className="text-xl font-black text-white flex items-center gap-2">
                    <CheckCircle2 className="h-6 w-6 text-emerald-400" />
                    Transacciones Detectadas
                  </h3>
                </div>
                <div className="max-h-[400px] overflow-y-auto bg-slate-900/50">
                  <Table>
                    <TableHeader className="sticky top-0 bg-slate-900 z-10">
                      <TableRow className="border-b-2 border-purple-500/30 hover:bg-slate-800/50">
                        <TableHead className="text-purple-300 font-black">Fecha</TableHead>
                        <TableHead className="text-purple-300 font-black">Descripción</TableHead>
                        <TableHead className="text-purple-300 font-black">Referencia</TableHead>
                        <TableHead className="text-purple-300 font-black text-right">Cargo</TableHead>
                        <TableHead className="text-purple-300 font-black text-right">Abono</TableHead>
                        <TableHead className="text-purple-300 font-black">Tipo</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {resultado.transacciones.map((tx, idx) => (
                        <TableRow key={idx} className="border-b border-purple-500/10 hover:bg-purple-950/20">
                          <TableCell className="font-bold text-white">{tx.fecha}</TableCell>
                          <TableCell className="text-slate-300">{tx.descripcion}</TableCell>
                          <TableCell className="text-slate-400 text-sm">{tx.referencia || '-'}</TableCell>
                          <TableCell className="text-right">
                            {tx.cargo > 0 && (
                              <span className="text-red-400 font-bold">-${tx.cargo.toLocaleString('es-MX', { minimumFractionDigits: 2 })}</span>
                            )}
                          </TableCell>
                          <TableCell className="text-right">
                            {tx.abono > 0 && (
                              <span className="text-emerald-400 font-bold">+${tx.abono.toLocaleString('es-MX', { minimumFractionDigits: 2 })}</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">
                              {tx.tipo}
                            </Badge>
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              </div>

              {/* Summary Stats */}
              <div className="grid grid-cols-3 gap-4">
                <div className="p-6 bg-gradient-to-br from-emerald-950/50 to-green-950/50 border-2 border-emerald-500/30 rounded-xl">
                  <p className="text-base text-emerald-400 font-bold mb-2">Total Abonos</p>
                  <p className="text-3xl font-black text-emerald-300">
                    +${resultado.total_abonos.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                </div>
                <div className="p-6 bg-gradient-to-br from-red-950/50 to-orange-950/50 border-2 border-red-500/30 rounded-xl">
                  <p className="text-base text-red-400 font-bold mb-2">Total Cargos</p>
                  <p className="text-3xl font-black text-red-300">
                    -${resultado.total_cargos.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                </div>
                <div className="p-6 bg-gradient-to-br from-blue-950/50 to-cyan-950/50 border-2 border-blue-500/30 rounded-xl">
                  <p className="text-base text-blue-400 font-bold mb-2">Saldo Final</p>
                  <p className="text-3xl font-black text-blue-300">
                    ${resultado.saldo_final.toLocaleString('es-MX', { minimumFractionDigits: 2 })}
                  </p>
                </div>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="gap-4 pt-8 border-t border-purple-500/20">
          <Button
            type="button"
            variant="outline"
            onClick={() => {
              onClose()
              resetForm()
            }}
            disabled={loading || importando}
            className="h-16 px-10 text-xl font-black border-2 border-slate-600 bg-slate-900/50 text-slate-300 hover:bg-slate-800 hover:text-white"
          >
            Cancelar
          </Button>

          {!resultado ? (
            <Button
              onClick={procesarConIA}
              disabled={!file || loading}
              className="h-16 px-10 text-xl font-black bg-gradient-to-r from-purple-600 via-pink-600 to-purple-600 hover:from-purple-500 hover:via-pink-500 hover:to-purple-500 text-white shadow-lg shadow-purple-500/30 hover:shadow-purple-500/50 transform hover:scale-105 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-3 h-6 w-6 animate-spin" />
                  Procesando con IA...
                </>
              ) : (
                <>
                  <Sparkles className="mr-3 h-6 w-6" />
                  Procesar con IA
                </>
              )}
            </Button>
          ) : (
            <>
              <Button
                onClick={() => {
                  setResultado(null)
                  setFile(null)
                }}
                disabled={importando}
                variant="outline"
                className="h-16 px-10 text-xl font-black border-2 border-purple-500 text-purple-300 hover:bg-purple-950"
              >
                Procesar Otro
              </Button>
              <Button
                onClick={importarTransacciones}
                disabled={importando}
                className="h-16 px-10 text-xl font-black bg-gradient-to-r from-emerald-600 via-green-600 to-emerald-600 hover:from-emerald-500 hover:via-green-500 hover:to-emerald-500 text-white shadow-lg shadow-emerald-500/30 hover:shadow-emerald-500/50 transform hover:scale-105 transition-all"
              >
                {importando ? (
                  <>
                    <Loader2 className="mr-3 h-6 w-6 animate-spin" />
                    Importando...
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="mr-3 h-6 w-6" />
                    Importar {resultado.num_transacciones} Transacciones
                  </>
                )}
              </Button>
            </>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
