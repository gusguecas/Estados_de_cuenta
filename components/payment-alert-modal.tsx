'use client'

import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { AlertTriangle, Calendar, CreditCard } from 'lucide-react'

interface PaymentAlert {
  cuenta: string
  dias: number
  empresa?: string
  tipo: 'empresa' | 'personal'
}

interface PaymentAlertModalProps {
  open: boolean
  onClose: () => void
  alerts: PaymentAlert[]
}

export function PaymentAlertModal({ open, onClose, alerts }: PaymentAlertModalProps) {
  if (alerts.length === 0) return null

  const getUrgencyColor = (dias: number) => {
    if (dias === 0) return 'from-red-600 via-orange-600 to-red-600'
    if (dias === 1) return 'from-orange-600 via-amber-600 to-orange-600'
    return 'from-yellow-600 via-amber-600 to-yellow-600'
  }

  const getUrgencyText = (dias: number) => {
    if (dias === 0) return 'HOY'
    if (dias === 1) return 'MAÑANA'
    return `EN ${dias} DÍAS`
  }

  const urgentAlerts = alerts.filter(a => a.dias <= 3)

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-[65vw] max-h-[85vh] overflow-y-auto bg-gradient-to-br from-slate-950 via-red-950 to-slate-950 border-red-500/50 shadow-2xl shadow-red-500/30">
        <DialogHeader className="space-y-4 pb-6 border-b border-red-500/20">
          <div className="flex items-center gap-4">
            <div className="p-4 rounded-2xl bg-gradient-to-br from-red-500 via-orange-500 to-red-500 shadow-xl shadow-red-500/50 animate-pulse">
              <AlertTriangle className="h-12 w-12 text-white" strokeWidth={2.5} />
            </div>
            <div>
              <DialogTitle className="text-4xl font-black text-transparent bg-clip-text bg-gradient-to-r from-red-400 to-orange-400">
                ⚠️ Pagos Urgentes
              </DialogTitle>
              <DialogDescription className="text-xl text-red-300 font-semibold mt-2">
                Tienes {urgentAlerts.length} {urgentAlerts.length === 1 ? 'pago próximo' : 'pagos próximos'}
              </DialogDescription>
            </div>
          </div>
        </DialogHeader>

        <div className="space-y-5 py-6">
          {urgentAlerts.map((alert, index) => (
            <div
              key={index}
              className={`relative overflow-hidden p-6 rounded-2xl border-2 ${
                alert.dias === 0
                  ? 'border-red-500/50 bg-gradient-to-br from-red-500/20 to-orange-500/20'
                  : alert.dias === 1
                  ? 'border-orange-500/50 bg-gradient-to-br from-orange-500/20 to-amber-500/20'
                  : 'border-yellow-500/50 bg-gradient-to-br from-yellow-500/20 to-amber-500/20'
              } backdrop-blur-sm`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-5">
                  <div className={`p-4 rounded-xl bg-gradient-to-br ${getUrgencyColor(alert.dias)} shadow-lg`}>
                    <CreditCard className="h-9 w-9 text-white" strokeWidth={2.5} />
                  </div>
                  <div>
                    <h3 className="text-3xl font-black text-white mb-1">{alert.cuenta}</h3>
                    {alert.empresa && (
                      <p className="text-lg text-white/70 font-semibold">{alert.empresa}</p>
                    )}
                    <p className={`text-base font-bold ${
                      alert.tipo === 'empresa' ? 'text-emerald-400' : 'text-purple-400'
                    }`}>
                      {alert.tipo === 'empresa' ? '🏢 Empresarial' : '👤 Personal'}
                    </p>
                  </div>
                </div>
                <div className="text-right">
                  <div className={`inline-flex items-center gap-3 px-6 py-3 rounded-xl bg-gradient-to-r ${getUrgencyColor(alert.dias)} shadow-lg`}>
                    <Calendar className="h-7 w-7 text-white" strokeWidth={2.5} />
                    <span className="text-3xl font-black text-white">
                      {getUrgencyText(alert.dias)}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex justify-center pt-6 border-t border-red-500/20">
          <Button
            onClick={onClose}
            className="h-16 px-16 text-2xl font-black bg-gradient-to-r from-red-600 via-orange-600 to-red-600 hover:from-red-500 hover:via-orange-500 hover:to-red-500 text-white shadow-lg shadow-red-500/30 hover:shadow-red-500/50 transform hover:scale-105 transition-all"
          >
            Entendido
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  )
}
