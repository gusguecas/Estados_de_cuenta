export interface PaymentAlert {
  cuenta: string
  dias: number
  empresa?: string
  tipo: 'empresa' | 'personal'
}

export async function requestNotificationPermission(): Promise<NotificationPermission> {
  if (!('Notification' in window)) {
    console.log('Este navegador no soporta notificaciones')
    return 'denied'
  }

  if (Notification.permission === 'granted') {
    return 'granted'
  }

  if (Notification.permission !== 'denied') {
    const permission = await Notification.requestPermission()
    return permission
  }

  return Notification.permission
}

export function sendPaymentNotification(alert: PaymentAlert) {
  if (!('Notification' in window)) {
    return
  }

  if (Notification.permission !== 'granted') {
    return
  }

  const urgencyEmoji = alert.dias === 0 ? '🚨' : alert.dias === 1 ? '⚠️' : '📅'
  const timeText = alert.dias === 0 ? 'HOY' : alert.dias === 1 ? 'MAÑANA' : `en ${alert.dias} días`

  const title = `${urgencyEmoji} Pago ${timeText}`
  const body = alert.empresa
    ? `${alert.cuenta} - ${alert.empresa}`
    : alert.cuenta

  try {
    new Notification(title, {
      body,
      icon: '/logo.png',
      badge: '/logo.png',
      tag: `payment-${alert.cuenta}`,
      requireInteraction: alert.dias === 0, // Solo requiere interacción si es hoy
      vibrate: alert.dias === 0 ? [200, 100, 200] : undefined,
    })
  } catch (error) {
    console.error('Error al enviar notificación:', error)
  }
}

export function sendMultiplePaymentNotifications(alerts: PaymentAlert[]) {
  if (alerts.length === 0) return

  // Enviar notificación solo si hay pagos urgentes (≤3 días)
  const urgentAlerts = alerts.filter(a => a.dias <= 3)

  if (urgentAlerts.length === 0) return

  if (Notification.permission !== 'granted') {
    return
  }

  // Si hay múltiples alertas, enviar una notificación resumen
  if (urgentAlerts.length > 1) {
    const title = `⚠️ ${urgentAlerts.length} Pagos Urgentes`
    const body = urgentAlerts
      .slice(0, 3)
      .map(a => {
        const time = a.dias === 0 ? 'Hoy' : a.dias === 1 ? 'Mañana' : `${a.dias}d`
        return `${time}: ${a.cuenta}`
      })
      .join('\n')

    try {
      new Notification(title, {
        body,
        icon: '/logo.png',
        badge: '/logo.png',
        tag: 'payment-summary',
        requireInteraction: urgentAlerts.some(a => a.dias === 0),
      })
    } catch (error) {
      console.error('Error al enviar notificación:', error)
    }
  } else {
    // Si solo hay una, enviar notificación individual
    sendPaymentNotification(urgentAlerts[0])
  }
}
