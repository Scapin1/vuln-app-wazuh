export const HOUR_MS = 3600000
export const DAY_MS = 86400000

const pad2 = number => String(number).padStart(2, '0')

export const alignHour = ms => Math.floor(ms / HOUR_MS) * HOUR_MS

export const fmtDDMM = ms => {
  const date = new Date(ms)
  return `${pad2(date.getDate())}/${pad2(date.getMonth() + 1)}`
}

export const fmtYear = ms => String(new Date(ms).getFullYear())

export const fmtHour = ms => {
  const date = new Date(ms)
  return `${pad2(date.getHours())}:00`
}

/** Devuelve string en formato YYYY-MM-DDTHH:MM (local) para input datetime-local */
export const toLocalDatetimeString = (date) => {
  const d = date || new Date()
  return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`
}

/**
 * Parsea un string de fecha del backend.
 * Si no tiene timezone info (ni Z, ni +, ni offset), asume UTC y agrega Z.
 * Esto corrige el bug donde datetime.utcnow() se serializa sin "Z"
 * y el frontend lo interpreta como hora local.
 */
export const parseServerDate = (dateString) => {
  if (!dateString) return null
  const str = String(dateString)
  const hasTimezone = str.includes('Z') || /[+-]\d{2}:\d{2}$/.test(str)
  return new Date(hasTimezone ? str : str + 'Z')
}

export const fmtDateTime = value => {
  const date = new Date(value)
  return date.toLocaleString('es-CL', {
    day: '2-digit',
    month: '2-digit',
    year: 'numeric',
    hour: '2-digit',
    minute: '2-digit'
  })
}

export const badge = type => {
  if (type === 'detection') return 'NUEVA'
  if (type === 'resolution') return 'RESUELTA'
  return 'MIXTO'
}
