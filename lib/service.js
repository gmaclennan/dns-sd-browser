/**
 * Service data type for discovered DNS-SD services.
 * @module
 */

/**
 * @typedef {object} Service
 * @property {string} name - Instance name (e.g. "My Printer")
 * @property {string} type - Service type (e.g. "_http._tcp")
 * @property {string} protocol - Transport protocol ("tcp" or "udp")
 * @property {string} domain - Domain (default "local")
 * @property {string} host - Target hostname (e.g. "printer.local")
 * @property {number} port - Port number
 * @property {string[]} addresses - IPv4 and IPv6 addresses
 * @property {Record<string, string | true>} txt - Parsed TXT key-value pairs
 * @property {Record<string, Uint8Array>} txtRaw - Raw TXT record values
 * @property {string} fqdn - Fully qualified service name
 * @property {string[]} subtypes - Service subtypes
 * @property {number} updatedAt - Timestamp of last update (ms)
 */

/**
 * Parse TXT record data (array of Uint8Array strings) into key-value pairs.
 *
 * Per RFC 6763 §6.3:
 * - Format is "key=value" where value is the part after the first '='
 * - Keys without '=' are boolean flags (value is `true`)
 * - Duplicate keys: only the first occurrence is used
 * - Keys are case-insensitive but we preserve original casing
 *
 * @param {Uint8Array[]} txtData
 * @returns {{ txt: Record<string, string | true>, txtRaw: Record<string, Uint8Array> }}
 */
export function parseTxtData(txtData) {
  /** @type {Record<string, string | true>} */
  const txt = {}
  /** @type {Record<string, Uint8Array>} */
  const txtRaw = {}
  /** @type {Set<string>} - Lowercase keys seen so far for duplicate detection */
  const seenKeys = new Set()
  const decoder = new TextDecoder()

  for (const entry of txtData) {
    // RFC 6763 §6.1: a single zero-length string is the "no service-defined
    // data" sentinel, not a boolean key. Skip it before key parsing.
    if (entry.byteLength === 0) continue

    const str = decoder.decode(entry)
    const eqIndex = str.indexOf('=')

    // RFC 6763 §6.4: strings beginning with '=' (missing key) MUST be silently ignored
    if (eqIndex === 0) continue

    if (eqIndex === -1) {
      // Boolean flag — key present without value (RFC 6763 §6.4)
      const key = str
      const keyLower = key.toLowerCase()
      if (!seenKeys.has(keyLower)) {
        seenKeys.add(keyLower)
        txt[key] = true
        txtRaw[key] = entry
      }
    } else {
      const key = str.slice(0, eqIndex)
      const value = str.slice(eqIndex + 1)
      const keyLower = key.toLowerCase()
      // Only first occurrence of a key is valid (RFC 6763 §6.4)
      if (!seenKeys.has(keyLower)) {
        seenKeys.add(keyLower)
        txt[key] = value
        txtRaw[key] = entry.slice(eqIndex + 1)
      }
    }
  }

  return { txt, txtRaw }
}

/**
 * Parse a service type string into its components.
 *
 * Accepts either:
 * - Full form: "_http._tcp" or "_http._tcp.local"
 * - Object form: { name: "http", protocol: "tcp" }
 *
 * @param {string | { name: string, protocol?: string }} serviceType
 * @returns {{ type: string, protocol: string, domain: string, queryName: string }}
 */
export function parseServiceType(serviceType) {
  if (typeof serviceType === 'object') {
    if (!serviceType || typeof serviceType.name !== 'string' || !serviceType.name) {
      throw new Error('Service type object must have a non-empty "name" property')
    }
    const name = serviceType.name.startsWith('_')
      ? serviceType.name
      : `_${serviceType.name}`
    const protocol = serviceType.protocol || 'tcp'
    const proto = protocol.startsWith('_') ? protocol : `_${protocol}`
    const type = `${name}.${proto}`
    return {
      type,
      protocol: proto.slice(1),
      domain: 'local',
      queryName: `${type}.local`,
    }
  }

  if (typeof serviceType !== 'string' || !serviceType) {
    throw new Error('Service type must be a non-empty string (e.g. "_http._tcp") or an object { name, protocol? }')
  }

  // String form: "_http._tcp" or "_http._tcp.local"
  const parts = serviceType.split('.')
  let type, domain

  if (parts.length >= 3 && parts[parts.length - 1] === 'local') {
    // "_http._tcp.local" → type = "_http._tcp", domain = "local"
    domain = parts[parts.length - 1]
    type = parts.slice(0, -1).join('.')
  } else {
    // "_http._tcp" → default domain "local"
    type = serviceType
    domain = 'local'
  }

  // Extract protocol from type (second label, defaults to tcp)
  const typeLabels = type.split('.')
  const protocol = typeLabels.length >= 2 ? typeLabels[1].replace(/^_/, '') : 'tcp'

  return {
    type,
    protocol,
    domain,
    queryName: `${type}.${domain}`,
  }
}

/**
 * Extract the instance name from a fully qualified service name.
 *
 * Given "My Service._http._tcp.local" and type "_http._tcp",
 * returns "My Service".
 *
 * @param {string} fqdn
 * @param {string} serviceType - e.g. "_http._tcp.local"
 * @returns {string}
 */
export function extractInstanceName(fqdn, serviceType) {
  // The instance name is everything before the service type
  const suffix = '.' + serviceType
  if (fqdn.endsWith(suffix)) {
    return fqdn.slice(0, -suffix.length)
  }
  // Fallback: return the full fqdn
  return fqdn
}
