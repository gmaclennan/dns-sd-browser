/** mDNS multicast IPv4 address (RFC 6762 §3) */
export const MDNS_ADDRESS = '224.0.0.251'

/** mDNS multicast IPv6 address (RFC 6762 §3) */
export const MDNS_ADDRESS_V6 = 'FF02::FB'

/** mDNS default port (RFC 6762 §3) */
export const MDNS_PORT = 5353

/** mDNS multicast TTL — must be 255 per RFC 6762 §11 */
export const MDNS_TTL = 255

/** Meta-query name for service type enumeration (RFC 6763 §9) */
export const SERVICE_TYPE_ENUMERATION = '_services._dns-sd._udp.local'

/** Default domain for mDNS */
export const DEFAULT_DOMAIN = 'local'
