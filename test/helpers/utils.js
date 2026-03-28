import { createSocket } from 'node:dgram'

/**
 * Network interface to use for multicast in tests.
 *
 * Windows does not support multicast on the loopback interface (127.0.0.1),
 * so we use 0.0.0.0 there, which lets the OS pick a real interface.
 * On Linux/macOS, loopback keeps test traffic off the network entirely.
 */
export const TEST_INTERFACE = process.platform === 'win32' ? '0.0.0.0' : '127.0.0.1'

/**
 * Get a random available UDP port by briefly binding to port 0.
 * @returns {Promise<number>}
 */
export async function getRandomPort() {
  return new Promise((resolve, reject) => {
    const socket = createSocket('udp4')
    socket.bind(0, () => {
      const { port } = socket.address()
      socket.close(() => resolve(port))
    })
    socket.on('error', reject)
  })
}

/**
 * Pull the next event from an async iterator, with a timeout.
 * @template T
 * @param {AsyncIterableIterator<T>} iterator
 * @param {number} [timeoutMs=3000]
 * @returns {Promise<T>}
 */
export async function nextEvent(iterator, timeoutMs = 3000) {
  /** @type {ReturnType<typeof setTimeout> | undefined} */
  let timer
  const result = await Promise.race([
    iterator.next(),
    new Promise((_, reject) => {
      timer = setTimeout(
        () => reject(new Error(`Timed out waiting for event after ${timeoutMs}ms`)),
        timeoutMs
      )
    }),
  ])
  clearTimeout(timer)
  if (result.done) {
    throw new Error('Iterator ended before producing an event')
  }
  return result.value
}

/**
 * Collect N events from an async iterator.
 * @template T
 * @param {AsyncIterableIterator<T>} iterator
 * @param {number} count
 * @param {number} [timeoutMs=5000]
 * @returns {Promise<T[]>}
 */
export async function collectEvents(iterator, count, timeoutMs = 5000) {
  const events = []
  for (let i = 0; i < count; i++) {
    events.push(await nextEvent(iterator, timeoutMs))
  }
  return events
}

/**
 * Wait for a specified number of milliseconds.
 * @param {number} ms
 * @returns {Promise<void>}
 */
export function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
