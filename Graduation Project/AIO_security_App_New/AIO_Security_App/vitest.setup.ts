import '@testing-library/jest-dom'
import { afterAll, afterEach, beforeAll } from 'vitest'
import { setupServer } from 'msw/node'

// Browser-side MSW is not needed here; renderer tests run in jsdom without real network
// For completeness, we keep a node server to intercept axios/fetch if used in tests
const server = setupServer()

beforeAll(() => server.listen({ onUnhandledRequest: 'bypass' }))
afterEach(() => server.resetHandlers())
afterAll(() => server.close()) 