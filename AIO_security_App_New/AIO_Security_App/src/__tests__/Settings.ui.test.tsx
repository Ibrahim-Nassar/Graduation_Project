import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import Settings from '../pages/Settings'
import { ToastProvider } from '../context/ToastContext'

// Mock window.api
const mockApi = {
	getSettings: vi.fn(async () => ({ virustotal: 'vt_abc' })),
	saveSettings: vi.fn(async () => ({ ok: true })),
	getSandboxSettings: vi.fn(async () => ({ 
		preferReputationFirst: true, 
		allowThirdPartyUploads: false 
	})),
	saveSandboxSettings: vi.fn(async () => ({ ok: true }))
}

Object.defineProperty(window, 'api', { value: mockApi })

function TestWrapper({ children }: { children: React.ReactNode }) {
	return (
		<ToastProvider>
			{children}
		</ToastProvider>
	)
}

describe('Settings UI', () => {
	it('saves API keys', async () => {
		render(<Settings />, { wrapper: TestWrapper })
		
		const vt = await screen.findByPlaceholderText('vt_xxx')
		fireEvent.change(vt, { target: { value: 'vt_abc' } })
		fireEvent.click(screen.getByText('Save'))
		await waitFor(() => expect(mockApi.saveSettings).toHaveBeenCalled())
	})
}) 