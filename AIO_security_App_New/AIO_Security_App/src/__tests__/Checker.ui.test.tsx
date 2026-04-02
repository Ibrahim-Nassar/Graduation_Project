import React from 'react'
import { describe, it, expect, vi } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Checker from '../pages/Checker'
import Settings from '../pages/Settings'
import { ToastProvider } from '../context/ToastContext'

let progressCb: ((data: any) => void) | null = null

// Mock window.api
const mockApi = {
	scanIOCs: vi.fn(async ({ iocs, jobId }) => {
		// Emit progress for all providers and both IOCs
		setTimeout(() => {
			const providers = ['virustotal','abuseipdb','otx','threatfox']
			for (let i = 0; i < iocs.length; i++){
				for (const p of providers){
					progressCb && progressCb({ jobId, iocIndex: i, provider: p, result: { provider: p, status: 'clean', score: 10 } })
				}
			}
		}, 10)
		// Resolve final results later
		return new Promise(resolve => setTimeout(() => resolve(iocs.map((v: string) => ({ ioc: v, type: 'ip', status: 'clean', score: 10, providers: {} }))), 50))
	}),
	onScanProgress: vi.fn((cb) => {
		progressCb = cb
		return () => { progressCb = null }
	}),
	cancelScan: vi.fn(),
	exportCsv: vi.fn(),
	copyToClipboard: vi.fn(),
	getRateLimits: vi.fn(async () => ({})),
	getSettings: vi.fn(async () => ({})),
	getSandboxSettings: vi.fn(async () => ({ preferReputationFirst: true, allowThirdPartyUploads: true })),
	saveSettings: vi.fn(async () => ({ ok: true })),
	saveSandboxSettings: vi.fn(async () => ({ ok: true })),
}

Object.defineProperty(window, 'api', { value: mockApi })

function AppShell(){
	return (
		<ToastProvider>
			<BrowserRouter>
				<nav>
					<NavLink to="/">Checker</NavLink>
					<NavLink to="/settings">Settings</NavLink>
				</nav>
				<Routes>
					<Route path="/" element={<Checker />} />
					<Route path="/settings" element={<Settings />} />
				</Routes>
			</BrowserRouter>
		</ToastProvider>
	)
}

describe('Checker UI', () => {
	it('runs a scan, navigates away and back without losing state or crashing', async () => {
		render(<AppShell />)
		const textarea = screen.getByPlaceholderText(/Enter your IOCs here/i)
		fireEvent.change(textarea, { target: { value: '8.8.8.8\n1.1.1.1' } })
		fireEvent.click(screen.getByText('Analyze IOCs'))
		// Navigate to settings while in-flight
		fireEvent.click(screen.getByText('Settings'))
		// Navigate back
		fireEvent.click(screen.getByText('Checker'))
		// Wait until results table shows first IOC
		await waitFor(() => expect(screen.getByText('8.8.8.8')).toBeInTheDocument())
		// Ensure input preserved
		expect((screen.getByPlaceholderText(/Enter your IOCs here/i) as HTMLTextAreaElement).value).toContain('8.8.8.8')
	})
}) 