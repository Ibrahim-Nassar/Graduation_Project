import React from 'react'
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import Sandbox from '../pages/Sandbox'
import { ToastProvider } from '../context/ToastContext'

let sandboxProgressCb: ((data: any) => void) | null = null

const mockApi = {
	selectFile: vi.fn(async () => ({
		canceled: false,
		filePath: '/test/malware.exe',
		fileName: 'malware.exe',
		fileSize: 1024000
	})),
	scanSandbox: vi.fn(async ({ jobId }) => {
		// Simulate progress updates
		setTimeout(() => {
			if (sandboxProgressCb) {
				sandboxProgressCb({ 
					jobId, 
					provider: 'virustotal', 
					stage: { stage: 'analyzing', progress: 50 } 
				})
				sandboxProgressCb({ 
					jobId, 
					provider: 'virustotal', 
					result: { 
						provider: 'virustotal', 
						status: 'malicious', 
						score: 85,
						evidence: ['Multiple engines detected threats'],
						raw_ref: 'https://virustotal.com'
					} 
				})
			}
		}, 10)

		return {
			input: 'malware.exe',
			type: 'file',
			status: 'malicious',
			score: 85,
			verdict: 'File is malicious',
			fileInfo: {
				name: 'malware.exe',
				size: 1024000,
				sha256: 'abc123'
			},
			providers: {
				virustotal: { 
					provider: 'virustotal', 
					status: 'malicious', 
					score: 85,
					evidence: ['Multiple engines detected threats'] 
				}
			}
		}
	}),
	onSandboxProgress: vi.fn((cb) => {
		sandboxProgressCb = cb
		return () => { sandboxProgressCb = null }
	}),
	cancelScan: vi.fn(),
	exportSandboxJson: vi.fn(async () => ({ canceled: false })),
	copyToClipboard: vi.fn(),
	getSandboxSettings: vi.fn(async () => ({ 
		preferReputationFirst: true, 
		allowThirdPartyUploads: true // Enable uploads for tests
	}))
}

Object.defineProperty(window, 'api', { value: mockApi, writable: true })

function TestWrapper({ children }: { children: React.ReactNode }) {
	return <ToastProvider>{children}</ToastProvider>
}

describe('Sandbox Component', () => {
	beforeEach(() => {
		vi.clearAllMocks()
		sandboxProgressCb = null
		sessionStorage.clear()
	})

	it('renders file analysis mode by default', () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		expect(screen.getByText('File Analysis')).toBeInTheDocument()
		expect(screen.getByText(/Click to select a file or drag & drop/i)).toBeInTheDocument()
	})

	it('switches between file and URL analysis modes', () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		const urlRadio = screen.getByLabelText(/URL Analysis/i)
		fireEvent.click(urlRadio)
		
		expect(screen.getByPlaceholderText('https://example.com')).toBeInTheDocument()
		expect(screen.queryByText(/Click to select a file/i)).not.toBeInTheDocument()
	})

	it('allows file selection', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(mockApi.selectFile).toHaveBeenCalled()
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
	})

	it('validates file selection before analysis', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText(/No file selected/i)).toBeInTheDocument()
		})
		
		expect(mockApi.scanSandbox).not.toHaveBeenCalled()
	})

	it('validates URL input before analysis', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		const urlRadio = screen.getByLabelText(/URL Analysis/i)
		fireEvent.click(urlRadio)
		
		const analyzeButton = screen.getByText(/Analyze URL/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText(/No URL entered/i)).toBeInTheDocument()
		})
		
		expect(mockApi.scanSandbox).not.toHaveBeenCalled()
	})

	it('validates provider selection before analysis', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select a file
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		// Uncheck all providers
		const vtCheckbox = screen.getByLabelText(/VirusTotal/i) as HTMLInputElement
		const mdCheckbox = screen.getByLabelText(/MetaDefender/i) as HTMLInputElement
		
		fireEvent.click(vtCheckbox)
		fireEvent.click(mdCheckbox)
		
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText(/No providers selected/i)).toBeInTheDocument()
		})
		
		expect(mockApi.scanSandbox).not.toHaveBeenCalled()
	})

	it('performs file analysis and displays results', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		// Start analysis
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		// Wait for results
		await waitFor(() => {
			expect(mockApi.scanSandbox).toHaveBeenCalled()
			expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
			expect(screen.getByText(/Score: 85/)).toBeInTheDocument()
		})
	})

	it('shows progress during analysis', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		// Start analysis
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		// Check for progress indicator
		await waitFor(() => {
			expect(screen.getByText(/Analyzing.../i)).toBeInTheDocument()
		})
	})

	it('allows cancelling analysis', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		// Start analysis
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		// Cancel analysis
		await waitFor(() => {
			const cancelButton = screen.getByText('Cancel')
			fireEvent.click(cancelButton)
		})
		
		await waitFor(() => {
			expect(mockApi.cancelScan).toHaveBeenCalled()
		})
	})

	it('can export results to JSON', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file and run analysis
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
		})
		
		// Export results
		const exportButton = screen.getByText('Export JSON')
		fireEvent.click(exportButton)
		
		await waitFor(() => {
			expect(mockApi.exportSandboxJson).toHaveBeenCalled()
		})
	})

	it('can copy summary to clipboard', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file and run analysis
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
		})
		
		// Copy summary
		const copyButton = screen.getByText('Copy Summary')
		fireEvent.click(copyButton)
		
		await waitFor(() => {
			expect(mockApi.copyToClipboard).toHaveBeenCalled()
		})
	})

	it('persists state across tab navigation', async () => {
		const { unmount } = render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		// Unmount component (simulate navigation away)
		unmount()
		
		// Re-mount component (simulate navigation back)
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Check that file selection persisted
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
	})

	it('clears results when Clear Results button is clicked', async () => {
		render(<Sandbox />, { wrapper: TestWrapper })
		
		// Select file and run analysis
		const dropZone = screen.getByText(/Click to select a file or drag & drop/i).parentElement!
		fireEvent.click(dropZone)
		
		await waitFor(() => {
			expect(screen.getByText('malware.exe')).toBeInTheDocument()
		})
		
		const analyzeButton = screen.getByText(/Analyze File/i)
		fireEvent.click(analyzeButton)
		
		await waitFor(() => {
			expect(screen.getByText('MALICIOUS')).toBeInTheDocument()
		})
		
		// Clear results
		const clearButton = screen.getByText('Clear Results')
		fireEvent.click(clearButton)
		
		// Check that results are cleared
		await waitFor(() => {
			expect(screen.queryByText('MALICIOUS')).not.toBeInTheDocument()
		})
	})
})

