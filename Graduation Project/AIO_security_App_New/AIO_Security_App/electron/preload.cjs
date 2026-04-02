/* eslint-disable */
const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('api', {
	getSettings: () => ipcRenderer.invoke('get-settings'),
	saveSettings: (keys) => ipcRenderer.invoke('save-settings', keys),
	getSandboxSettings: () => ipcRenderer.invoke('get-sandbox-settings'),
	saveSandboxSettings: (settings) => ipcRenderer.invoke('save-sandbox-settings', settings),
	scanIOCs: (payload) => ipcRenderer.invoke('scan-iocs', payload),
	scanSandbox: (payload) => ipcRenderer.invoke('scan-sandbox', payload),
	cancelScan: (jobId) => ipcRenderer.invoke('cancel-scan', jobId),
	selectFile: () => ipcRenderer.invoke('select-file'),
	exportCsv: (csv) => ipcRenderer.invoke('export-csv', csv),
	exportSandboxJson: (result) => ipcRenderer.invoke('export-sandbox-json', result),
	copyToClipboard: (text) => ipcRenderer.invoke('copy-to-clipboard', text),
	// Renderer-side OCR fallback: read image from clipboard and OCR to text
	pasteImageToText: async () => {
		try {
			const image = await navigator.clipboard.read()
			for (const item of image) {
				if (!item.types) continue
				for (const type of item.types) {
					if (type.startsWith('image/')) {
						const blob = await item.getType(type)
						// Defer-load Tesseract directly in preload
						const mod = await import('tesseract.js').catch(() => null)
						const recognize = mod && (mod.recognize || mod.default?.recognize)
						const ocrText = recognize ? await recognize(blob, 'eng').then(r => String(r?.data?.text || '').trim()).catch(() => '') : ''
						return ocrText || ''
					}
				}
			}
			return ''
		} catch {
			return ''
		}
	},
	onScanProgress: (callback) => {
		const handler = (event, data) => callback(data)
		ipcRenderer.on('scan-progress', handler)
		return () => ipcRenderer.removeListener('scan-progress', handler)
	},
	onSandboxProgress: (callback) => {
		const handler = (event, data) => callback(data)
		ipcRenderer.on('sandbox-progress', handler)
		return () => ipcRenderer.removeListener('sandbox-progress', handler)
	},
	getRateLimits: () => ipcRenderer.invoke('get-rate-limits'),
}) 