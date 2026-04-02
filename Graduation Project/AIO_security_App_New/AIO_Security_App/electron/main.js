import { app, BrowserWindow, ipcMain, dialog, clipboard, shell } from 'electron'
import Store from 'electron-store'
import path from 'node:path'
import fs from 'node:fs/promises'
import { fileURLToPath } from 'node:url'
import { scanWithProviders } from './providers/scan.js'
import { scanSandbox } from './providers/sandbox-scan.js'
import { getRateLimitSnapshot } from './net/http.js'
import { jobManager } from './utils/job-manager.js'

const __filename = fileURLToPath(import.meta.url)
const __dirname = path.dirname(__filename)

let mainWindow = null
const store = new Store({ name: 'aio-security-app' })

function getPreloadPath(){
	return path.join(__dirname, 'preload.cjs')
}

async function createWindow(){
	mainWindow = new BrowserWindow({
		width: 1280,
		height: 840,
		minWidth: 1000,
		minHeight: 720,
		backgroundColor: '#0f1115',
		webPreferences: {
			preload: getPreloadPath(),
			contextIsolation: true,
			nodeIntegration: false,
			sandbox: true,
		}
	})

	// Handle window close event
	mainWindow.on('closed', () => {
		mainWindow = null
		// Cancel all active jobs
		jobManager.cancelAllJobs()
	})

	// Handle window close attempt
	mainWindow.on('close', (event) => {
		// Allow the window to close normally
		// Cleanup will happen in the 'closed' event
	})

	const devUrl = process.env.VITE_DEV_SERVER_URL
	if (devUrl){
		await mainWindow.loadURL(devUrl)
		if (process.env.OPEN_DEVTOOLS === '1') {
			mainWindow.webContents.openDevTools({ mode: 'detach' })
		}
	} else {
		await mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
	}
}

app.whenReady().then(async () => {
	await createWindow()
	app.on('activate', () => {
		if (BrowserWindow.getAllWindows().length === 0) void createWindow()
	})
})

app.on('window-all-closed', () => {
	// Cancel all active jobs before quitting
	const cancelled = jobManager.cancelAllJobs()
	if (cancelled > 0) {
		console.log(`Cancelled ${cancelled} active job(s) on app quit`)
	}
	
	// Force quit on all platforms in development
	app.quit()
})

app.on('before-quit', () => {
	// Final cleanup before quitting
	jobManager.cancelAllJobs()
})

// Handle process termination signals
process.on('SIGINT', () => {
	// eslint-disable-next-line no-console
	console.log('Received SIGINT, cleaning up...')
	app.quit()
})

process.on('SIGTERM', () => {
	// eslint-disable-next-line no-console
	console.log('Received SIGTERM, cleaning up...')
	app.quit()
})

// IPC: Settings
ipcMain.handle('get-settings', async () => {
	return store.get('apiKeys', {})
})

ipcMain.handle('save-settings', async (event, keys) => {
	store.set('apiKeys', keys || {})
	return { ok: true }
})

ipcMain.handle('get-sandbox-settings', async () => {
	return store.get('sandboxSettings', {
		preferReputationFirst: true,
		allowThirdPartyUploads: false
	})
})

ipcMain.handle('save-sandbox-settings', async (event, settings) => {
	store.set('sandboxSettings', settings || {})
	return { ok: true }
})

/**
 * Safely send message to renderer without throwing if window is destroyed
 * @param {import('electron').WebContents} webContents
 * @param {string} channel
 * @param {any} payload
 */
function safeSendScan(webContents, channel, payload){
	try{
		if (webContents && !webContents.isDestroyed?.()) {
			webContents.send(channel, payload)
		}
	} catch (err) {
		console.warn(`Failed to send ${channel}:`, err.message)
	}
}

ipcMain.handle('scan-iocs', async (event, payload) => {
	const { iocs, providers, jobId } = payload || {}
	if (!Array.isArray(iocs) || iocs.length === 0) {
		return []
	}
	const apiKeys = store.get('apiKeys', {})
	const controllers = []
	jobManager.registerJob(jobId, controllers)
	
	// Cache sender
	const wc = event.sender
	// If the renderer is destroyed during a job, cancel controllers to prevent stray work
	try { 
		wc.once?.('destroyed', () => {
			jobManager.cancelJob(jobId)
		}) 
	} catch (err) {
		console.warn('Failed to attach destroyed listener:', err.message)
	}
	
	// Set up progress callback for real-time updates
	const onProgress = (iocIndex, provider, result) => {
		safeSendScan(wc, 'scan-progress', { jobId, iocIndex, provider, result })
	}
	
	try{
		const results = await scanWithProviders(iocs, providers, apiKeys, controllers, onProgress)
		return results
	} finally {
		jobManager.cancelJob(jobId)
	}
})

ipcMain.handle('scan-sandbox', async (event, payload) => {
	const { type, input, providers, settings, jobId } = payload || {}
	if (!type || !input) {
		throw new Error('Missing required parameters for sandbox scan')
	}
	
	const apiKeys = store.get('apiKeys', {})
	const controllers = []
	jobManager.registerJob(jobId, controllers)
	
	// Cache sender
	const wc = event.sender
	try { 
		wc.once?.('destroyed', () => {
			jobManager.cancelJob(jobId)
		}) 
	} catch (err) {
		console.warn('Failed to attach destroyed listener:', err.message)
	}
	
	// Set up progress callback for real-time updates
	const onProgress = (progressData) => {
		safeSendScan(wc, 'sandbox-progress', progressData)
	}
	
	try {
		const result = await scanSandbox({ type, input, providers, settings, jobId }, apiKeys, controllers, onProgress)
		return result
	} finally {
		jobManager.cancelJob(jobId)
	}
})

ipcMain.handle('cancel-scan', async (event, jobId) => {
	const cancelled = jobManager.cancelJob(jobId)
	if (!cancelled) {
		console.warn(`Attempted to cancel non-existent job: ${jobId}`)
	}
	return { cancelled }
})

ipcMain.handle('select-file', async (event) => {
	const win = BrowserWindow.fromWebContents(event.sender)
	const { canceled, filePaths } = await dialog.showOpenDialog(win, {
		title: 'Select File for Analysis',
		filters: [
			{ name: 'All Files', extensions: ['*'] },
			{ name: 'Executables', extensions: ['exe', 'dll', 'scr', 'com', 'bat', 'cmd', 'msi'] },
			{ name: 'Documents', extensions: ['pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx'] },
			{ name: 'Archives', extensions: ['zip', 'rar', '7z', 'tar', 'gz'] },
			{ name: 'Scripts', extensions: ['js', 'py', 'ps1', 'vbs', 'bat', 'cmd'] }
		],
		properties: ['openFile']
	})
	
	if (canceled || !filePaths || filePaths.length === 0) {
		return { canceled: true }
	}
	
	const filePath = filePaths[0]
	const fileName = path.basename(filePath)
	
	try {
		const stats = await fs.stat(filePath)
		return {
			canceled: false,
			filePath,
			fileName,
			fileSize: stats.size
		}
	} catch (error) {
		throw new Error(`Failed to read file: ${error.message}`)
	}
})

ipcMain.handle('export-csv', async (event, csv) => {
	const win = BrowserWindow.fromWebContents(event.sender)
	const { canceled, filePath } = await dialog.showSaveDialog(win, {
		title: 'Save Results CSV',
		defaultPath: `ioc-results-${new Date().toISOString().replace(/[:.]/g,'-')}.csv`,
		filters: [{ name: 'CSV', extensions: ['csv'] }]
	})
	if (canceled || !filePath) return { canceled: true }
	await fs.writeFile(filePath, csv, 'utf-8')
	
	// Automatically open the CSV file with the default application
	try {
		await shell.openPath(filePath)
	} catch (error) {
		console.warn('Failed to open CSV file:', error)
	}
	
	return { canceled: false, filePath }
})

ipcMain.handle('export-sandbox-json', async (event, result) => {
	const win = BrowserWindow.fromWebContents(event.sender)
	const { canceled, filePath } = await dialog.showSaveDialog(win, {
		title: 'Save Sandbox Results',
		defaultPath: `sandbox-results-${new Date().toISOString().replace(/[:.]/g,'-')}.json`,
		filters: [{ name: 'JSON', extensions: ['json'] }]
	})
	if (canceled || !filePath) return { canceled: true }
	
	const jsonData = JSON.stringify(result, null, 2)
	await fs.writeFile(filePath, jsonData, 'utf-8')
	
	// Automatically open the JSON file with the default application
	try {
		await shell.openPath(filePath)
	} catch (error) {
		console.warn('Failed to open JSON file:', error)
	}
	
	return { canceled: false, filePath }
})

ipcMain.handle('copy-to-clipboard', async (event, text) => {
	clipboard.writeText(String(text || ''))
})

ipcMain.handle('get-rate-limits', async () => {
	try{ return getRateLimitSnapshot() }catch{ return {} }
}) 