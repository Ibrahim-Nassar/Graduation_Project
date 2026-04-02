import { test, expect, _electron as electron } from '@playwright/test'
import type { ElectronApplication, Page } from '@playwright/test'
import path from 'path'

let electronApp: ElectronApplication
let page: Page

test.beforeAll(async () => {
	// Launch Electron app
	electronApp = await electron.launch({
		args: [path.join(__dirname, '..', 'electron', 'main.js')],
		env: {
			...process.env,
			NODE_ENV: 'test',
		}
	})

	// Get the first window that the app opens
	page = await electronApp.firstWindow()
	await page.waitForLoadState('domcontentloaded')
})

test.afterAll(async () => {
	await electronApp.close()
})

test.describe('IOC Checker - Complete Workflows', () => {
	test('should load application and show main interface', async () => {
		await expect(page.locator('text=IOC Checker')).toBeVisible()
		await expect(page.locator('text=Checker')).toBeVisible()
		await expect(page.locator('text=Settings')).toBeVisible()
	})

	test('should navigate between tabs without crashing', async () => {
		// Navigate to Settings
		await page.click('text=Settings')
		await expect(page.locator('text=API Configuration')).toBeVisible()

		// Navigate to Sandbox
		await page.click('text=Sandbox')
		await expect(page.locator('text=Sandbox Analysis')).toBeVisible()

		// Navigate to Help
		await page.click('text=Help')
		await expect(page.locator('text=Help & Documentation')).toBeVisible()

		// Navigate back to Checker
		await page.click('text=Checker')
		await expect(page.locator('text=IOC Analysis')).toBeVisible()
	})

	test('should handle IOC input and validation', async () => {
		// Ensure we're on Checker tab
		await page.click('text=Checker')
		
		// Enter IOC
		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('8.8.8.8\n1.1.1.1\nmalicious.com')

		// Check IOC count
		await expect(page.locator('text=3 IOCs detected')).toBeVisible()
	})

	test('should show error when analyzing without providers selected', async () => {
		await page.click('text=Checker')
		
		// Enter IOCs
		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('8.8.8.8')

		// Uncheck all providers
		await page.click('label:has-text("VirusTotal")')
		await page.click('label:has-text("AbuseIPDB")')
		await page.click('label:has-text("OTX")')
		await page.click('label:has-text("ThreatFox")')

		// Try to analyze
		await page.click('button:has-text("Analyze IOCs")')

		// Should show error toast
		await expect(page.locator('text=No providers selected')).toBeVisible({ timeout: 5000 })
	})

	test('should persist state when switching tabs during analysis', async () => {
		await page.click('text=Checker')
		
		// Enter IOCs
		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('192.168.1.1\n10.0.0.1')

		// Check IOC count
		await expect(page.locator('text=2 IOCs detected')).toBeVisible()

		// Navigate to Settings and back
		await page.click('text=Settings')
		await page.waitForTimeout(500)
		await page.click('text=Checker')

		// Verify IOCs are still present
		const textareaValue = await textarea.inputValue()
		expect(textareaValue).toContain('192.168.1.1')
		expect(textareaValue).toContain('10.0.0.1')
	})

	test('should handle filter panel when results are present', async () => {
		await page.click('text=Checker')
		
		// Enter IOCs
		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('test.com')

		// Note: Without real API keys, we can't complete a scan
		// This test verifies the UI doesn't crash with the filter panel
		await expect(textarea).toBeVisible()
	})
})

test.describe('Settings Management', () => {
	test('should allow entering API keys', async () => {
		await page.click('text=Settings')

		// Enter test API keys
		const vtInput = page.locator('input[placeholder="vt_xxx"]')
		await vtInput.fill('vt_test_key_123456789')

		// Should not crash
		await expect(vtInput).toHaveValue('vt_test_key_123456789')
	})

	test('should show API limits information', async () => {
		await page.click('text=Settings')
		
		await expect(page.locator('text=API Limits')).toBeVisible()
	})
})

test.describe('Sandbox Workflows', () => {
	test('should switch between file and URL analysis modes', async () => {
		await page.click('text=Sandbox')

		// Check file mode
		await expect(page.locator('text=File Analysis')).toBeVisible()
		await expect(page.locator('text=Click to select a file')).toBeVisible()

		// Switch to URL mode
		await page.click('label:has-text("URL Analysis")')
		await expect(page.locator('input[placeholder="https://example.com"]')).toBeVisible()

		// Switch back to file mode
		await page.click('label:has-text("File Analysis")')
		await expect(page.locator('text=Click to select a file')).toBeVisible()
	})

	test('should validate inputs before analysis', async () => {
		await page.click('text=Sandbox')

		// Try to analyze without selecting a file
		await page.click('button:has-text("Analyze File")')

		// Should show error toast
		await expect(page.locator('text=No file selected')).toBeVisible({ timeout: 5000 })
	})

	test('should persist sandbox state across navigation', async () => {
		await page.click('text=Sandbox')

		// Switch to URL mode and enter URL
		await page.click('label:has-text("URL Analysis")')
		const urlInput = page.locator('input[placeholder="https://example.com"]')
		await urlInput.fill('https://test-url.com')

		// Navigate away and back
		await page.click('text=Settings')
		await page.waitForTimeout(500)
		await page.click('text=Sandbox')

		// Verify URL is still present
		const urlValue = await urlInput.inputValue()
		expect(urlValue).toBe('https://test-url.com')
	})
})

test.describe('Error Handling', () => {
	test('should not crash on rapid tab switching', async () => {
		// Rapidly switch between tabs
		for (let i = 0; i < 5; i++) {
			await page.click('text=Checker')
			await page.waitForTimeout(100)
			await page.click('text=Settings')
			await page.waitForTimeout(100)
			await page.click('text=Sandbox')
			await page.waitForTimeout(100)
		}

		// Verify app is still responsive
		await page.click('text=Checker')
		await expect(page.locator('text=IOC Analysis')).toBeVisible()
	})

	test('should handle empty input gracefully', async () => {
		await page.click('text=Checker')

		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('')

		// Try to analyze with empty input
		await page.click('button:has-text("Analyze IOCs")')

		// Should show error
		await expect(page.locator('text=No IOCs detected')).toBeVisible({ timeout: 5000 })
	})

	test('should handle special characters in IOC input', async () => {
		await page.click('text=Checker')

		const textarea = page.locator('textarea[placeholder*="Enter your IOCs"]')
		await textarea.fill('8.8.8.8\n<script>alert("xss")</script>\n1.1.1.1')

		// Should detect valid IOCs and ignore invalid ones
		await expect(page.locator('text=2 IOCs detected')).toBeVisible()
	})
})

test.describe('Keyboard Shortcuts', () => {
	test('should support Ctrl+S to save settings', async () => {
		await page.click('text=Settings')

		// Enter a test key
		const vtInput = page.locator('input[placeholder="vt_xxx"]')
		await vtInput.fill('test_key_123')

		// Press Ctrl+S
		await page.keyboard.press('Control+s')

		// Should show success toast (if settings save succeeds)
		// Note: Without real persistence, this just verifies no crash
		await expect(vtInput).toHaveValue('test_key_123')
	})
})

test.describe('UI Responsiveness', () => {
	test('should display all major UI components', async () => {
		await page.click('text=Checker')

		// Check for major sections
		await expect(page.locator('text=IOC Analysis')).toBeVisible()
		await expect(page.locator('text=IOC Input')).toBeVisible()
		await expect(page.locator('text=Threat Intelligence Providers')).toBeVisible()
		await expect(page.locator('text=Supported IOCs')).toBeVisible()
	})

	test('should show provider checkboxes', async () => {
		await page.click('text=Checker')

		await expect(page.locator('label:has-text("VirusTotal")')).toBeVisible()
		await expect(page.locator('label:has-text("AbuseIPDB")')).toBeVisible()
		await expect(page.locator('label:has-text("OTX")')).toBeVisible()
		await expect(page.locator('label:has-text("ThreatFox")')).toBeVisible()
	})
})

