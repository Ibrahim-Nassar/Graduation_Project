import { defineConfig } from '@playwright/test'

export default defineConfig({
	testDir: 'e2e',
	reporter: [['list'], ['html', { outputFolder: 'playwright-report' }]],
	timeout: 120000,
	expect: { timeout: 10000 },
	use: {
		trace: 'retain-on-failure',
		screenshot: 'only-on-failure',
		video: 'retain-on-failure',
	},
}) 