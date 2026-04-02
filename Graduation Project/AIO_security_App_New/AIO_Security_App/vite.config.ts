import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
	base: './',
	plugins: [react()],
	server: {
		port: 5173,
		hmr: true,
		watch: {
			ignored: [
				'**/node_modules/**',
				'**/.git/**',
				'**/dist/**',
				'**/build/**',
				'**/coverage/**',
				'**/logs/**',
				'**/outputs/**',
				'**/scans/**',
				'**/*.log'
			]
		}
	},
	build: {
		outDir: 'dist',
		target: 'es2020'
	},
	test: {
		environment: 'jsdom',
		setupFiles: ['./vitest.setup.ts'],
		environmentMatchGlobs: [
			['electron/**', 'node']
		],
		exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
		coverage: {
			reporter: ['text', 'html', 'json-summary'],
			all: true,
			include: ['src/**/*.{ts,tsx}', 'electron/**/*.{js,ts}'],
			branches: 90,
			statements: 90,
			lines: 90,
			functions: 90,
		},
		globals: true,
		css: true
	}
}) 