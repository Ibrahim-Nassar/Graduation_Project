module.exports = {
	parserOptions: {
		tsconfigRootDir: __dirname,
		project: ['./tsconfig.json'],
	},
	rules: {
		// Base JS
		'no-console': ['warn', { allow: ['warn', 'error'] }],
		'no-async-promise-executor': 'error',
		'no-unsafe-optional-chaining': 'error',
	},
	overrides: [
		{
			files: ['src/**/*.{ts,tsx}', 'electron/**/*.{ts,tsx}'],
			parser: '@typescript-eslint/parser',
			plugins: ['@typescript-eslint', 'react-hooks'],
			rules: {
				'@typescript-eslint/no-explicit-any': 'error',
				'@typescript-eslint/no-floating-promises': 'error',
				'react-hooks/exhaustive-deps': 'warn',
			},
		},
		{
			files: ['**/*.{js,cjs}'],
			rules: {
				'no-console': ['warn', { allow: ['warn', 'error', 'log'] }],
			}
		},
		{
			files: ['**/*.test.{ts,tsx}'],
			parser: '@typescript-eslint/parser',
			plugins: ['@typescript-eslint'],
			rules: {
				'@typescript-eslint/no-explicit-any': 'off'
			}
		}
	],
	ignorePatterns: [
		'release/**',
		'dist/**',
		'coverage/**',
		'node_modules/**',
		'e2e/**',
		'playwright.config.ts',
		'vitest.setup.ts',
		'vitest.node.setup.ts',
		'vite.config.ts',
		'testlib/**',
		'electron/net/http.js',
		'electron/preload.cjs'
	]
}
