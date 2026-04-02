#!/usr/bin/env node

import { scanWithProviders } from './electron/providers/scan.js'
import { detectIocType } from './electron/utils/ioc-detection.js'

async function readStdin() {
	let data = ''

	for await (const chunk of process.stdin) {
		data += chunk
	}

	return data.trim()
}

function writeJson(value, exitCode = 0) {
	process.stdout.write(`${JSON.stringify(value, null, 2)}\n`)
	process.exitCode = exitCode
}

function usage() {
	return [
		'Usage:',
		`node ioc_service.js <<< '{"ioc":"8.8.8.8","providers":{"virustotal":true}}'`,
		'',
		'Input JSON format:',
		'{"ioc":"8.8.8.8","providers":{"virustotal":true},"apiKeys":{"virustotal":"..."}}',
	].join('\n')
}

async function runScanQuietly(ioc, providers, apiKeys) {
	const originalLog = console.log

	try {
		// The existing backend logs progress/debug lines to stdout.
		// Silence them here so this wrapper always emits JSON only.
		console.log = () => {}
		return await scanWithProviders([ioc], providers, apiKeys, [], null)
	} finally {
		console.log = originalLog
	}
}

async function main() {
	try {
		const input = await readStdin()

		if (!input) {
			writeJson({ error: 'No JSON payload received on stdin', usage: usage() }, 1)
			return
		}

		let payload
		try {
			payload = JSON.parse(input)
		} catch (error) {
			writeJson(
				{
					error: 'Invalid JSON payload',
					message: error instanceof Error ? error.message : String(error),
					usage: usage(),
				},
				1
			)
			return
		}

		const ioc = String(payload?.ioc ?? '').trim()
		const providers = payload?.providers && typeof payload.providers === 'object' ? payload.providers : {}
		const apiKeys = payload?.apiKeys && typeof payload.apiKeys === 'object' ? payload.apiKeys : {}

		if (!ioc) {
			writeJson({ error: 'Missing required field: ioc' }, 1)
			return
		}

		const detectedType = detectIocType(ioc)
		if (detectedType === 'unknown') {
			writeJson(
				{
					ioc,
					type: detectedType,
					status: 'invalid',
					score: 0,
					providers: {},
					errors: ['Invalid IOC'],
				},
				1
			)
			return
		}

		const results = await runScanQuietly(ioc, providers, apiKeys)
		writeJson(results[0] ?? { ioc, type: detectedType, status: 'unknown', score: 0, providers: {} })
	} catch (error) {
		writeJson(
			{
				error: 'IOC scan failed',
				message: error instanceof Error ? error.message : String(error),
			},
			1
		)
	}
}

void main()
