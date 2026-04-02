/**
 * Provider execution wrapper with standardized error handling
 * @module electron/utils/provider-wrapper
 */

/**
 * Wraps a provider call with standardized error handling and progress reporting
 * @param {Object} options
 * @param {string} options.providerKey - Provider identifier (e.g., 'virustotal')
 * @param {Function} options.providerFn - Provider function to execute
 * @param {Object} options.apiKeys - All API keys
 * @param {string} options.requiredKeyName - Required API key name
 * @param {string} [options.missingKeyMessage] - Custom message for missing key
 * @param {AbortController[]} options.controllers - Array to push abort controller
 * @param {Function} [options.onProgress] - Progress callback
 * @param {Function} [options.onSuccess] - Success callback
 * @param {Function} [options.onError] - Error callback
 * @returns {Promise<void>}
 */
export async function wrapProviderCall({
	providerKey,
	providerFn,
	apiKeys,
	requiredKeyName,
	missingKeyMessage,
	controllers,
	onProgress,
	onSuccess,
	onError
}) {
	// Check for API key
	if (!apiKeys[requiredKeyName]) {
		const error = {
			provider: providerKey,
			status: 'error',
			score: 0,
			error: missingKeyMessage || `Missing ${providerKey} API key`
		}
		if (onError) {
			onError(error)
		}
		return
	}

	// Create abort controller
	const controller = new AbortController()
	controllers.push(controller)

	try {
		const result = await providerFn(controller.signal)
		const enriched = { provider: providerKey, ...result }
		
		if (onSuccess) {
			onSuccess(enriched)
		}
	} catch (err) {
		const error = {
			provider: providerKey,
			status: 'error',
			score: 0,
			error: String(err?.message || err)
		}
		
		if (onError) {
			onError(error)
		}
	}
}

/**
 * Executes multiple providers in parallel with progress tracking
 * @param {Object} options
 * @param {Object} options.providers - Enabled providers map
 * @param {Array} options.providerConfigs - Provider configurations
 * @param {Object} options.apiKeys - All API keys
 * @param {AbortController[]} options.controllers - Controllers array
 * @param {Function} [options.onProviderProgress] - Per-provider progress callback
 * @returns {Promise<Object>} Results keyed by provider name
 */
export async function executeProviders({
	providers,
	providerConfigs,
	apiKeys,
	controllers,
	onProviderProgress
}) {
	const results = {}
	const promises = []

	for (const config of providerConfigs) {
		if (!providers[config.key]) continue

		const promise = wrapProviderCall({
			providerKey: config.key,
			providerFn: config.fn,
			apiKeys,
			requiredKeyName: config.requiredKey || config.key,
			missingKeyMessage: config.missingKeyMessage,
			controllers,
			onSuccess: (result) => {
				results[config.key] = result
				if (onProviderProgress) {
					onProviderProgress(config.key, result)
				}
			},
			onError: (error) => {
				results[config.key] = error
				if (onProviderProgress) {
					onProviderProgress(config.key, error)
				}
			}
		})

		promises.push(promise)
	}

	await Promise.all(promises)
	return results
}

