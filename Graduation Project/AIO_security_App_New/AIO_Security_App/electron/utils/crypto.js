import fs from 'node:fs/promises'
import crypto from 'node:crypto'

/**
 * Maximum file size for hash calculation (100MB)
 * Files larger than this should be rejected to prevent memory issues
 */
const MAX_FILE_SIZE = 100 * 1024 * 1024

/**
 * Calculates cryptographic hashes for a file
 * @param {string} filePath - Path to the file
 * @returns {Promise<{sha256: string, md5: string, sha1: string}>} Hash values
 * @throws {Error} If file is too large or cannot be read
 */
export async function calculateFileHash(filePath) {
	// Check file size first before reading
	const stats = await fs.stat(filePath)
	if (stats.size > MAX_FILE_SIZE) {
		throw new Error(`File too large: ${stats.size} bytes (max ${MAX_FILE_SIZE} bytes)`)
	}
	
	const fileBuffer = await fs.readFile(filePath)
	
	return {
		sha256: crypto.createHash('sha256').update(fileBuffer).digest('hex'),
		md5: crypto.createHash('md5').update(fileBuffer).digest('hex'),
		sha1: crypto.createHash('sha1').update(fileBuffer).digest('hex')
	}
}

/**
 * Validates file size before processing
 * @param {string} filePath - Path to the file
 * @param {number} maxSize - Maximum allowed size in bytes
 * @returns {Promise<{size: number, valid: boolean, error?: string}>}
 */
export async function validateFileSize(filePath, maxSize = MAX_FILE_SIZE) {
	try {
		const stats = await fs.stat(filePath)
		if (stats.size > maxSize) {
			return {
				size: stats.size,
				valid: false,
				error: `File exceeds maximum size of ${maxSize} bytes`
			}
		}
		return { size: stats.size, valid: true }
	} catch (error) {
		return {
			size: 0,
			valid: false,
			error: `Failed to validate file: ${error.message}`
		}
	}
}

