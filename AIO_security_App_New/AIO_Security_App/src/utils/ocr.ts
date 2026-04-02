/*
	Performs lightweight OCR in the renderer using tesseract.js.
	Uses a dynamic import so the hefty library is only loaded on demand
	when users paste an image.
*/

export async function ocrImageToText(image: Blob | ArrayBuffer | string): Promise<string> {
	try {
		// Dynamically import to keep initial bundle small
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const mod: any = await import('tesseract.js')
		// Support both default and named exports across versions
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		const recognize: any = (mod && (mod.recognize || (mod.default && mod.default.recognize)))
		if (typeof recognize !== 'function') throw new Error('OCR engine not available')
		const result = await recognize(image, 'eng')
		const text: string = String(result?.data?.text || '').trim()
		return text
	} catch (err) {
		return ''
	}
}


