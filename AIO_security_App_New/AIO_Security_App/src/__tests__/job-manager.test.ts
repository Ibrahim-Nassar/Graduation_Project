/* @vitest-environment node */
import { describe, it, expect, beforeEach } from 'vitest'
import { JobManager } from '../../electron/utils/job-manager.js'

describe('JobManager', () => {
	let manager: JobManager

	beforeEach(() => {
		manager = new JobManager()
	})

	describe('registerJob', () => {
		it('registers a new job with controllers', () => {
			const controllers = [new AbortController(), new AbortController()]
			manager.registerJob('job-1', controllers)

			expect(manager.hasJob('job-1')).toBe(true)
			expect(manager.getActiveJobCount()).toBe(1)
		})

		it('replaces existing job with same ID', () => {
			const controllers1 = [new AbortController()]
			const controllers2 = [new AbortController(), new AbortController()]
			
			manager.registerJob('job-1', controllers1)
			manager.registerJob('job-1', controllers2)

			expect(manager.getActiveJobCount()).toBe(1)
		})
	})

	describe('cancelJob', () => {
		it('cancels a specific job and aborts its controllers', () => {
			const controller1 = new AbortController()
			const controller2 = new AbortController()
			manager.registerJob('job-1', [controller1, controller2])

			const result = manager.cancelJob('job-1')

			expect(result).toBe(true)
			expect(controller1.signal.aborted).toBe(true)
			expect(controller2.signal.aborted).toBe(true)
			expect(manager.hasJob('job-1')).toBe(false)
		})

		it('returns false when cancelling non-existent job', () => {
			const result = manager.cancelJob('non-existent')
			expect(result).toBe(false)
		})

		it('handles already aborted controllers gracefully', () => {
			const controller = new AbortController()
			controller.abort()
			
			manager.registerJob('job-1', [controller])

			const result = manager.cancelJob('job-1')

			expect(result).toBe(true)
			expect(manager.hasJob('job-1')).toBe(false)
		})
	})

	describe('cancelAllJobs', () => {
		it('cancels all active jobs', () => {
			const controller1 = new AbortController()
			const controller2 = new AbortController()
			const controller3 = new AbortController()
			
			manager.registerJob('job-1', [controller1])
			manager.registerJob('job-2', [controller2, controller3])

			const count = manager.cancelAllJobs()

			expect(count).toBe(3)
			expect(controller1.signal.aborted).toBe(true)
			expect(controller2.signal.aborted).toBe(true)
			expect(controller3.signal.aborted).toBe(true)
			expect(manager.getActiveJobCount()).toBe(0)
		})

		it('returns 0 when no jobs are active', () => {
			const count = manager.cancelAllJobs()
			expect(count).toBe(0)
		})
	})

	describe('getActiveJobCount', () => {
		it('returns correct count of active jobs', () => {
			expect(manager.getActiveJobCount()).toBe(0)

			manager.registerJob('job-1', [new AbortController()])
			expect(manager.getActiveJobCount()).toBe(1)

			manager.registerJob('job-2', [new AbortController()])
			expect(manager.getActiveJobCount()).toBe(2)

			manager.cancelJob('job-1')
			expect(manager.getActiveJobCount()).toBe(1)

			manager.cancelAllJobs()
			expect(manager.getActiveJobCount()).toBe(0)
		})
	})

	describe('hasJob', () => {
		it('returns true for registered jobs', () => {
			manager.registerJob('job-1', [new AbortController()])
			expect(manager.hasJob('job-1')).toBe(true)
		})

		it('returns false for non-existent jobs', () => {
			expect(manager.hasJob('non-existent')).toBe(false)
		})

		it('returns false after job is cancelled', () => {
			manager.registerJob('job-1', [new AbortController()])
			manager.cancelJob('job-1')
			expect(manager.hasJob('job-1')).toBe(false)
		})
	})
})

