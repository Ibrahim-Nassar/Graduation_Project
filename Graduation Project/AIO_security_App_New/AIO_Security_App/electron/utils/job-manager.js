/**
 * Job and cancellation management utility
 * @module electron/utils/job-manager
 */

/**
 * Manages active job controllers for cancellation
 */
class JobManager {
	constructor() {
		/** @type {Map<string, AbortController[]>} */
		this.jobControllers = new Map()
	}

	/**
	 * Registers controllers for a job
	 * @param {string} jobId - Unique job identifier
	 * @param {AbortController[]} controllers - Array of abort controllers
	 */
	registerJob(jobId, controllers) {
		this.jobControllers.set(jobId, controllers)
	}

	/**
	 * Cancels a specific job by ID
	 * @param {string} jobId - Job to cancel
	 * @returns {boolean} True if job was found and cancelled
	 */
	cancelJob(jobId) {
		const controllers = this.jobControllers.get(jobId)
		if (!controllers) {
			return false
		}

		for (const controller of controllers) {
			try {
				controller.abort()
			} catch (err) {
				// Abort might throw if already aborted, which is fine
				console.warn(`Error aborting controller for job ${jobId}:`, err.message)
			}
		}

		this.jobControllers.delete(jobId)
		return true
	}

	/**
	 * Cancels all active jobs
	 * @returns {number} Number of jobs cancelled
	 */
	cancelAllJobs() {
		let cancelledCount = 0

		for (const [jobId, controllers] of this.jobControllers.entries()) {
			for (const controller of controllers) {
				try {
					controller.abort()
					cancelledCount++
				} catch (err) {
					console.warn(`Error aborting controller for job ${jobId}:`, err.message)
				}
			}
		}

		this.jobControllers.clear()
		return cancelledCount
	}

	/**
	 * Gets the number of active jobs
	 * @returns {number}
	 */
	getActiveJobCount() {
		return this.jobControllers.size
	}

	/**
	 * Checks if a job is active
	 * @param {string} jobId - Job ID to check
	 * @returns {boolean}
	 */
	hasJob(jobId) {
		return this.jobControllers.has(jobId)
	}
}

// Singleton instance
const jobManager = new JobManager()

export { jobManager, JobManager }

