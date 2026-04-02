import Store from 'electron-store';
import { randomUUID } from 'node:crypto';

const store = new Store({ name: 'cases' });
const historyStore = new Store({ name: 'ioc-history' });

/**
 * @typedef {Object} Case
 * @property {string} id
 * @property {string} name
 * @property {string} createdAt
 * @property {string} updatedAt
 * @property {string} input
 * @property {Array} results
 * @property {Object} filters
 * @property {Object} providers
 */

/**
 * List all cases with optional filtering
 * @returns {Array<Object>} List of case summaries
 */
export function listCases() {
    const cases = store.get('cases', []);
    // Return lightweight summaries to avoid loading everything if possible, 
    // but electron-store reads the whole file anyway.
    return cases.map(c => ({
        id: c.id,
        name: c.name,
        createdAt: c.createdAt,
        updatedAt: c.updatedAt,
        iocCount: c.results ? c.results.length : 0,
        tags: c.tags || []
    })).sort((a, b) => new Date(b.updatedAt).getTime() - new Date(a.updatedAt).getTime());
}

/**
 * Get full case details
 * @param {string} id 
 */
export function getCase(id) {
    const cases = store.get('cases', []);
    return cases.find(c => c.id === id) || null;
}

/**
 * Save or update a case
 * @param {Object} caseData 
 */
export function saveCase(caseData) {
    const cases = store.get('cases', []);
    
    // Validate or generate ID
    if (!caseData.id) {
        caseData.id = randomUUID();
        caseData.createdAt = new Date().toISOString();
    }
    
    caseData.updatedAt = new Date().toISOString();
    
    const idx = cases.findIndex(c => c.id === caseData.id);
    if (idx >= 0) {
        cases[idx] = { ...cases[idx], ...caseData };
    } else {
        cases.push(caseData);
    }
    
    store.set('cases', cases);
    
    // Update History asynchronously
    updateIocHistory(caseData);
    
    return caseData;
}

/**
 * Delete a case
 * @param {string} id 
 */
export function deleteCase(id) {
    const cases = store.get('cases', []);
    const newCases = cases.filter(c => c.id !== id);
    if (newCases.length === cases.length) return false;
    
    store.set('cases', newCases);
    return true;
}

/**
 * Update IOC history index
 * @param {Object} caseData 
 */
function updateIocHistory(caseData) {
    const history = historyStore.get('history', {});
    
    if (caseData.results && Array.isArray(caseData.results)) {
        caseData.results.forEach(result => {
            if (!result.ioc) return;
            
            const entry = {
                caseId: caseData.id,
                caseName: caseData.name,
                timestamp: caseData.updatedAt,
                status: result.status || 'unknown'
            };
            
            if (!history[result.ioc]) {
                history[result.ioc] = [];
            }
            
            // Check if this case is already in history for this IOC to avoid duplicates
            const existingIdx = history[result.ioc].findIndex(h => h.caseId === caseData.id);
            if (existingIdx >= 0) {
                history[result.ioc][existingIdx] = entry;
            } else {
                history[result.ioc].push(entry);
            }
        });
    }
    
    historyStore.set('history', history);
}

/**
 * Check if IOCs have appeared in previous cases
 * @param {string[]} iocs 
 */
export function checkIocHistory(iocs) {
    const history = historyStore.get('history', {});
    const results = {};
    
    for (const ioc of iocs) {
        if (history[ioc]) {
            results[ioc] = history[ioc];
        }
    }
    
    return results;
}




