import type { IocType } from './ioc';
import type { IocResult, ProviderSelection } from './providers';
import type { IocFilters } from './filters';

export interface IocContext {
  sourceLine: string;
  lineNumber?: number;
  timestamp?: string;
  srcIp?: string;
  dstIp?: string;
  srcPort?: number;
  dstPort?: number;
  username?: string;
  hostname?: string;
}

export interface CaseIoc extends IocResult {
  context?: IocContext;
}

export interface Case {
  id: string;
  name: string;
  createdAt: string; // ISO date string
  updatedAt: string; // ISO date string
  input: string;
  fileName?: string; // If loaded from file
  fileSize?: number;
  providers: ProviderSelection;
  results: CaseIoc[];
  filters: IocFilters;
  tags?: string[];
  description?: string;
}

export interface CaseSummary {
  id: string;
  name: string;
  createdAt: string;
  updatedAt: string;
  iocCount: number;
  maliciousCount: number;
  tags?: string[];
}

export interface IocHistoryEntry {
  caseId: string;
  caseName: string;
  timestamp: string;
  status: 'malicious' | 'suspicious' | 'clean' | 'unknown';
}




