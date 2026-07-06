export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved' | 'closed'
export type IncidentType = 'suspicious_iot_beaconing' | 'identity_compromise' | 'api_abuse' | 'ddos_attack' | 'quishing_bec' | 'malware_detection'

export interface Incident {
  id: string
  tenant_id: string
  title: string
  description?: string
  incident_type: IncidentType
  severity: Severity
  status: IncidentStatus
  risk_score: number
  evidence?: EvidenceItem[]
  mitre_tactics?: string[]
  mitre_techniques?: string[]
  assigned_to?: string
  assigned_at?: string
  resolved_at?: string
  playbook_id?: string
  created_at: string
  updated_at: string
}

export interface EvidenceItem {
  type: string
  description: string
  timestamp: string
  source: string
}

export interface IncidentStats {
  total: number
  open: number
  investigating: number
  critical: number
}
