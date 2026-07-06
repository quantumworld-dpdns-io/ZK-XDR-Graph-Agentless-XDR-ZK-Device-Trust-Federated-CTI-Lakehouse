export interface XDREvent {
  id: string
  event_id: string
  tenant_id: string
  source: string
  event_type: string
  severity: string
  asset_id?: string
  device_id?: string
  identity_id?: string
  observed_at: string
  raw?: Record<string, unknown>
  normalized?: Record<string, unknown>
  risk_score?: number
  risk_factors?: string[]
  collector?: string
  pipeline?: string
  created_at: string
}

export interface Playbook {
  id: string
  name: string
  description?: string
  version: string
  trigger_type?: string
  is_active: boolean
  created_at: string
  updated_at: string
}
