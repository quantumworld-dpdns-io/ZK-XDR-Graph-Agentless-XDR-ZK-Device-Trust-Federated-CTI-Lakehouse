export type AssetType = 'endpoint' | 'iot' | 'server' | 'vdi' | 'cloud' | 'network' | 'mobile'
export type AssetStatus = 'active' | 'inactive' | 'quarantined' | 'decommissioned'
export type Criticality = 'low' | 'medium' | 'high' | 'critical'

export interface Asset {
  id: string
  tenant_id: string
  name: string
  asset_type: AssetType
  serial_number?: string
  manufacturer?: string
  model?: string
  firmware_version?: string
  os?: string
  ip_addresses?: string[]
  mac_address?: string
  network_segment?: string
  criticality: Criticality
  status: AssetStatus
  trust_score: number
  last_seen_at?: string
  created_at: string
  updated_at: string
}

export interface AssetStats {
  total: number
  active: number
  inactive: number
  quarantined: number
  critical: number
}
