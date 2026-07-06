export type IoCType = 'ip_address' | 'domain' | 'url' | 'file_hash_md5' | 'file_hash_sha1' | 'file_hash_sha256' | 'email_address' | 'cve'
export type TLP = 'white' | 'green' | 'amber' | 'red'

export interface CTIIndicator {
  id: string
  indicator_id: string
  type: IoCType
  value: string
  confidence: number
  source?: string
  tlp: TLP
  first_seen?: string
  last_seen?: string
  tags?: string[]
  mitre_tactics?: string[]
  description?: string
  is_active: boolean
  created_at: string
  updated_at: string
}
