'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { DataTable } from '@/components/ui/data-table'
import type { CTIIndicator } from '@/types'

const columns = [
  { key: 'value', header: 'Indicator', sortable: true },
  { key: 'type', header: 'Type', sortable: true },
  { key: 'confidence', header: 'Confidence', sortable: true, cell: (item: CTIIndicator) => (
    <span className={item.confidence >= 80 ? 'text-red-500 font-bold' : item.confidence >= 60 ? 'text-yellow-500' : 'text-green-500'}>
      {item.confidence}%
    </span>
  )},
  { key: 'tlp', header: 'TLP', sortable: true, cell: (item: CTIIndicator) => (
    <Badge variant={item.tlp === 'red' ? 'destructive' : item.tlp === 'amber' ? 'warning' : 'secondary'}>
      {item.tlp}
    </Badge>
  )},
  { key: 'source', header: 'Source', sortable: true },
]

export default function CTIPage() {
  const indicators: CTIIndicator[] = [
    { id: '1', indicator_id: 'ioc_001', type: 'domain', value: 'strange-domain.example', confidence: 82, tlp: 'amber', source: 'federated_sme_cluster', is_active: true, created_at: '', updated_at: '' },
    { id: '2', indicator_id: 'ioc_002', type: 'ip_address', value: '203.0.113.42', confidence: 90, tlp: 'red', source: 'internal_siem', is_active: true, created_at: '', updated_at: '' },
    { id: '3', indicator_id: 'ioc_003', type: 'file_hash_sha256', value: 'abc123...', confidence: 75, tlp: 'amber', source: 'virustotal', is_active: true, created_at: '', updated_at: '' },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">CTI Search</h1>
        <p className="text-muted-foreground">Threat intelligence indicators and enrichment</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Indicators of Compromise</CardTitle>
          <CardDescription>{indicators.length} active indicators</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={indicators} searchable searchKeys={['value', 'source']} />
        </CardContent>
      </Card>
    </div>
  )
}
