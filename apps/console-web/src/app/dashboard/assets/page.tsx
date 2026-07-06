'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { DataTable } from '@/components/ui/data-table'
import type { Asset } from '@/types'

const columns = [
  { key: 'name', header: 'Name', sortable: true },
  { key: 'asset_type', header: 'Type', sortable: true },
  { key: 'network_segment', header: 'Network', sortable: true },
  { key: 'trust_score', header: 'Trust Score', sortable: true, cell: (item: Asset) => (
    <span className={item.trust_score < 60 ? 'text-red-500 font-bold' : item.trust_score < 80 ? 'text-yellow-500' : 'text-green-500'}>
      {item.trust_score}/100
    </span>
  )},
  { key: 'criticality', header: 'Criticality', sortable: true, cell: (item: Asset) => (
    <Badge variant={item.criticality === 'critical' ? 'destructive' : item.criticality === 'high' ? 'warning' : 'secondary'}>
      {item.criticality}
    </Badge>
  )},
  { key: 'status', header: 'Status', sortable: true, cell: (item: Asset) => (
    <Badge variant={item.status === 'active' ? 'success' : item.status === 'quarantined' ? 'destructive' : 'secondary'}>
      {item.status}
    </Badge>
  )},
]

export default function AssetsPage() {
  const [assets, setAssets] = useState<Asset[]>([])

  useEffect(() => {
    const fetchAssets = async () => {
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'}/api/v1/assets`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token') || ''}` },
        })
        const data = await res.json()
        setAssets(data.data || [])
      } catch {
        setAssets([
          { id: '1', tenant_id: 't1', name: 'IoT Camera 042', asset_type: 'iot', trust_score: 45, criticality: 'high', status: 'quarantined', network_segment: 'finance-iot', created_at: '', updated_at: '' },
          { id: '2', tenant_id: 't1', name: 'Workstation 003', asset_type: 'endpoint', trust_score: 72, criticality: 'critical', status: 'active', network_segment: 'finance', created_at: '', updated_at: '' },
          { id: '3', tenant_id: 't1', name: 'VDI Pool A', asset_type: 'vdi', trust_score: 88, criticality: 'medium', status: 'active', network_segment: 'engineering', created_at: '', updated_at: '' },
        ])
      }
    }
    fetchAssets()
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Asset Inventory</h1>
        <p className="text-muted-foreground">All managed assets with trust scores</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Assets</CardTitle>
          <CardDescription>{assets.length} assets total</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={assets} searchable searchKeys={['name', 'asset_type', 'network_segment']} onRowClick={(item) => window.location.href = `/dashboard/assets/${item.id}`} />
        </CardContent>
      </Card>
    </div>
  )
}
