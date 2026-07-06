'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { DataTable } from '@/components/ui/data-table'
import type { Incident } from '@/types'

const columns = [
  { key: 'title', header: 'Title', sortable: true },
  { key: 'incident_type', header: 'Type', sortable: true },
  { key: 'severity', header: 'Severity', sortable: true, cell: (item: Incident) => (
    <Badge variant={item.severity === 'critical' ? 'destructive' : item.severity === 'high' ? 'warning' : 'secondary'}>
      {item.severity}
    </Badge>
  )},
  { key: 'risk_score', header: 'Risk Score', sortable: true, cell: (item: Incident) => (
    <span className={item.risk_score >= 80 ? 'text-red-500 font-bold' : item.risk_score >= 60 ? 'text-yellow-500' : 'text-green-500'}>
      {item.risk_score}/100
    </span>
  )},
  { key: 'status', header: 'Status', sortable: true, cell: (item: Incident) => (
    <Badge variant={item.status === 'open' ? 'destructive' : item.status === 'investigating' ? 'warning' : 'secondary'}>
      {item.status}
    </Badge>
  )},
]

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<Incident[]>([])

  useEffect(() => {
    const fetchIncidents = async () => {
      try {
        const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080'}/api/v1/incidents`, {
          headers: { Authorization: `Bearer ${localStorage.getItem('token') || ''}` },
        })
        const data = await res.json()
        setIncidents(data.data || [])
      } catch {
        setIncidents([
          { id: '1', tenant_id: 't1', title: 'Suspicious IoT Camera Beaconing', incident_type: 'suspicious_iot_beaconing', severity: 'high', status: 'open', risk_score: 91, created_at: '', updated_at: '' },
          { id: '2', tenant_id: 't1', title: 'API Credential Stuffing', incident_type: 'api_abuse', severity: 'critical', status: 'investigating', risk_score: 85, created_at: '', updated_at: '' },
          { id: '3', tenant_id: 't1', title: 'QR Phishing Campaign', incident_type: 'quishing_bec', severity: 'high', status: 'contained', risk_score: 78, created_at: '', updated_at: '' },
        ])
      }
    }
    fetchIncidents()
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Incidents</h1>
        <p className="text-muted-foreground">Security incidents requiring investigation</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Active Incidents</CardTitle>
          <CardDescription>{incidents.length} incidents</CardDescription>
        </CardHeader>
        <CardContent>
          <DataTable columns={columns} data={incidents} searchable searchKeys={['title', 'incident_type']} onRowClick={(item) => window.location.href = `/dashboard/incidents/${item.id}`} />
        </CardContent>
      </Card>
    </div>
  )
}
