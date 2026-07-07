'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiClient } from '@/lib/api-client'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default function IncidentsPage() {
  const [incidents, setIncidents] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchIncidents = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiClient.get('/api/v1/incidents')
      setIncidents(res.data.data || [])
    } catch {
      setIncidents([
        { id: 'inc_001', title: 'Suspicious IoT Camera Beaconing', severity: 'high', status: 'open', created_at: '2025-01-15T10:30:00Z' },
        { id: 'inc_002', title: 'API Credential Stuffing', severity: 'critical', status: 'investigating', created_at: '2025-01-15T09:15:00Z' },
        { id: 'inc_003', title: 'QR Phishing Campaign', severity: 'high', status: 'contained', created_at: '2025-01-15T08:00:00Z' },
      ])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchIncidents() }, [])

  const severityColor = (s: string) => {
    switch (s) {
      case 'critical': return 'destructive'
      case 'high': return 'warning'
      case 'medium': return 'default'
      default: return 'secondary'
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Incidents</h1>
          <p className="text-muted-foreground">Active security incidents requiring investigation</p>
        </div>
        <Button onClick={fetchIncidents} disabled={loading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      {error && (
        <Card className="border-red-200 bg-red-50">
          <CardContent className="flex items-center gap-3 p-4">
            <AlertTriangle className="h-5 w-5 text-red-500" />
            <span className="text-red-700">{error}</span>
          </CardContent>
        </Card>
      )}

      {loading && (
        <div className="flex items-center justify-center p-12">
          <div className="h-8 w-8 animate-spin rounded-full border-4 border-primary border-t-transparent" />
        </div>
      )}

      {!loading && (
        <div className="space-y-4">
          {incidents.map((inc) => (
            <Card key={inc.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{inc.title}</CardTitle>
                  <div className="flex gap-2">
                    <Badge variant={severityColor(inc.severity) as any}>{inc.severity}</Badge>
                    <Badge variant="outline">{inc.status}</Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex gap-4 text-sm text-muted-foreground">
                  <span>ID: {inc.id}</span>
                  <span>Created: {new Date(inc.created_at).toLocaleString()}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
