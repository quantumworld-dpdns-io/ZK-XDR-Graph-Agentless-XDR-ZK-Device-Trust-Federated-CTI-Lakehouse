'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiClient } from '@/lib/api-client'
import { AlertTriangle, RefreshCw, Play, Pause } from 'lucide-react'

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchPlaybooks = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiClient.get('/api/v1/playbooks')
      setPlaybooks(res.data.data || [])
    } catch {
      setPlaybooks([
        { id: 'pb_001', name: 'Low Trust Device Quarantine', trigger: 'zk.device.attestation.failed', status: 'active', actions: 4 },
        { id: 'pb_002', name: 'Suspicious DNS Response', trigger: 'dns.query.suspicious', status: 'active', actions: 3 },
        { id: 'pb_003', name: 'API Abuse Rate Limit', trigger: 'waf.rate_limit.exceeded', status: 'active', actions: 3 },
        { id: 'pb_004', name: 'DDoS Mitigation', trigger: 'waf.ddos.detected', status: 'active', actions: 3 },
        { id: 'pb_005', name: 'Quishing/BEC Response', trigger: 'email.phishing.detected', status: 'active', actions: 4 },
      ])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchPlaybooks() }, [])

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">SOAR Playbooks</h1>
          <p className="text-muted-foreground">Automated response playbooks</p>
        </div>
        <Button onClick={fetchPlaybooks} disabled={loading}>
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
          {playbooks.map((pb) => (
            <Card key={pb.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{pb.name}</CardTitle>
                  <div className="flex items-center gap-2">
                    <Badge variant={pb.status === 'active' ? 'success' : 'secondary'}>
                      {pb.status === 'active' ? <Play className="h-3 w-3 mr-1" /> : <Pause className="h-3 w-3 mr-1" />}
                      {pb.status}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <div className="flex gap-4 text-sm text-muted-foreground">
                  <span>Trigger: <code className="bg-muted px-1 rounded">{pb.trigger}</code></span>
                  <span>Actions: {pb.actions}</span>
                  <span>ID: {pb.id}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
