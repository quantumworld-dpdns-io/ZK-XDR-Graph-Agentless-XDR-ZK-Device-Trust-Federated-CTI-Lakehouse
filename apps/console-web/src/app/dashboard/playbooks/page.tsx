'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'

const playbooks = [
  { id: 'pb_001', name: 'Low Trust Device Quarantine', trigger: 'zk.device.attestation.failed', status: 'active', lastRun: '2026-07-06T13:00:00Z' },
  { id: 'pb_002', name: 'Suspicious DNS Response', trigger: 'dns.query.suspicious', status: 'active', lastRun: '2026-07-06T13:05:00Z' },
  { id: 'pb_003', name: 'API Abuse Rate Limit', trigger: 'waf.anomaly.detected', status: 'active', lastRun: '2026-07-06T13:10:00Z' },
  { id: 'pb_004', name: 'DDoS Mitigation', trigger: 'waf.ddos.detected', status: 'inactive', lastRun: null },
  { id: 'pb_005', name: 'Quishing/BEC Response', trigger: 'email.phishing.detected', status: 'active', lastRun: '2026-07-06T12:30:00Z' },
]

export default function PlaybooksPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">SOAR Playbooks</h1>
        <p className="text-muted-foreground">Automated response playbooks</p>
      </div>
      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
        {playbooks.map((pb) => (
          <Card key={pb.id}>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="text-lg">{pb.name}</CardTitle>
                <Badge variant={pb.status === 'active' ? 'success' : 'secondary'}>
                  {pb.status}
                </Badge>
              </div>
              <CardDescription>Trigger: {pb.trigger}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Last run: {pb.lastRun ? new Date(pb.lastRun).toLocaleString() : 'Never'}
                </p>
                <div className="flex gap-2">
                  <Button variant="outline" size="sm">Dry Run</Button>
                  <Button size="sm">Execute</Button>
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  )
}
