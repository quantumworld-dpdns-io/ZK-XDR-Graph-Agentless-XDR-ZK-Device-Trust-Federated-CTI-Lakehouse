'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'

const events = [
  { time: '13:00:00', source: 'ddi', type: 'dns.query.suspicious', severity: 'medium', description: 'IoT Camera 042 queried strange-domain.example' },
  { time: '13:02:15', source: 'zk', type: 'zk.device.attestation.failed', severity: 'critical', description: 'ZK attestation expired for IoT Camera 042' },
  { time: '13:05:30', source: 'waf', type: 'waf.anomaly.detected', severity: 'high', description: 'API credential stuffing from 203.0.113.42' },
  { time: '13:08:45', source: 'cti', type: 'cti.ioc_match', severity: 'high', description: 'Domain matched IOC cluster (confidence: 82%)' },
  { time: '13:10:00', source: 'mail', type: 'email.phishing.detected', severity: 'high', description: 'QR phishing email campaign detected' },
  { time: '13:12:30', source: 'endpoint', type: 'endpoint.process.suspicious', severity: 'medium', description: 'Suspicious process on workstation 003' },
]

export default function TimelinePage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Event Timeline</h1>
        <p className="text-muted-foreground">Chronological view of security events</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Timeline</CardTitle>
          <CardDescription>Events from the current incident</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="relative space-y-6">
            <div className="absolute left-4 top-0 bottom-0 w-0.5 bg-border" />
            {events.map((event, i) => (
              <div key={i} className="relative flex items-start gap-4 pl-8">
                <div className={`absolute left-2.5 top-1.5 h-3 w-3 rounded-full border-2 ${
                  event.severity === 'critical' ? 'bg-red-500 border-red-500' :
                  event.severity === 'high' ? 'bg-orange-500 border-orange-500' :
                  'bg-yellow-500 border-yellow-500'
                }`} />
                <div className="flex-1 space-y-1">
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-muted-foreground">{event.time}</span>
                    <Badge variant="outline" className="text-xs">{event.source}</Badge>
                    <Badge variant={event.severity === 'critical' ? 'destructive' : 'secondary'} className="text-xs">
                      {event.severity}
                    </Badge>
                  </div>
                  <p className="text-sm font-medium">{event.type}</p>
                  <p className="text-sm text-muted-foreground">{event.description}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
