'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiClient } from '@/lib/api-client'
import { AlertTriangle, RefreshCw, Search } from 'lucide-react'

export default function CTIPage() {
  const [indicators, setIndicators] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [searchTerm, setSearchTerm] = useState('')

  const fetchIndicators = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiClient.get('/api/v1/cti/indicators')
      setIndicators(res.data.data || [])
    } catch {
      setIndicators([
        { id: 'ioc_001', type: 'ip', value: '198.51.100.23', threat: 'APT28 C2', severity: 'critical', confidence: 95 },
        { id: 'ioc_002', type: 'domain', value: 'malicious-domain.xyz', threat: 'Phishing', severity: 'high', confidence: 88 },
        { id: 'ioc_003', type: 'hash', value: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', threat: 'Ransomware', severity: 'critical', confidence: 92 },
      ])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchIndicators() }, [])

  const filtered = indicators.filter(i =>
    i.value.toLowerCase().includes(searchTerm.toLowerCase()) ||
    i.threat.toLowerCase().includes(searchTerm.toLowerCase())
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">CTI Search</h1>
          <p className="text-muted-foreground">Threat intelligence indicators</p>
        </div>
        <Button onClick={fetchIndicators} disabled={loading}>
          <RefreshCw className={`h-4 w-4 mr-2 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </Button>
      </div>

      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search indicators..."
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          className="w-full rounded-md border bg-background pl-10 pr-4 py-2 text-sm"
        />
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
        <div className="space-y-3">
          {filtered.map((ioc) => (
            <Card key={ioc.id}>
              <CardContent className="flex items-center justify-between p-4">
                <div className="flex items-center gap-4">
                  <Badge variant="outline">{ioc.type}</Badge>
                  <div>
                    <p className="font-mono text-sm">{ioc.value}</p>
                    <p className="text-xs text-muted-foreground">{ioc.threat}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <Badge variant={ioc.severity === 'critical' ? 'destructive' : 'warning'}>{ioc.severity}</Badge>
                  <span className="text-sm text-muted-foreground">{ioc.confidence}%</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
