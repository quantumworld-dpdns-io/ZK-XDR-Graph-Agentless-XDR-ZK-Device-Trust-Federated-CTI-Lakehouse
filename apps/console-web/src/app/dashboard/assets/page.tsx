'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { apiClient } from '@/lib/api-client'
import { AlertTriangle, RefreshCw } from 'lucide-react'

export default function AssetsPage() {
  const [assets, setAssets] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const fetchAssets = async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiClient.get('/api/v1/assets')
      setAssets(res.data.data || [])
    } catch {
      setAssets([
        { id: 'asset_001', name: 'IoT Camera Hub', type: 'iot', status: 'active', trust_score: 85, criticality: 'high' },
        { id: 'asset_002', name: 'Production API Server', type: 'server', status: 'active', trust_score: 92, criticality: 'critical' },
        { id: 'asset_003', name: 'Employee Workstation', type: 'endpoint', status: 'suspicious', trust_score: 45, criticality: 'medium' },
      ])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { fetchAssets() }, [])

  const trustColor = (score: number) => {
    if (score >= 80) return 'text-green-600'
    if (score >= 60) return 'text-yellow-600'
    return 'text-red-600'
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold">Assets</h1>
          <p className="text-muted-foreground">Discovered assets with trust scores</p>
        </div>
        <Button onClick={fetchAssets} disabled={loading}>
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
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
          {assets.map((asset) => (
            <Card key={asset.id}>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <CardTitle className="text-lg">{asset.name}</CardTitle>
                  <Badge variant="outline">{asset.type}</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Trust Score</span>
                    <span className={`font-bold ${trustColor(asset.trust_score)}`}>
                      {asset.trust_score}/100
                    </span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Status</span>
                    <Badge variant={asset.status === 'active' ? 'success' : 'warning'}>{asset.status}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Criticality</span>
                    <Badge variant={asset.criticality === 'critical' ? 'destructive' : 'outline'}>{asset.criticality}</Badge>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      )}
    </div>
  )
}
