'use client'

import { useEffect, useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Server, AlertTriangle, Shield, Activity, Database, Wifi } from 'lucide-react'
import { apiClient } from '@/lib/api-client'

interface DashboardStats {
  assets: { total: number; active: number; critical: number }
  incidents: { total: number; open: number; critical: number }
  events: { total: number; today: number }
  trustScore: { average: number }
}

interface ServiceStatus {
  name: string
  status: 'healthy' | 'degraded' | 'down'
  url: string
}

export default function DashboardPage() {
  const [stats, setStats] = useState<DashboardStats>({
    assets: { total: 0, active: 0, critical: 0 },
    incidents: { total: 0, open: 0, critical: 0 },
    events: { total: 0, today: 0 },
    trustScore: { average: 0 },
  })
  const [loading, setLoading] = useState(true)
  const [services, setServices] = useState<ServiceStatus[]>([
    { name: 'API Gateway', status: 'healthy', url: 'http://localhost:8080' },
    { name: 'CTI Lakehouse', status: 'healthy', url: 'http://localhost:8095' },
    { name: 'Analyst Copilot', status: 'healthy', url: 'http://localhost:8090' },
    { name: 'IoC Parsers', status: 'healthy', url: 'http://localhost:8085' },
    { name: 'Anomaly Detection', status: 'healthy', url: 'http://localhost:8086' },
  ])

  useEffect(() => {
    const fetchStats = async () => {
      setLoading(true)
      try {
        const [assetsRes, incidentsRes] = await Promise.all([
          apiClient.get('/api/v1/assets'),
          apiClient.get('/api/v1/incidents'),
        ])
        const assets = assetsRes.data.data || []
        const incidents = incidentsRes.data.data || []
        setStats({
          assets: {
            total: assets.length,
            active: assets.filter((a: any) => a.status === 'active').length,
            critical: assets.filter((a: any) => a.criticality === 'critical').length,
          },
          incidents: {
            total: incidents.length,
            open: incidents.filter((i: any) => i.status === 'open').length,
            critical: incidents.filter((i: any) => i.severity === 'critical').length,
          },
          events: { total: 1547, today: 89 },
          trustScore: { average: 72 },
        })
      } catch {
        // Use demo data when API is unavailable
        setStats({
          assets: { total: 24, active: 18, critical: 3 },
          incidents: { total: 7, open: 3, critical: 2 },
          events: { total: 1547, today: 89 },
          trustScore: { average: 72 },
        })
      } finally {
        setLoading(false)
      }
    }
    fetchStats()
  }, [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">SOC Overview</h1>
        <p className="text-muted-foreground">ZK-XDR Graph Platform Dashboard</p>
      </div>

      {loading && (
        <div className="flex items-center gap-2 text-sm text-muted-foreground">
          <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
          Loading dashboard data...
        </div>
      )}

      <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Assets</CardTitle>
            <Server className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.assets.total}</div>
            <p className="text-xs text-muted-foreground">
              {stats.assets.active} active, {stats.assets.critical} critical
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Open Incidents</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.incidents.open}</div>
            <p className="text-xs text-muted-foreground">
              {stats.incidents.critical} critical severity
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Security Events</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.events.today}</div>
            <p className="text-xs text-muted-foreground">events today</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Avg Trust Score</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.trustScore.average}/100</div>
            <p className="text-xs text-muted-foreground">across all assets</p>
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Recent Incidents</CardTitle>
            <CardDescription>Latest security incidents</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { title: 'Suspicious IoT Camera Beaconing', severity: 'high', status: 'open' },
                { title: 'API Credential Stuffing', severity: 'critical', status: 'investigating' },
                { title: 'QR Phishing Campaign', severity: 'high', status: 'contained' },
              ].map((incident, i) => (
                <div key={i} className="flex items-center justify-between">
                  <div>
                    <p className="font-medium">{incident.title}</p>
                  </div>
                  <div className="flex gap-2">
                    <Badge variant={incident.severity === 'critical' ? 'destructive' : 'warning'}>
                      {incident.severity}
                    </Badge>
                    <Badge variant="outline">{incident.status}</Badge>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Asset Trust Distribution</CardTitle>
            <CardDescription>Assets by trust score range</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[
                { range: 'High Trust (80-100)', count: 12, color: 'bg-green-500' },
                { range: 'Medium Trust (60-79)', count: 8, color: 'bg-yellow-500' },
                { range: 'Low Trust (40-59)', count: 3, color: 'bg-orange-500' },
                { range: 'Critical (<40)', count: 1, color: 'bg-red-500' },
              ].map((item, i) => (
                <div key={i} className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>{item.range}</span>
                    <span className="font-medium">{item.count}</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted">
                    <div
                      className={`h-2 rounded-full ${item.color}`}
                      style={{ width: `${(item.count / 24) * 100}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>System Status</CardTitle>
          <CardDescription>Service health overview</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-2 lg:grid-cols-3">
            {services.map((service) => (
              <div key={service.name} className="flex items-center justify-between rounded-lg border p-3">
                <div className="flex items-center gap-3">
                  {service.status === 'healthy' ? (
                    <Wifi className="h-4 w-4 text-green-500" />
                  ) : service.status === 'degraded' ? (
                    <Wifi className="h-4 w-4 text-yellow-500" />
                  ) : (
                    <Wifi className="h-4 w-4 text-red-500" />
                  )}
                  <div>
                    <p className="text-sm font-medium">{service.name}</p>
                    <p className="text-xs text-muted-foreground">{service.url}</p>
                  </div>
                </div>
                <Badge variant={service.status === 'healthy' ? 'success' : service.status === 'degraded' ? 'warning' : 'destructive'}>
                  {service.status}
                </Badge>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
