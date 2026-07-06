'use client'

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card'

export default function GraphPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-3xl font-bold">Asset Risk Graph</h1>
        <p className="text-muted-foreground">Visual representation of asset relationships</p>
      </div>
      <Card>
        <CardHeader>
          <CardTitle>Graph View</CardTitle>
          <CardDescription>Asset-to-threat relationship visualization</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex h-96 items-center justify-center rounded-lg border bg-muted/50">
            <div className="text-center space-y-2">
              <p className="text-lg font-medium">Graph Visualization</p>
              <p className="text-sm text-muted-foreground">
                Connect to Neo4j to visualize asset relationships
              </p>
              <div className="flex justify-center gap-4 mt-4">
                <div className="text-center">
                  <div className="h-12 w-12 rounded-full bg-blue-500/20 flex items-center justify-center mx-auto mb-1">
                    <span className="text-xs font-bold text-blue-500">ASSET</span>
                  </div>
                  <p className="text-xs">Devices</p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 rounded-full bg-green-500/20 flex items-center justify-center mx-auto mb-1">
                    <span className="text-xs font-bold text-green-500">IP</span>
                  </div>
                  <p className="text-xs">Addresses</p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 rounded-full bg-yellow-500/20 flex items-center justify-center mx-auto mb-1">
                    <span className="text-xs font-bold text-yellow-500">DOMAIN</span>
                  </div>
                  <p className="text-xs">Domains</p>
                </div>
                <div className="text-center">
                  <div className="h-12 w-12 rounded-full bg-red-500/20 flex items-center justify-center mx-auto mb-1">
                    <span className="text-xs font-bold text-red-500">IOC</span>
                  </div>
                  <p className="text-xs">Threat Intel</p>
                </div>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
