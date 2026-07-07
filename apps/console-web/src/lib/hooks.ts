'use client'

import { useEffect, useState, useCallback } from 'react'
import { apiClient } from '@/lib/api-client'

interface UseApiOptions<T> {
  immediate?: boolean
  fallback?: T
}

interface UseApiResult<T> {
  data: T | null
  loading: boolean
  error: string | null
  refetch: () => Promise<void>
}

export function useApi<T>(fetcher: () => Promise<{ data: T }>, options: UseApiOptions<T> = {}): UseApiResult<T> {
  const { immediate = true, fallback = null } = options
  const [data, setData] = useState<T | null>(fallback)
  const [loading, setLoading] = useState(immediate)
  const [error, setError] = useState<string | null>(null)

  const fetchData = useCallback(async () => {
    setLoading(true)
    setError(null)
    try {
      const res = await fetcher()
      setData(res.data)
    } catch (err: any) {
      setError(err?.message || 'Failed to fetch data')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (immediate) {
      fetchData()
    }
  }, [immediate, fetchData])

  return { data, loading, error, refetch: fetchData }
}

// Asset hooks
export function useAssets() {
  return useApi<any[]>(() => apiClient.get('/api/v1/assets').then(r => ({ data: r.data.data || [] })), {
    fallback: [],
  })
}

export function useIncidents() {
  return useApi<any[]>(() => apiClient.get('/api/v1/incidents').then(r => ({ data: r.data.data || [] })), {
    fallback: [],
  })
}

export function useCTIIndicators() {
  return useApi<any[]>(() => apiClient.get('/api/v1/cti/indicators').then(r => ({ data: r.data.data || [] })), {
    fallback: [],
  })
}

export function usePlaybooks() {
  return useApi<any[]>(() => apiClient.get('/api/v1/playbooks').then(r => ({ data: r.data.data || [] })), {
    fallback: [],
  })
}

// Copilot hooks
export function useCopilotQuery() {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const query = useCallback(async (question: string) => {
    setLoading(true)
    setError(null)
    try {
      const res = await apiClient.post('http://localhost:8090/api/v1/copilot/query', { query: question })
      return res.data
    } catch (err: any) {
      setError(err?.message || 'Failed to query copilot')
      return null
    } finally {
      setLoading(false)
    }
  }, [])

  return { query, loading, error }
}
