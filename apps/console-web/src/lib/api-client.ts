import axios, { AxiosError, InternalAxiosRequestConfig } from 'axios'
import { getSession } from 'next-auth/react'

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8080',
  timeout: 30000,
  headers: {
    'Content-Type': 'application/json',
  },
})

apiClient.interceptors.request.use(async (config: InternalAxiosRequestConfig) => {
  const session = await getSession()
  if ((session as any)?.accessToken) {
    config.headers.Authorization = `Bearer ${(session as any).accessToken}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    if (error.response?.status === 401) {
      if (typeof window !== 'undefined') {
        window.location.href = '/login'
      }
    }
    return Promise.reject(error)
  }
)

export { apiClient }
export default apiClient

export interface ApiResponse<T> {
  data: T
  message?: string
}

export interface PaginatedResponse<T> {
  data: T[]
  total: number
  page: number
  per_page: number
  total_pages: number
}

// Service URLs for microservices
const SERVICES = {
  ctiLakehouse: process.env.NEXT_PUBLIC_CTI_URL || 'http://localhost:8095',
  analystCopilot: process.env.NEXT_PUBLIC_COPILOT_URL || 'http://localhost:8090',
  iocParsers: process.env.NEXT_PUBLIC_IOC_PARSERS_URL || 'http://localhost:8085',
  anomalyDetection: process.env.NEXT_PUBLIC_ANOMALY_URL || 'http://localhost:8086',
}

// CTI Lakehouse API
export const ctiApi = {
  listIoCs: (params?: { page?: number; page_size?: number; ioc_type?: string; severity?: string }) =>
    axios.get(`${SERVICES.ctiLakehouse}/api/v1/iocs`, { params }),

  getIoC: (id: string) =>
    axios.get(`${SERVICES.ctiLakehouse}/api/v1/iocs/${id}`),

  createIoC: (data: any) =>
    axios.post(`${SERVICES.ctiLakehouse}/api/v1/iocs`, data),

  searchIoCs: (query: string) =>
    axios.post(`${SERVICES.ctiLakehouse}/api/v1/iocs/search`, null, { params: { query } }),

  matchIoCs: (values: string[]) =>
    axios.post(`${SERVICES.ctiLakehouse}/api/v1/iocs/match`, values),
}

// Analyst Copilot API
export const copilotApi = {
  query: (question: string, context?: string) =>
    axios.post(`${SERVICES.analystCopilot}/api/v1/copilot/query`, { query: question, context }),

  enrichIndicator: (type: string, value: string) =>
    axios.post(`${SERVICES.analystCopilot}/api/v1/copilot/enrich`, {
      indicator_type: type,
      indicator_value: value,
    }),

  summarizeIncident: (incidentId: string, events: any[]) =>
    axios.post(`${SERVICES.analystCopilot}/api/v1/copilot/summarize`, {
      incident_id: incidentId,
      events,
    }),
}

// IoC Parsers API
export const iocParserApi = {
  parseText: (text: string, source?: string) =>
    axios.post(`${SERVICES.iocParsers}/api/v1/parse`, { text, source }),
}

// Anomaly Detection API
export const anomalyApi = {
  detect: (events: any[]) =>
    axios.post(`${SERVICES.anomalyDetection}/api/v1/detect`, { events }),
}
