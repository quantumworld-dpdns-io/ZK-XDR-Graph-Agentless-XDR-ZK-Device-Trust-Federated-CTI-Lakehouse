*** Settings ***
Library    Collections
Library    RequestsLibrary
Library    OperatingSystem
Library    String
Library    Process

*** Variables ***
${API_BASE_URL}    http://localhost:8080
${CTI_URL}         http://localhost:8095
${COPILOT_URL}     http://localhost:8090
${IOC_PARSERS_URL} http://localhost:8085
${ANOMALY_URL}     http://localhost:8086
${GRAFANA_URL}     http://localhost:3001
${PROMETHEUS_URL}  http://localhost:9090
${REDIS_URL}       http://localhost:6379
${NEO4J_URL}       http://localhost:7474
${CLICKHOUSE_URL}  http://localhost:8123

${TEST_TENANT_ID}  test-tenant-001
${TEST_ASSET_ID}   test-asset-001

*** Keywords ***
API Gateway Is Ready
    ${resp}=    GET    ${API_BASE_URL}/api/v1/health    expected_status=any
    Status Should Be    200    ${resp}

CTI Lakehouse Is Ready
    ${resp}=    GET    ${CTI_URL}/api/v1/health    expected_status=any
    Status Should Be    200    ${resp}

Analyst Copilot Is Ready
    ${resp}=    GET    ${COPILOT_URL}/api/v1/health    expected_status=any
    Status Should Be    200    ${resp}

IoC Parsers Is Ready
    ${resp}=    GET    ${IOC_PARSERS_URL}/api/v1/health    expected_status=any
    Status Should Be    200    ${resp}

Anomaly Detection Is Ready
    ${resp}=    GET    ${ANOMALY_URL}/api/v1/health    expected_status=any
    Status Should Be    200    ${resp}

Prometheus Is Ready
    ${resp}=    GET    ${PROMETHEUS_URL}/api/v1/status/config    expected_status=any
    Status Should Be    200    ${resp}

Grafana Is Ready
    ${resp}=    GET    ${GRAFANA_URL}/api/health    expected_status=any
    Status Should Be    200    ${resp}

Create Session    api    ${API_BASE_URL}    verify=${FALSE}
Create Session    cti    ${CTI_URL}    verify=${FALSE}
Create Session    copilot    ${COPILOT_URL}    verify=${FALSE}

Register Test User
    ${body}=    Create Dictionary    email=test@example.com    password=Test1234!    name=Test User
    ${resp}=    POST On Session    api    /api/v1/auth/register    json=${body}    expected_status=any
    RETURN    ${resp}

Login Test User
    ${body}=    Create Dictionary    email=test@example.com    password=Test1234!
    ${resp}=    POST On Session    api    /api/v1/auth/login    json=${body}    expected_status=any
    RETURN    ${resp}

Get Auth Token
    ${resp}=    Login Test User
    IF    ${resp.status_code} == 200
        ${token}=    Set Variable    ${resp.json()['access_token']}
        RETURN    ${token}
    ELSE
        ${reg_resp}=    Register Test User
        ${login_resp}=    Login Test User
        ${token}=    Set Variable    ${login_resp.json()['access_token']}
        RETURN    ${token}
    END

Create Test Asset
    ${body}=    Create Dictionary
    ...    name=Test IoT Camera
    ...    type=iot
    ...    ip_address=192.168.1.100
    ...    status=active
    ...    criticality=high
    ${resp}=    POST On Session    api    /api/v1/assets    json=${body}    expected_status=any
    RETURN    ${resp}

Create Test Event
    ${body}=    Create Dictionary
    ...    source=ddi
    ...    event_type=dns.query.suspicious
    ...    severity=high
    ...    confidence=85
    ...    risk_score=750
    ...    source_ip=192.168.1.100
    ...    domain=strange-domain.xyz
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${body}    expected_status=any
    RETURN    ${resp}

Create CTI Indicator
    ${body}=    Create Dictionary
    ...    type=ip
    ...    value=198.51.100.23
    ...    threat=APT28 C2 Server
    ...    severity=critical
    ...    confidence=95
    ...    source=manual
    ...    tlp=amber
    ${resp}=    POST On Session    cti    /api/v1/cti/indicators    json=${body}    expected_status=any
    RETURN    ${resp}

Wait For Condition
    [Arguments]    ${condition_keyword}    ${timeout}=30s    ${interval}=2s
    ${end_time}=    Evaluate    time.time() + ${timeout.replace('s','')}    time
    WHILE    True
        ${result}=    Run Keyword And Return Status    ${condition_keyword}
        IF    ${result}    RETURN    ${TRUE}
        ${now}=    Evaluate    time.time()    time
        IF    ${now} > ${end_time}    FAIL    Timeout waiting for condition
        Sleep    ${interval}
    END
