*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions
Test Setup    Reset Demo State

*** Test Cases ***
Phase 1 Reconnaissance - DNS Queries
    [Tags]    e2e    demo    phase1
    [Documentation]    Attacker performs DNS reconnaissance

    # Normal DNS query
    ${event}=    Create Dictionary
    ...    source=ddi
    ...    event_type=dns.query.normal
    ...    severity=info
    ...    confidence=50
    ...    risk_score=200
    ...    source_ip=10.0.0.50
    ...    domain=company.com
    ...    tenant_id=${TEST_TENANT_ID}
    POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any

    # Suspicious DNS query
    ${event2}=    Create Dictionary
    ...    source=ddi
    ...    event_type=dns.query.suspicious
    ...    severity=high
    ...    confidence=80
    ...    risk_score=750
    ...    source_ip=10.0.0.50
    ...    domain=strange-domain.xyz
    ...    tenant_id=${TEST_TENANT_ID}
    POST On Session    api    /api/v1/events/ingest    json=${event2}    expected_status=any

Phase 2 Initial Access - Phishing Email
    [Tags]    e2e    demo    phase2
    [Documentation]    Attacker sends phishing email

    ${event}=    Create Dictionary
    ...    source=mail
    ...    event_type=email.phishing.detected
    ...    severity=high
    ...    confidence=90
    ...    risk_score=850
    ...    source_ip=203.0.113.50
    ...    domain=malicious-domain.xyz
    ...    tenant_id=${TEST_TENANT_ID}
    POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any

Phase 3 Credential Access - Brute Force
    [Tags]    e2e    demo    phase3
    [Documentation]    Attacker attempts credential stuffing

    FOR    ${i}    IN RANGE    7
        ${event}=    Create Dictionary
        ...    source=waf
        ...    event_type=waf.auth.failure
        ...    severity=high
        ...    confidence=75
        ...    risk_score=700
        ...    source_ip=203.0.113.50
        ...    tenant_id=${TEST_TENANT_ID}
        POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any
    END

Phase 4 Lateral Movement - Device Compromise
    [Tags]    e2e    demo    phase4
    [Documentation]    IoT device compromised, ZK attestation fails

    ${event}=    Create Dictionary
    ...    source=zk
    ...    event_type=zk.attestation.failed
    ...    severity=critical
    ...    confidence=95
    ...    risk_score=900
    ...    asset_id=iot-camera-001
    ...    asset_name=IoT Camera Hub
    ...    asset_type=iot
    ...    tenant_id=${TEST_TENANT_ID}
    POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any

Phase 5 Command and Control - DGA Domains
    [Tags]    e2e    demo    phase5
    [Documentation]    DGA domains indicate C2 communication

    FOR    ${i}    IN RANGE    4
        ${event}=    Create Dictionary
        ...    source=ddi
        ...    event_type=dns.query.dga
        ...    severity=critical
        ...    confidence=85
        ...    risk_score=900
        ...    source_ip=192.168.1.100
        ...    domain=xkrjfmalwpqtop.com
        ...    tenant_id=${TEST_TENANT_ID}
        POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any
    END

Phase 6 Exfiltration - DDoS Attack
    [Tags]    e2e    demo    phase6
    [Documentation]    DDoS attack as distraction or exfiltration

    FOR    ${i}    IN RANGE    12
        ${event}=    Create Dictionary
        ...    source=waf
        ...    event_type=waf.rate_limit.exceeded
        ...    severity=critical
        ...    confidence=90
        ...    risk_score=800
        ...    source_ip=203.0.113.50
        ...    tenant_id=${TEST_TENANT_ID}
        POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any
    END

Verify Incidents Created
    [Tags]    e2e    verify
    [Documentation]    Verify correlation engine created incidents

    Sleep    60s    Wait for correlation engine
    ${resp}=    GET On Session    api    /api/v1/incidents    expected_status=any
    Status Should Be    200    ${resp}

Verify CTI Indicators Matched
    [Tags]    e2e    verify
    [Documentation]    Verify CTI matching service found IoC matches

    # Create a known IoC first
    ${ioc}=    Create Dictionary
    ...    type=ip
    ...    value=203.0.113.50
    ...    threat=Known Attacker IP
    ...    severity=critical
    ...    confidence=95
    ...    source=manual
    ...    tlp=amber
    POST On Session    cti    /api/v1/cti/indicators    json=${ioc}    expected_status=any

    # Lookup should find it
    ${lookup}=    Create Dictionary    value=203.0.113.50    type=ip
    ${resp}=    POST On Session    cti    /api/v1/cti/lookup    json=${lookup}    expected_status=any
    Status Should Be    200    ${resp}

Verify Prometheus Metrics
    [Tags]    e2e    verify
    [Documentation]    Verify metrics are being collected

    ${resp}=    GET    ${API_BASE_URL}/api/v1/metrics    expected_status=any
    Status Should Be    200    ${resp}
    Should Contain    ${resp.text}    xdr_events_total

Verify Playbook Exists
    [Tags]    e2e    verify
    [Documentation]    Verify SOAR playbooks are available

    ${resp}=    GET On Session    api    /api/v1/playbooks    expected_status=any
    Status Should Be    200    ${resp}

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}
    Create Session    cti    ${CTI_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions

Reset Demo State
    Log    Running E2E demo attack scenario
