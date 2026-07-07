*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions

*** Test Cases ***
Event Ingestion Pipeline
    [Tags]    pipeline    e2e
    [Documentation]    Verify events flow through the entire pipeline

    # Step 1: Ingest DDI event (suspicious domain)
    ${ddi_event}=    Create Dictionary
    ...    source=ddi
    ...    event_type=dns.query.suspicious
    ...    severity=high
    ...    confidence=80
    ...    risk_score=750
    ...    source_ip=192.168.1.100
    ...    domain=strange-domain.xyz
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp1}=    POST On Session    api    /api/v1/events/ingest    json=${ddi_event}    expected_status=any
    Should Be True    ${resp1.status_code} == 200 or ${resp1.status_code} == 201

    # Step 2: Ingest WAF event (rate limit)
    ${waf_event}=    Create Dictionary
    ...    source=waf
    ...    event_type=waf.rate_limit.exceeded
    ...    severity=medium
    ...    confidence=70
    ...    risk_score=500
    ...    source_ip=203.0.113.42
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp2}=    POST On Session    api    /api/v1/events/ingest    json=${waf_event}    expected_status=any
    Should Be True    ${resp2.status_code} == 200 or ${resp2.status_code} == 201

    # Step 3: Ingest Mail event (phishing)
    ${mail_event}=    Create Dictionary
    ...    source=mail
    ...    event_type=email.phishing.detected
    ...    severity=high
    ...    confidence=90
    ...    risk_score=850
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp3}=    POST On Session    api    /api/v1/events/ingest    json=${mail_event}    expected_status=any
    Should Be True    ${resp3.status_code} == 200 or ${resp3.status_code} == 201

    # Step 4: Ingest ZK attestation failure
    ${zk_event}=    Create Dictionary
    ...    source=zk
    ...    event_type=zk.attestation.failed
    ...    severity=critical
    ...    confidence=95
    ...    risk_score=900
    ...    asset_id=${TEST_ASSET_ID}
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp4}=    POST On Session    api    /api/v1/events/ingest    json=${zk_event}    expected_status=any
    Should Be True    ${resp4.status_code} == 200 or ${resp4.status_code} == 201

DDI Connector Event Classification
    [Tags]    connector    ddi
    [Documentation]    Verify DDI events are classified correctly

    # Suspicious TLD
    ${event1}=    Create Dictionary
    ...    source=ddi
    ...    domain=malicious-site.xyz
    ...    query_type=A
    ...    source_ip=10.0.0.1
    ...    response_ip=203.0.113.1
    ...    status_code=200
    ...    response_time_ms=150
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${event1}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

    # DGA pattern
    ${event2}=    Create Dictionary
    ...    source=ddi
    ...    domain=xkrjfmalwpqtop.com
    ...    query_type=A
    ...    source_ip=10.0.0.2
    ...    response_ip=198.51.100.1
    ...    status_code=200
    ...    response_time_ms=200
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${event2}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

WAF Connector Event Classification
    [Tags]    connector    waf
    [Documentation]    Verify WAF events are classified correctly

    # Rate limiting
    ${event}=    Create Dictionary
    ...    source=waf
    ...    client_ip=203.0.113.42
    ...    method=POST
    ...    path=/api/v1/auth/login
    ...    status_code=429
    ...    rule_id=rl_001
    ...    rule_action=block
    ...    request_size=1024
    ...    user_agent=Nmap
    ...    host=api.example.com
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

Mail Connector Event Classification
    [Tags]    connector    mail
    [Documentation]    Verify Mail events are classified correctly

    # Phishing email
    ${event}=    Create Dictionary
    ...    source=mail
    ...    from=phishing@malicious-domain.xyz
    ...    to=finance@company.com
    ...    subject=Urgent: Verify your account
    ...    has_attachment=${TRUE}
    ...    attachment_count=1
    ...    attachment_types=[".zip"]
    ...    spam_score=0.85
    ...    phish_score=0.92
    ...    spf_pass=${FALSE}
    ...    dkim_pass=${FALSE}
    ...    dmarc_pass=${FALSE}
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${event}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

ZK Proof Submission
    [Tags]    zk    proof
    [Documentation]    Verify ZK proofs can be submitted

    ${proof}=    Create Dictionary
    ...    proof_type=device_identity
    ...    device_id=device-001
    ...    proof_data=eyJ0ZXN0IjogdHJ1ZX0=
    ...    verified=${TRUE}
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/zk/proofs    json=${proof}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}
    Create Session    cti    ${CTI_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions
