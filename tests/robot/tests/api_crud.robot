*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions

*** Test Cases ***
Create Asset
    [Tags]    crud    assets
    ${resp}=    Create Test Asset
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201
    Dictionary Should Contain Key    ${resp.json()}    id

List Assets
    [Tags]    crud    assets
    ${resp}=    GET On Session    api    /api/v1/assets    expected_status=any
    Status Should Be    200    ${resp}
    ${data}=    Set Variable    ${resp.json()}
    ${count}=    Get Length    ${data}
    Should Be True    ${count} >= 0

Create Incident
    [Tags]    crud    incidents
    ${body}=    Create Dictionary
    ...    title=Test Incident
    ...    description=Robot Framework test incident
    ...    severity=high
    ...    status=open
    ...    tenant_id=${TEST_TENANT_ID}
    ${resp}=    POST On Session    api    /api/v1/incidents    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

List Incidents
    [Tags]    crud    incidents
    ${resp}=    GET On Session    api    /api/v1/incidents    expected_status=any
    Status Should Be    200    ${resp}

Ingest Security Event
    [Tags]    crud    events
    ${resp}=    Create Test Event
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

Create CTI Indicator
    [Tags]    crud    cti
    ${resp}=    Create CTI Indicator
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

List CTI Indicators
    [Tags]    crud    cti
    ${resp}=    GET On Session    cti    /api/v1/cti/indicators    expected_status=any
    Status Should Be    200    ${resp}

CTI Lookup
    [Tags]    crud    cti
    ${body}=    Create Dictionary    value=198.51.100.23    type=ip
    ${resp}=    POST On Session    cti    /api/v1/cti/lookup    json=${body}    expected_status=any
    Status Should Be    200    ${resp}

List Playbooks
    [Tags]    crud    playbooks
    ${resp}=    GET On Session    api    /api/v1/playbooks    expected_status=any
    Status Should Be    200    ${resp}

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}
    Create Session    cti    ${CTI_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions
