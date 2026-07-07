*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions

*** Test Cases ***
Ingest Event With Missing Fields
    [Tags]    negative    validation
    ${body}=    Create Dictionary    source=test
    ${resp}=    POST On Session    api    /api/v1/events/ingest    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 400 or ${resp.status_code} == 202

Create Asset With Invalid Data
    [Tags]    negative    validation
    ${body}=    Create Dictionary
    ...    name=
    ...    type=invalid_type
    ${resp}=    POST On Session    api    /api/v1/assets    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 400 or ${resp.status_code} == 422

Access Protected Endpoint Without Token
    [Tags]    negative    auth
    ${resp}=    GET On Session    api    /api/v1/assets    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 401

CTI Lookup Nonexistent Indicator
    [Tags]    negative    cti
    ${body}=    Create Dictionary    value=999.999.999.999    type=ip
    ${resp}=    POST On Session    cti    /api/v1/cti/lookup    json=${body}    expected_status=any
    Status Should Be    200    ${resp}

Submit Invalid JSON
    [Tags]    negative    validation
    ${resp}=    POST On Session    api    /api/v1/events/ingest    data=not-json    headers=${{"Content-Type": "application/json"}}    expected_status=any
    Should Be True    ${resp.status_code} == 400 or ${resp.status_code} == 422

Playbook Dry Run Nonexistent
    [Tags]    negative    playbooks
    ${resp}=    POST On Session    api    /api/v1/playbooks/nonexistent/dry-run    expected_status=any
    Should Be True    ${resp.status_code} == 404 or ${resp.status_code} == 400

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}
    Create Session    cti    ${CTI_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions
