*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions

*** Test Cases ***
API Gateway Health Check
    [Tags]    health    smoke
    API Gateway Is Ready

CTI Lakehouse Health Check
    [Tags]    health    smoke
    CTI Lakehouse Is Ready

Analyst Copilot Health Check
    [Tags]    health    smoke
    Analyst Copilot Is Ready

IoC Parsers Health Check
    [Tags]    health    smoke
    IoC Parsers Is Ready

Anomaly Detection Health Check
    [Tags]    health    smoke
    Anomaly Detection Is Ready

Prometheus Health Check
    [Tags]    health    smoke
    Prometheus Is Ready

Grafana Health Check
    [Tags]    health    smoke
    Grafana Is Ready

API Gateway Metrics Endpoint
    [Tags]    metrics
    ${resp}=    GET    ${API_BASE_URL}/api/v1/metrics    expected_status=any
    Status Should Be    200    ${resp}
    Should Contain    ${resp.text}    xdr_events_total

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}
    Create Session    cti    ${CTI_URL}    verify=${FALSE}
    Create Session    copilot    ${COPILOT_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions
