*** Settings ***
Resource    ../resources/keywords.robot
Suite Setup    Create Sessions
Suite Teardown    Delete All Sessions

*** Test Cases ***
Register New User
    [Tags]    auth
    ${body}=    Create Dictionary
    ...    email=newuser@robot.test
    ...    password=Robot1234!
    ...    name=Robot Test User
    ${resp}=    POST On Session    api    /api/v1/auth/register    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 200 or ${resp.status_code} == 201

Login With Valid Credentials
    [Tags]    auth
    ${body}=    Create Dictionary    email=test@example.com    password=Test1234!
    ${resp}=    POST On Session    api    /api/v1/auth/login    json=${body}    expected_status=any
    Status Should Be    200    ${resp}
    Dictionary Should Contain Key    ${resp.json()}    access_token

Login With Invalid Password
    [Tags]    auth    negative
    ${body}=    Create Dictionary    email=test@example.com    password=wrongpassword
    ${resp}=    POST On Session    api    /api/v1/auth/login    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 401 or ${resp.status_code} == 403

Register Duplicate User
    [Tags]    auth    negative
    ${body}=    Create Dictionary
    ...    email=test@example.com
    ...    password=Test1234!
    ...    name=Duplicate User
    ${resp}=    POST On Session    api    /api/v1/auth/register    json=${body}    expected_status=any
    Should Be True    ${resp.status_code} == 409 or ${resp.status_code} == 400

*** Keywords ***
Create Sessions
    Create Session    api    ${API_BASE_URL}    verify=${FALSE}

Delete All Sessions
    Delete All Sessions
