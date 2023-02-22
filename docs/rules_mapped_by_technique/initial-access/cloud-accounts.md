---
tags:
  - Initial Access
  - T1078
  - T1078.004
---

### CloudTrail
    ConsoleLogin
    GetFederationToken
    GetSessionToken
    StartSession
    GetAuthorizationToken

### GuardDuty\SCC Detections
=== "AWS GuardDuty"
    ``` yaml linenums="1"
    InitialAccess:IAMUser/AnomalousBehavior
    UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B
    ```
=== "GCP Security Command Center"
    ``` yaml linenums="1"
    ```
