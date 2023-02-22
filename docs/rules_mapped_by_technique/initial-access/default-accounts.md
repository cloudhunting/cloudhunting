---
tags:
  - Initial Access
  - T1078
  - T1078.001
---
### Using of IAM User from External IP address
=== "AWS"
    ``` yaml linenums="1"
    title: Using of IAM User from External IP address
    id: b3877a46-b2ff-4766-b36e-5ed311058cdd
    status: test
    description: Detects the using of IAM user from outside AWS range
    author: asafaprozper
    date: 2022/11/01
    tags:
        - attack.initial_access
        - attack.t1078.001
    logsource:
        product: aws
        service: cloudtrail
    detection:
        selection_source:
            userIdentity.type: IAMUser
        filter:
            sourceIPAddress:
                - '*.amazonaws.com'
                - 'AWS Internal'
        condition: selection_source and not filter
    falsepositives:
        - Sometimes DevOps using a strong IAM user (such as, "jenkins" or "teamcity") from their personal workstation for troubleshooting
        - Detecting access from other AWS accounts, to avoid that you will need to add all AWS IP address ranges to exclude
    level: high
    ```
=== "GCP"
    ``` yaml linenums="1"
    ```

### AWS Root Account Activity
=== "AWS"
    ``` yaml linenums="1"
    title: Using of a Root account
    id: b3877a46-b2ff-4766-b36e-5ed311058cdd
    status: test
    description: Detects the sensitive usage of a Root account in a more timely manner (comparing to GuardDuty)
    author: asafaprozper
    date: 2022/11/01
    tags:
        - attack.initial_access
        - attack.t1078.001
    logsource:
        product: aws
        service: cloudtrail
    detection:
        selection_source:
            userIdentity.type: root
        condition: selection_source
    falsepositives:
        - Using of root account for invoice and payments request for AWS support
        - Using of root account for disabling region-lock
    level: high
    ```

### Anonymous Principle Successful Requests
=== "AWS"
    ``` yaml linenums="1"
    title: Anonymous Principle Successful Requests
    id: c8d96265-dde3-43a9-a7d2-ea48bca8e62a
    status: test
    description: Detects successful requests by Anonymous Principle which can indicate on public exposure
    author: asafaprozper
    date: 2022/11/01
    tags:
        - attack.initial_access
        - attack.t1078.001
    logsource:
        product: aws
        service: cloudtrail
    detection:
        selection_source:
            userIdentity.accountId: ANONYMOUS_PRINCIPAL
            errorCode: success
        filter:
            - userAgent: "[Amazon CloudFront]"
            - eventName: PreflightRequest
        condition: selection_source and not filter
    falsepositives:
        - Public exposure that meant to be exposed to anyone on the internet without authentication
    level: high
    ```
=== "GCP"
    ``` yaml linenums="1"
    ```

### GuardDuty\SCC Detections
=== "AWS GuardDuty"
    ``` yaml linenums="1"
    Policy:IAMUser/RootCredentialUsage
    ```
=== "GCP Security Command Center"
    ``` yaml linenums="1"
    ```