# AWS CloudTrail Threat Hunting — Splunk BOTS v3

Investigation of anomalous IAM activity in the Splunk BOTS v3 dataset, using `aws:cloudtrail` logs to trace a compromised credential from initial recon through a failed persistence attempt to resource abuse.

## Dataset
- **Source:** Splunk Boss of the SOC v3 (`index=botsv3`)
- **Sourcetype:** `aws:cloudtrail`
- **Tooling:** Splunk SPL (`spath`, `stats`, `coalesce`, `eval`)

## Methodology

### 1. Orient — what's in the environment?
```spl
index=botsv3 | stats count by sourcetype | sort -count
```
![Sourcetype breakdown](screenshots/01_sourcetype_breakdown.png)

107 sourcetypes total, spanning network capture (`stream:*`), AWS/cloud (`aws:cloudtrail`, `aws:cloudwatchlogs*`), and endpoint telemetry (`osquery:*`, `wineventlog:*`). Confirms this is an AWS-centric attack scenario with supporting endpoint and network data.

### 2. Baseline normal API activity
```spl
index=botsv3 sourcetype=aws:cloudtrail | stats count by eventName | sort -count | head 20
```
![EventName breakdown](screenshots/02_eventname_breakdown.png)

Top calls were mostly AWS Config/Inspector housekeeping (`DescribeConfigRuleEvaluationStatus`, `ListAssessmentRuns`) and read-only describes. Two calls stood out for follow-up: `AssumeRole` (332) and `GetCallerIdentity` (304) — both common in privilege-escalation / access-verification patterns.

### 3. Check AssumeRole for human activity
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=AssumeRole
| spath
| eval actor=coalesce('userIdentity.arn', 'userIdentity.invokedBy', 'userIdentity.type')
| stats count by actor, requestParameters.roleArn | sort -count
```
**Result:** all 8 actors were AWS services assuming their own built-in service roles (Config, AutoScaling, VPC Flow Logs, EC2, Lambda, EventBridge, GuardDuty, Inspector). No human/attacker signal here — ruled out as noise.

### 4. Check GetCallerIdentity — who's checking their own access?
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=GetCallerIdentity
| spath
| eval actor=coalesce('userIdentity.arn','userIdentity.userName','userIdentity.type')
| stats count by actor, sourceIPAddress | sort -count
```
![GetCallerIdentity by actor and IP](screenshots/03_getcalleridentity_pivot.png)

**Result:** IAM user `web_admin` called this from **two different source IPs** — `139.198.18.205` and `35.153.154.221`. One IAM identity, multiple source IPs is a strong anomaly signal.

### 5. Pivot on web_admin — what did each IP actually do?
```spl
index=botsv3 sourcetype=aws:cloudtrail
| spath
| eval actor=coalesce('userIdentity.arn','userIdentity.userName')
| search actor="*web_admin*"
| stats count by eventName, sourceIPAddress | sort sourceIPAddress
```
![web_admin activity across 4 source IPs](screenshots/04_webadmin_multi_ip.png)

**Result:** `web_admin` was active from **4 distinct IPs**, each with a different behavior pattern:

| Source IP | Behavior |
|---|---|
| `35.153.154.221` | `CreateUser`, `CreateAccessKey`, `DeleteAccessKey`, `ListAccessKeys`, `GetSessionToken` — IAM manipulation (persistence attempt) |
| `139.198.18.205` | `RunInstances` ×2,304, `CreateDefaultVpc`, `DescribeKeyPairs`, `ListBuckets` — mass EC2 launch |
| `82.102.18.111` | `DescribeAccountAttributes`, `GetUser` — light recon |
| `209.107.196.112` | `ListAccessKeys` — recon |

### 6. Confirm the EC2 launch pattern
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=RunInstances sourceIPAddress=139.198.18.205
| spath | table _time, requestParameters.instanceType, responseElements.instancesSet.items{}.instanceId
```
![RunInstances instance types launched](screenshots/05_runinstances_types.png)

Instances launched across nearly every instance family within a single minute (`m4.2xlarge`, `t2.2xlarge`, `m3.2xlarge`, `m5.2xlarge`, `x1e.16xlarge`, `c4.2xlarge`, `m5.24xlarge`, `h1.4xlarge`, `c5.9xlarge`, `c3.4xlarge`) — consistent with an attacker probing instance-type/service-limit availability rather than a normal application workload.

### 7. Confirm the persistence attempt
```spl
index=botsv3 sourcetype=aws:cloudtrail eventName=CreateUser sourceIPAddress=35.153.154.221 | head 1
```
![CreateUser AccessDenied event](screenshots/06_createuser_accessdenied.png)

```json
errorCode: AccessDenied
errorMessage: User: arn:aws:iam::622676721278:user/web_admin is not authorized to
perform: iam:CreateUser on resource: arn:aws:iam::622676721278:user/my_db_user
userAgent: Boto3/1.7.44 Python/2.7.12 Linux/4.4.0-1063-aws Botocore/1.10.44
```
`web_admin` attempted to create a new IAM user (`my_db_user`) — likely intended as a backdoor identity — but lacked `iam:CreateUser` permission, so the attempt failed. The `userAgent` shows this was scripted (Boto3/Python), not manual console activity.

## Findings summary

1. IAM user `web_admin`'s credentials were used from **4 separate source IPs**, each performing a different stage of activity.
2. **Recon**: `GetCallerIdentity`, `GetUser`, `ListAccessKeys` — attacker verifying access and enumerating existing keys.
3. **Attempted persistence**: a scripted (Boto3) attempt to create a new IAM user (`my_db_user`) — **denied** due to insufficient permissions.
4. **Impact**: 576+ EC2 instances launched across almost every available instance family within a single minute, from a separate IP — consistent with resource-abuse (crypto-mining/botnet staging) or limit-testing.
5. `AssumeRole` traffic in this environment was entirely AWS-service automation and not related to this activity — ruled out early to avoid a false lead.

## Recommended response
- Immediately revoke/rotate `web_admin`'s access keys.
- Terminate the instances launched from `139.198.18.205` and review for cost/abuse impact.
- Block or investigate all 4 source IPs.
- Enforce MFA and IP-based conditions on `web_admin` (or replace with a role assumed via SSO).
- Audit `web_admin`'s IAM policy — the failed `CreateUser` call shows least-privilege partially worked; tightening further would remove the EC2 launch ability too.

---
*Investigation performed against the publicly available Splunk BOTS v3 training dataset for skills practice.*
