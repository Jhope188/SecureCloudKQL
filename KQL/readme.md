# KQL Alerts Catalog

**Tags:** `#KQL` `#KQLAlerts` `#AzureAlerts`

This document consolidates and organizes all provided KQL queries into logical alerting and analysis categories for Azure Monitor, Log Analytics, Sentinel, and Defender.

---

## 1. Authentication & Sign‑In Monitoring

### Failed Logons (Windows Security Events)

```kql
SecurityEvent
| where TimeGenerated <= ago(7d)
| where EventID == 4625
| summarize count() by TargetAccount, Computer
```

### Successful vs Failed Logons (30‑Day Trend)

```kql
SecurityEvent
| where TimeGenerated > ago(30d)
| summarize
    Success = countif(EventID == 4624),
    Failed  = countif(EventID == 4625)
    by bin(TimeGenerated, 1h)
| render timechart
```

### Conditional Access Failures

```kql
SigninLogs
| where TimeGenerated >= ago(1h)
| where ConditionalAccessStatus == 'failure'
| project TimeGenerated, UserPrincipalName, IPAddress,
          Status.errorCode, Status.failureReason,
          AppDisplayName, ClientAppUsed
| order by TimeGenerated desc
```

### Suspicious Geo‑Location Sign‑Ins

```kql
SigninLogs
| where UserPrincipalName contains "acmeuser
| where tostring(LocationDetails.countryOrRegion) !in ("US")
| project TimeGenerated, UserPrincipalName, IPAddress,
          countryOrRegion = tostring(LocationDetails.countryOrRegion)
```

### Relay Account Authentication Review

```kql
SigninLogs
| where UserPrincipalName == ""
| extend authMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| where isnotempty(authMethod)
| where TimeGenerated > ago(7d)
| project TimeGenerated, UserPrincipalName, IPAddress, authMethod,
          AppDisplayName, ClientAppUsed, ConditionalAccessStatus
```


---

## 2. Authentication Method & Identity Changes

### Authentication Method Changes

```kql
AuditLogs
| where Category == "UserManagement"
| where OperationName in (
    "Add authentication method",
    "Delete authentication method",
    "Admin registered security info",
    "Update user",
    "Admin deleted security info"
)
| extend InitiatedByUPN = tostring(InitiatedBy.user.userPrincipalName),
         InitiatedByApp = tostring(InitiatedBy.app.displayName),
         TargetUser     = tostring(TargetResources[0].userPrincipalName),
         AuthMethod     = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project TimeGenerated, OperationName, TargetUser,
          AuthMethod, InitiatedByUPN, InitiatedByApp, Result
| order by TimeGenerated desc
```

### Privileged / Sensitive Accounts

```kql
IdentityInfo
| where IsAccountEnabled
| extend SensitiveUser = Tags has "Sensitive"
| extend GlobalAdministrator = AssignedRoles has "Global Administrator"
| extend SecurityAdministrator = set_has_element(AssignedRoles, "Security Administrator")
| where SensitiveUser or GlobalAdministrator or SecurityAdministrator
| summarize arg_max(Timestamp, *) by AccountObjectId
```

---

## 3. Application Consent & Service Principals

### App Consent – Success

```kql
AuditLogs
| where ActivityDisplayName == "Consent to application"
| where TimeGenerated >= ago(90d)
| where TargetResources has "4014c28c-06d1-4e41-8bf2-13bae1abda1f"
   or TargetResources has "829bbc38-639f-49da-b30f-d50e0c0c275d"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser
```

### App Consent – Failure

```kql
AuditLogs
| where ActivityDisplayName == "Consent to application"
| where Result contains "failure"
| where TimeGenerated >= ago(90d)
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated,
          InitiatedByUser, Result
```

### Service Principal Creation

```kql
AuditLogs
| where OperationName contains "Add service principal"
| extend ServicePrincipalName = tostring(TargetResources[0].displayName),
         UserWhoCreated = tostring(InitiatedBy.user.userPrincipalName)
| project TimeGenerated, ServicePrincipalName, UserWhoCreated
| order by TimeGenerated desc
```

---

## 4. Azure Administrative Operations

### Critical Admin Operations

```kql
AzureActivity
| where TimeGenerated > ago(15m)
| where CategoryValue == "Administrative"
| extend OperationNameUpper = toupper(OperationNameValue)
| where OperationNameUpper in (
    "MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE",
    "MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/WRITE",
    "MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE",
    "MICROSOFT.COMPUTE/VIRTUALMACHINES/DELETE"
)
| project TimeGenerated, OperationNameValue, Caller,
          ResourceGroup, SubscriptionId
```

### Consolidated Admin Alert

```kql
AzureActivity
| where TimeGenerated > ago(5m)
| where CategoryValue == "Administrative"
| extend OperationNameUpper = toupper(OperationNameValue)
| summarize FirstSeen=min(TimeGenerated), Count=count()
          by OperationNameUpper
```

---

## 5. Disk & Infrastructure Health

### Disk Free Space Below Threshold

```kql
let _minValue = 10;
InsightsMetrics
| where TimeGenerated >= ago(4h)
| where Origin == "vm.azm.ms"
| where Namespace == "LogicalDisk" and Name == "FreeSpacePercentage"
| where Val <= _minValue
| extend Disk = tostring(todynamic(Tags)["vm.azm.ms/mountId"])
| where Disk !in ("H:", "X:")
| summarize AggregatedValue = avg(Val)
          by bin(TimeGenerated, 15m), Computer, Disk
```

### 30‑Day Disk Growth Trend

```kql
let targetVM = "RMG-AHS-SQL01";ACME-SQL01ics
| where TimeGenerated >= ago(30d)
| where Namespace == "LogicalDisk" and Name == "FreeSpacePercentage"
| extend Disk = tostring(todynamic(Tags)["vm.azm.ms/mountId"])
| where Computer has targetVM
| summarize FreeSpacePercent=max(Val)
          by bin(TimeGenerated, 1d), Disk
| render timechart
```

---

## 6. Active Directory & Privilege Escalation

### Domain Admin Group Membership Changes

```kql
Event
| where TimeGenerated > ago(1h)
| where EventLog == "Security"
| where EventID == 4728
| where RenderedDescription has "Domain Admins"
| where RenderedDescription !contains "_jit"
| extend MemberName = extract(@"<Data Name=\"MemberName\">(.*?)</Data>", 1, EventData),
         SubjectUserName = extract(@"<Data Name=\"SubjectUserName\">(.*?)</Data>", 1, EventData)
| project TimeGenerated, Computer, SubjectUserName, MemberName
```

---

## 7. AVD Monitoring

### High RTT per User (Null‑Safe)

```kql
WVDConnectionNetworkData
| join kind=leftouter (
    WVDConnections
    | where State == "Completed"
      and isnotnull(UserName)
      and trim(' ', UserName) != ""
    | distinct CorrelationId, UserName
) on CorrelationId
| where isnotnull(UserName)
| summarize AvgRTT=round(avg(EstRoundTripTimeInMs)),
          RTT_P95=percentile(EstRoundTripTimeInMs, 95)
          by UserName
| where AvgRTT > 100
```

---

## 8. Policy & Security Control Changes

### Conditional Access Policy Changes

```kql
AuditLogs
| where OperationName has "Conditional Access policy"
| where Category == "Policy"
| extend InitiatedBy = tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName)
| extend PolicyName = tostring(TargetResources[0].displayName)
| project TimeGenerated, OperationName, InitiatedBy, PolicyName, Result
```

### Suspicious Role Assignments

```kql
AuditLogs
| where Category == "RoleManagement"
| where OperationName contains "Add role assignment"
| extend Role = tostring(TargetResources[0].displayName)
| extend Assignee = tostring(InitiatedBy.user.userPrincipalName)
| where Role in ("Owner", "User Access Administrator", "Contributor")
| project TimeGenerated, Role, Assignee
```

---

## 9. Automation & Service Monitoring

### Windows Service Stopped

```kql
Event
| where TimeGenerated > ago(15m)
| where EventLog == 'Application'
| where Source == 'CTSDirectConnectService'
| where RenderedDescription contains "Service Stopped"
| project Computer, TimeGenerated, RenderedDescription
```

### Automation Runbooks

```kql
AzureDiagnostics
| where Category == "JobLogs"
| where Status == "Completed"
| project TimeGenerated, RunbookName, Caller, ResourceGroup
```

---

## 10. Reference Links

* GeeksForGeeks – Azure KQL Event Logs <https://www.geeksforgeeks.org/microsoft-azure-query-system-event-log-data-using-azure-kql/>
* Jan Bakker – M365 Authentication Change Notifications<https://janbakker.tech/microsoft-365-end-user-notifications-for-changes-in-authentication-methods/>
* TerminalWorks – Windows Service Monitoring <https://www.terminalworks.com/blog/post/2022/01/09/monitor-windows-services-using-azure-monitor-and-generate-an-email-alert>

---

**Status:** Actively used alert library
**Next Steps:** Map alerts to Sentinel Analytics Rules & Action Groups





# Understanding `tostring(parse_json())` in KQL

When working with **Azure Entra ID (Azure AD) SigninLogs**, many valuable attributes are stored as **dynamic JSON objects** rather than simple strings. To reliably query, filter, and alert on these values, you must correctly **parse** and **cast** them.

This document explains *why*, *when*, and *how* to use:

```kql
tostring(parse_json())
```

---

## Why This Matters

Fields like `AuthenticationDetails` often contain critical security context:

* Authentication method (Password, MFA, FIDO2, Passkey)
* Authentication success/failure
* Step-by-step authentication flow

However, because these fields are **dynamic**, they cannot be filtered or compared directly without transformation.

---

## The Source Field: `AuthenticationDetails`

In **SigninLogs**, `AuthenticationDetails` is a *dynamic array* containing one or more authentication steps.

Example structure:

```json
[
  {
    "authenticationMethod": "Password",
    "authenticationStepDateTime": "2025-01-01T12:00:00Z",
    "succeeded": true
  }
]
```

Because this is **not a string**, KQL treats it as an object—not something you can directly compare or alert on.

---

## The Core Query Example

```kql
SigninLogs
| where UserPrincipalName == "user@acme.com"
| extend authMethod = tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
| where isnotempty(authMethod)
| where TimeGenerated > ago(7d)
| project TimeGenerated,
          UserPrincipalName,
          IPAddress,
          authMethod,
          AppDisplayName,
          ClientAppUsed,
          ConditionalAccessStatus
```

---

## Step-by-Step Breakdown

### 1. `parse_json()` — Convert JSON to a Queryable Object

```kql
parse_json(AuthenticationDetails)
```

This function converts the JSON content into a structured **dynamic object** that KQL can navigate.

---

### 2. `[0]` — Select the First Authentication Step

```kql
parse_json(AuthenticationDetails)[0]
```

Most interactive sign-ins record the **primary authentication method** in the first array element.

---

### 3. `.authenticationMethod` — Extract the Property

```kql
parse_json(AuthenticationDetails)[0].authenticationMethod
```

This isolates the authentication method value, but it is **still dynamic** at this stage.

---

### 4. `tostring()` — Cast to a Scalar Value

```kql
tostring(parse_json(AuthenticationDetails)[0].authenticationMethod)
```

Many KQL operations—such as `where`, `isnotempty()`, `summarize`, and alert rules—require **scalar values**, not dynamic objects.

`tostring()` converts the value into a usable string.

---

## Why `tostring()` Is Required

Without `tostring()`, filters may:

* Return **no results**
* Fail silently
* Break alert conditions

### ❌ Incorrect

```kql
| where authMethod == "Password"
```

### ✅ Correct

```kql
| where tostring(authMethod) == "Password"
```

---

## Filtering Valid Authentication Events

```kql
| where isnotempty(authMethod)
```

This removes:

* Token refresh events
* Non-interactive sign-ins
* Service principal authentications

Resulting in **clean, actionable data**.

---

## Advanced Scenario: Multiple Authentication Steps

Some sign-ins include **multiple authentication methods** (e.g., Password + MFA). To capture all of them:

```kql
SigninLogs
| mv-expand Auth = parse_json(AuthenticationDetails)
| extend authMethod = tostring(Auth.authenticationMethod)
| where isnotempty(authMethod)
| project TimeGenerated, UserPrincipalName, authMethod
```

### Use Cases

* MFA enforcement validation
* Passkey adoption tracking
* Legacy authentication detection

---

## Best Practices

✔ Always cast parsed JSON values using `tostring()`
✔ Guard against null or empty values
✔ Use `mv-expand` when analyzing multi-step authentication
✔ Normalize authentication methods for alerting

---

## When to Use This Pattern

Use `tostring(parse_json())` when:

* A field is marked as **dynamic**
* Query results show `{}` or `[]`
* Filters unexpectedly return no data
* You are building **Sentinel analytics rules**
* You need reliable **alert thresholds**

---

## Key Takeaway

> **`parse_json()` reveals the structure.**
> **`tostring()` makes it actionable.**

Together, they unlock identity telemetry hidden inside dynamic fields.

---

**Status:** Reusable / Public-safe (ACME placeholders)

**Recommended Next Steps:**

* Convert into Sentinel Analytics Rules
* Map authentication methods to MITRE ATT&CK
* Add alert thresholds per auth method



# KQL Deep Dive: `tostring()` vs `todynamic()` in AzureActivity

Azure Activity Logs frequently store critical details inside **nested JSON payloads**. To reliably detect configuration changes—such as **disabled alert rules, policy changes, or security control tampering**—you must understand when to use:

```kql
tostring()
todynamic()
```

This deep dive walks through both functions using a real-world **AzureActivity** alert scenario.

---

## Use Case: Detect Disabled Scheduled Query Rules

This query detects when an **Azure Monitor Scheduled Query Rule** (Log Analytics alert) is disabled.

```kql
AzureActivity
| where parse_json(Properties).message == "microsoft.insights/scheduledqueryrules/write"
| extend requestBody = parse_json(tostring(Properties_d.requestbody))
| where parse_json(tostring(requestBody.properties)).enabled == false
| extend resource = todynamic(Properties).resource
| project TimeGenerated, ResourceGroup, _ResourceId,
          Caller, CallerIpAddress, OperationNameValue, resource
```

---

## Why This Is Necessary

AzureActivity stores request and response payloads in **deeply nested dynamic fields**:

* `Properties` → dynamic JSON
* `Properties_d.requestbody` → dynamic *inside* dynamic
* `requestBody.properties` → JSON string

Without proper parsing and casting, these values are **invisible to filters and alerts**.

---

## Step-by-Step Breakdown

### 1. `parse_json()` — Access the Message Field

```kql
parse_json(Properties).message
```

`Properties` is stored as a **dynamic object**. `parse_json()` allows you to reference subfields like `.message`.

This filter scopes the query to **scheduled query rule write operations**.

---

### 2. `tostring()` — Normalize Nested JSON Strings

```kql
tostring(Properties_d.requestbody)
```

Even though `requestbody` *looks* like JSON, it is often stored as a **stringified JSON blob**.

`tostring()` ensures the content can be reliably parsed again.

---

### 3. `parse_json()` (Again) — Decode the Request Body

```kql
parse_json(tostring(Properties_d.requestbody))
```

This converts the stringified JSON into a usable **dynamic object** called `requestBody`.

---

### 4. Double Parsing: Accessing Nested Properties

```kql
parse_json(tostring(requestBody.properties)).enabled
```

Why the second `parse_json()`?

* `requestBody.properties` is **another JSON string**
* It must be parsed before accessing `.enabled`

This is a common AzureActivity pattern.

---

### 5. Filter on Disabled Alerts

```kql
| where parse_json(tostring(requestBody.properties)).enabled == false
```

This line identifies:

* Disabled Log Analytics alerts
* Silent security control changes
* Alert suppression attempts

---

### 6. `todynamic()` — Preserve Complex Objects

```kql
extend resource = todynamic(Properties).resource
```

`todynamic()` keeps the value as a **dynamic object** instead of flattening it into a string.

Use `todynamic()` when:

* You want to preserve structure
* You may extract multiple subfields later
* The field is already valid JSON

---

## `tostring()` vs `todynamic()` — When to Use Which

| Function      | Purpose            | Best Used For                  |
| ------------- | ------------------ | ------------------------------ |
| `tostring()`  | Convert to scalar  | Filtering, comparisons, alerts |
| `todynamic()` | Preserve structure | Nested JSON analysis           |

---

## Common Pitfalls

### ❌ Skipping `tostring()` Before `parse_json()`

```kql
parse_json(Properties_d.requestbody)
```

May fail silently if the field is stored as a string.

✅ **Correct**

```kql
parse_json(tostring(Properties_d.requestbody))
```

---

### ❌ Flattening JSON Too Early

```kql
tostring(Properties)
```

This destroys structure and limits future analysis.

✅ **Better**

```kql
todynamic(Properties)
```

---

## Security Value

This pattern is critical for detecting:

* Disabled monitoring alerts
* Policy tampering
* Defense evasion
* Unauthorized operational changes

It aligns directly with **MITRE ATT&CK – Defense Evasion (T1562)**.

---

## Key Takeaways

> **Use `tostring()` to compare and alert.**
> **Use `todynamic()` to explore and preserve structure.**

AzureActivity logs demand **layered parsing**—expect to parse more than once.

---

**Status:** Public-safe (ACME placeholders)

**Recommended Next Steps:**

* Convert into Sentinel Analytics Rule
* Add severity thresholds
* Pair with change-management alerts

