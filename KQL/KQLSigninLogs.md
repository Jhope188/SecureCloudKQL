//Parsing SignIn logs for success of a specific user:

```
SigninLogs
| extend succeeded_ = tostring(parse_json(AuthenticationDetails)[0].succeeded)
| where Identity contains "User Identity"
```

//Create alert for failure to register Specific Enterprise App
```
AuditLogs
| where ActivityDisplayName == "Consent to application" and Result contains “failure”
| where TimeGenerated >= ago(90d)
| where TargetResources has "4014c28c-06d1-4e41-8bf2-13bae1abda1f" or TargetResources has "829bbc38-639f-49da-b30f-d50e0c0c275d"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser, Result

```

//Grab the username: of someone who consented to an Enterprise App
```
AuditLogs
| where ActivityDisplayName == "Consent to application"
| where TimeGenerated >= ago(90d)
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser
```

```
AuditLogs
| where ActivityDisplayName == "Consent to application"
| where TimeGenerated >= ago(90d)
| where TargetResources has "4014c28c-06d1-4e41-8bf2-13bae1abda1f" or TargetResources has "829bbc38-639f-49da-b30f-d50e0c0c275d"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser
```


//Check for failed sign ins

```

SigninLogs
| where TimeGenerated >= ago(1h)  // Adjust time range as needed
| where ConditionalAccessStatus == 'failure'    // Only failed sign-ins
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName, ResourceDisplayName, 
          Status.errorCode, Status.failureReason, Status.additionalDetails, ConditionalAccessStatus, ClientAppUsed
| order by TimeGenerated desc
```
