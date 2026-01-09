//RMG App Consent for Apex alert

AuditLogs
| where ActivityDisplayName == "Consent to application"
| where TimeGenerated >= ago(90d)
| where TargetResources has "4014c28c-06d1-4e41-8bf2-13bae1abda1f" or TargetResources has "829bbc38-639f-49da-b30f-d50e0c0c275d"
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)



//Grab the username:
AuditLogs
| where ActivityDisplayName == "Consent to application"
| where TimeGenerated >= ago(90d)
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser


//Create alert for failure to register Apex App
AuditLogs
| where ActivityDisplayName == "Consent to application" and Result contains “failure”
| where TimeGenerated >= ago(90d)
| where TargetResources has "4014c28c-06d1-4e41-8bf2-13bae1abda1f" or TargetResources has "829bbc38-639f-49da-b30f-d50e0c0c275d"
| extend InitiatedByUser = tostring(parse_json(InitiatedBy).user.userPrincipalName)
| project ActivityDisplayName, TargetResources, TimeGenerated, InitiatedByUser, Result

