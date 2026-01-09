Azure KQL 


Check Disk space:
```
// Logical disk space % below threshold 
// Logical disk space % below threshold. 
let _minValue = 10; // Set the minValue according to your needs
InsightsMetrics
| where TimeGenerated >= ago(1h) // choose time to observe 
| where Origin == "vm.azm.ms"
| where Namespace == "LogicalDisk" and Name == "FreeSpacePercentage"
| where Val <= _minValue
| extend Disk=tostring(todynamic(Tags)["vm.azm.ms/mountId"])
| summarize AggregatedValue = avg(Val) by bin(TimeGenerated, 15m), Computer, _ResourceId, Disk
```
```
InsightsMetrics
  | where Name == "FreeSpaceMB"
  | extend Tags = parse_json(Tags)
  | extend mountId = tostring(Tags["vm.azm.ms/mountId"])
          ,diskSizeMB = toreal(Tags["vm.azm.ms/diskSizeMB"])
  | where mountId !in ("D:", "E:")
  | project-rename FreeSpaceMB = Val
  | summarize arg_max(TimeGenerated, diskSizeMB, FreeSpaceMB) by Computer, mountId
           ,FreeSpacePercentage = round(FreeSpaceMB / diskSizeMB * 100, 1)
  | extend diskSizeGB = round(diskSizeMB / 1024, 1)
          ,FreeSpaceGB = round(FreeSpaceMB / 1024, 1)
  | project TimeGenerated, Computer, mountId, diskSizeGB, FreeSpaceGB, FreeSpacePercentage
  | order by Computer asc, mountId asc
```

//https://www.geeksforgeeks.org/microsoft-azure-query-system-event-log-data-using-azure-kql/

```
Event
| where TimeGenerated > ago(1d)
| where EventLog has "System"
```
```
Event
| where TimeGenerated > ago(1d) and EventLog has "System"
```
```
Test Combining:
InsightsMetrics
| where TimeGenerated >= ago(1h) // choose time to observe 
| where Origin == "vm.azm.ms"
| where Namespace == "LogicalDisk" and Name == "FreeSpacePercentage"
| where Val <= 10
| extend Disk=tostring(todynamic(Tags)["vm.azm.ms/mountId"])
| where Disk != ("H:")
| summarize AggregatedValue = avg(Val) by bin(TimeGenerated, 15m), Computer, _ResourceId, Disk
```

//SecurityCenter KQL:
```
IdentityInfo
| where IsAccountEnabled
| extend SensitiveUser = Tags has "Sensitive"
| extend GlobalAdministrator = AssignedRoles has "Global Administrator"
| extend SecurityAdministrator = set_has_element(AssignedRoles, "Security Administrator")
| where SensitiveUser or GlobalAdministrator or SecurityAdministrator
| summarize arg_max(Timestamp, *) by AccountObjectId, OnPremSid, CloudSid
| project-away SensitiveUser, GlobalAdministrator, SecurityAdministrator, IsAccountEnabled
```

//https://www.geeksforgeeks.org/microsoft-azure-query-system-event-log-data-using-azure-kql/

```
Event
| where TimeGenerated > ago(15m)
| where EventLog == 'Application' and Source == 'CTSDirectConnectService'
//| where RenderedDescription contains "running state"
| where RenderedDescription contains "Service Stopped"
| project Computer,TimeGenerated,RenderedDescription
```

//GlobalCapture CTS DirectConnect Service
//| where RenderedDescription contains "running state"

https://www.terminalworks.com/blog/post/2022/01/09/monitor-windows-services-using-azure-monitor-and-generate-an-email-alert

