## Helpful KQL Queries

```
//Determin resources without an owner in a sub:
resources
| where subscriptionId == "subscription ID of company"
| where managedBy == ""
| project id, name, type, location, resourceGroup, subscriptionId
```

```
//Determine common resources ie Disk/NIC etc that are unattached:

resources
| where subscriptionId == "subscription ID of company"
| where (type =~ 'Microsoft.Compute/disks' and properties.diskState == 'Unattached') or (type =~ 'Microsoft.Network/networkInterfaces' and properties.virtualMachine.id == '')
| project id, name, type, location, resourceGroup, subscriptionId
```


Azure Assesment KQL

//List All resources and Resource Groups in a Sub:
```
resources
| where subscriptionId == "subscription ID of company"
```

//List all resources but order by Type

```
resources
| where subscriptionId == "subscription ID of company"
| project name, type
| order by type
```
