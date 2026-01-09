> <https://github.com/ml58158/Demystifying-KQL/tree/main/Advanced>
> - `Demystifying-KQL and Advanced KQL for ThreatHunters.pdf training by the above link`


# KQL Repository

This repository contains **Kusto Query Language (KQL)** queries and
supporting scripts used for **Microsoft security, identity, and Azure
monitoring** scenarios. It is organized to make it easy to understand
*what each query is for*, *where it is used*, and *how it fits into
operational or security workflows*.

------------------------------------------------------------------------

## 📁 Folder Structure

    Security/
    │
    ├── AuthenticationMethodChange.kql
    ├── ConditionalAccessChange.kql
    ├── EntraCredLeak.md
    ├── GlobalAdminAlert.kql
    ├── GlobalAdminElevationAlert.md
    ├── MonitorAlerts.kql
    ├── ResourceLockDelete.kql
    

------------------------------------------------------------------------

## 📂 Security Folder

The **Security** folder contains queries and scripts focused on:

-   Azure & Entra ID security monitoring
-   Azure Virtual Desktop (AVD) usage and access visibility
-   Sign-in and authentication analysis
-   Alerting and subscription-level insights

This folder is designed to support **SOC, IT Ops, and Identity teams**
working with Microsoft Sentinel, Log Analytics, and Entra ID.

------------------------------------------------------------------------

## 📄 File Descriptions

### `AVDUserUsage.kql`

Analyzes Azure Virtual Desktop user activity and usage patterns.

### `AVDuserconnectionsquery.ps1`

PowerShell automation for querying AVD user connection data.

### `AzureAlerts.KQL`

Queries Azure alert data across subscriptions and resources.

### `AzureSubKQL.md`

Reference documentation for subscription-level KQL queries.

### `EntAppDiscovery.ps1`

Enterprise Application discovery and governance script using Microsoft
Graph.

### `KQLSigninLogs.md`

KQL reference for Entra ID sign-in log analysis.

### `KQLreadme.md`

General KQL guidance, patterns, and best practices.

### `readme.md`

Primary README for the Security folder.

------------------------------------------------------------------------

## 🛠 Prerequisites

-   Azure Log Analytics access
-   Entra ID / Azure RBAC permissions
-   Microsoft Sentinel (optional)
-   PowerShell 7+

------------------------------------------------------------------------

**Author:** Jonathan Hope
