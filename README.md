# App Services - Sentinel - Prism Access

This repository hosts an Azure App Services Python code in order to get Prisma Access logs and send them into Microsoft Sentinel SIEM.
This one is a substitute to the [legacy connector](https://github.com/PaloAltoNetworks/cdl-decompress-proxy-sentinel-ingest/tree/master).

This connector is using DCR and format logs to be sent on the **CommonSecurityLog** table.

## Pre-requisites

  * A Python 3.13 [Azure Function App](https://learn.microsoft.com/en-us/azure/app-service/configure-language-python) 
  * A [Log Analytics Workspace](https://docs.microsoft.com/en-us/azure/azure-monitor/logs/log-analytics-overview) with Sentinel enabled on it.
  * A [DCE](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-endpoint-overview?tabs=portal) and [DCR](https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/data-collection-rule-overview) to receive logs from the App Services and send them into Sentinel.
  * Function [Managed Identity](https://docs.microsoft.com/en-us/azure/active-directory/managed-identities-azure-resources/overview)
    with at least `Monitoring Metrics Publisher` on the DCR.

### Variables

  * **DCE_URL** (required): The ingestion URL of the Data Collection Endpoint. 
  * **DCR_ID** (required): The Data Collection Rule immutable ID.
  * **DCR_STREAM** (required): The Data Collection Rule stream.