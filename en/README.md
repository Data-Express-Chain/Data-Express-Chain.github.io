## Introduction

Nowadays, it is difficult for individual users to effectively ensure the authenticity and trustworthiness of their provided data. To address this issue, we have developed a SaaS service (Data Express Chain). The project is focusing on the portability of personal data in Fintech area. In the beginning, users proactively initiate personal data transmission by uploading the data by themselves. Afterwards, Data Express Chain incorporates blockchain technology to realize trustworthy data verification and further ensure the authenticity and reliability of data. This process allows users to become key participants in the process of data exchange - and it further grants the rights of personal data information to single individuals, aiming to build a basic infrastructure for cross-industry, cross-scenario, and distributed data transmission.

## Data Source

* Chiyu Banking
* TaxPyament e-receipt
* Shopee
* BPJS
* chsi

## Terminology

| **Terminology**                       | **Meaning**               |
| -------------------------------------- | ------------------------------- |
| DECS      | Short for Data Express Chain System |
| Data Acquisition | The procedure that End-User login to specific data-source and acquire his/her own data |
| System Provider        | Organization responsible to deploy the DECS system |
| System Integrator | Organization seeking to access to DECS deployed by System Provider |
| System End-User |  End-User of DECS to do actual data acquisition |
| Clean Environment | Remote software environment where End-User doing data acquisition |
| VDI | The specific Virtual Machine where End-User do data acquisition |
| Success Page | The url page redirected to after a successful data acquisition, provided by System Integrator |
| Failure Page | The url page redirected to after a failed data acquisition, provided by System Integrator |
| Original-File| The original data file acquired directly from data source |
| Original-File-Parse | Parsing the Original-File from data source into readable json format |
| Evidence Certificate | The data repository pdf file marking the existence of a data acquisition trial |
| Admin Console | The administration web console to manage DECS settings, used by System Provider |