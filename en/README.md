## Overview

Nowadays, it is difficult for individual users to effectively ensure the authenticity and trustworthiness of their provided data. To address this issue, we have developed a SaaS service - Data Express Chain. It is focusing on the portability of personal data in Fintech area. Users proactively initiate personal data transmission by fetching the data by themselves. Afterwards, Data Express Chain incorporates blockchain technology to realize trustworthy data verification and further ensure the authenticity and reliability of data. This process allows users to become key participants in the process of data exchange - and it further grants the rights of personal data information to single individuals, aiming to build a basic infrastructure for cross-industry, cross-scenario, and distributed data transmission.

## Data Source

* Chiyu Banking Transacation Records
* Tax Payment e-receipt

## Terminology

| **Terminology** | **Meaning**                                                                                                                           |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| DECS                  | Short for Data Express Chain System                                                                                                         |
| Data Fetching         | The procedure that user login to the official website or application, download and authorize the specified data to the System Integrator |
| System Provider       | Organization to deploy the DECS system                                                                                                      |
| System Integrator     | Organization to access to DECS and integrate its functionalities                                                                            |
| System User           | User of DECS to conduct data fetching                                                                                                       |
| Clean Environment     | Remote software environment where data fetching happens                                                                                     |
| VDI                   | The specific Virtual Machine of a clean environment                                                                                         |
| Success Page          | The page after a successful data fetching, provided by System Integrator                                                                    |
| Failure Page          | The page after a failed data fetching, provided by System Integrator                                                                       |
| Original-File         | The original data file acquired directly from data source                                                                                   |
| Original-File-Parsing | Parsing the Original-File into readable json format (Parsed-File)                                                                          |
| Admin Console         | The administration web console to manage DECS configurations, used by System Provider                                                       |
