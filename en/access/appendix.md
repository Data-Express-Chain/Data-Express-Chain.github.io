
## 1. Supported Access Methods (accessWay)

See below: [Possible values for accessWay](/en/access/appendix?id=_4-possible-values-for-accessway)


## 2. Supported Data Types (site)

### 2.1 VDI Type Data

| site | Corresponding Chinese Name in Agreement (Official Data Type Name) | Description | Supported Access Methods | File Format and Number of Data Acquisition Files, Asynchronous Download and Duration, Parsed-Original-File in ZIP | Source Type |
|:----|:----|:----|:----|:----|:----|
| tax | Personal Tax Record | Individual Electronic Tax Bureau PC Webpage | Weixin Miniapp; SDK; H5 | PDF: 1, password is the last 6 digits of ID number | PC Webpage |
| cscse | Overseas Academic Degree Certification | Overseas Diploma (CSCSE) | Weixin Miniapp; SDK; H5 | PNG: 1 | PC Webpage |
| chsi | Domestic Academic Degree Certificate | CHSI Academic Degree Query | Weixin Miniapp; SDK; H5 | html: 1 + png: 1 (zip) | PC Webpage |
| xlcx | Domestic Academic Degree Certificate | CHSI Academic Degree Scattered Query | Weixin Miniapp; SDK; H5 | html: 1 + png: 1 (zip) | PC Webpage |
| chrome-chsi-xw | Domestic Degree Query Results | CHSI Degree Login Query | Weixin Miniapp; SDK; H5 | html: 1 + png: 1 (zip) | PC Webpage |
| chrome-zwfw-diploma | Domestic Degree Certificate | CHSI Degree Scattered (ID) Query | Weixin Miniapp; SDK; H5 | html: 1 + png: 1 (zip) | PC Webpage |
| bjbdc | Beijing Real Estate | Beijing Real Estate | Weixin Miniapp; H5 | Image: 1~n Multiple properties may be shown in multiple images (page change) | PC Webpage |
| shbdc | Shanghai Real Estate | Shanghai Real Estate | H5 (Weixin only) | PDF: 1 | PC Webpage |
| chrome-tjbdc | Tianjin Real Estate | Tianjin Real Estate | Weixin Miniapp; SDK; H5 | PDF: 1~n, **asynchronous download, 20s**; multiple properties may be shown in multiple PDFs | PC Webpage |
| chrome-cdzjryb-bdc | Chengdu Real Estate | Chengdu Real Estate | Weixin Miniapp; SDK; H5 | PDF: 1+3*N (zip) N is the number of real estate properties **Parsed file is a zip package** | PC Webpage |
| sipub | Shenzhen Social Security | Shenzhen Social Security | Weixin Miniapp; SDK; H5 | PDF: 1 | PC Webpage |
| chsixj | Domestic Academic Status Query Results | CHSI Academic Status Query | Weixin Miniapp; SDK; H5 | html: 1 + png: 1 (zip) | PC Webpage |
| taxe | Employer Information | Tax Website Employer Information | Weixin Miniapp; SDK; H5 | pdf: 1 + html: 1 (zip) | PC Webpage |
| taxeat | Personal Tax Records and Employer Information | Tax Website Tax Records + Employer Information | Weixin Miniapp; SDK; H5 | pdf: 1 + html: 1 (zip) | PC Webpage |
| chrome-lfbdc-bdc | Langfang Real Estate | Langfang Real Estate | Weixin Miniapp; SDK; H5 | pdf:1 | PC Webpage |
| chrome-ncsbdc-bdc | Nanchang Real Estate | Nanchang Real Estate | Weixin Miniapp; SDK; H5 | pdf:1, multiple properties may be shown in 1 PDF | PC Webpage |
| bjsb | Beijing Social Security | Beijing Social Security (Offline, replaced by National Social Security) | Weixin Miniapp; SDK; H5 | pdf: 1 | PC Webpage |
| chrome-gjj-any | Housing Provident Fund Information (Housing Provident Fund Payment Details/Housing Provident Fund Loan Details/Housing Provident Fund Authorization Information, depending on your actual choice) | Multiple Housing Provident Fund Items | Weixin Miniapp; SDK; H5 | html:1+n </br> asynchronous download </br> download according to the actual childSites passed in, </br> childSites include: </br> chrome-gjj-jnjl: Housing Provident Fund Payment Details  </br> </br> Download file naming: </br> chrome-gjj-any_baseInfo.html   Housing Provident Fund Basic Information Details Page </br> chrome-gjj-any_jnjl.html  Housing Provident Fund Payment Record Details Page | PC Webpage |
| app-gjzwfw-gjj | Housing Provident Fund Query Results | National Government Service App - Housing Provident Fund </br> Note: **Main process requires facial recognition** | Weixin Miniapp; SDK; H5 | xml: 1~n </br> current status and balance of housing provident fund centers nationwide, each housing provident fund center corresponds to one file | Mobile App |
| app-gjzwfw-jsz | Driver's License | National Government Service App - Driver's License | Weixin Miniapp; SDK; H5 | html: 1  | Mobile App |
| app-jszwfw | Jiangsu Real Estate Query Results | Jiangsu Government Service App - Jiangsu Real Estate </br> Note: **Main process requires facial recognition** | Weixin Miniapp; SDK; H5 | zip: 1, unpacked into 1-n png /html, multiple properties will have multiple png/html | Mobile App |
| app-tax-income | Personal Income Tax Details | Tax App - Personal Income Tax Details | Weixin Miniapp; SDK; H5 | html: 3, </br> **asynchronous download, 20s** </br> **Forensic file name suffix corresponds to:** </br> income1 current year </br>  income2  T-1 year </br> income3 T-2 year | Mobile App |
| app-alipay-any | Alipay Information (Sesame Credit, Huabei, Jiebei, MyBank Loan, depending on your selection) | Alipay App - Multiple Items | Weixin Miniapp; SDK; H5 | xml: 3~6, </br>  including ID page and personal information page, **asynchronous download, 30-40s** </br>  recommend passing childSites according to actual user needs, including: </br>  app-alipay-cr Sesame Credit </br>  app-alipay-huabei Huabei </br>  app-alipay-jiebei Jiebei </br>  app-alipay-wsd MyBank Loan </br> </br>  **File name includes suffix corresponding to:** </br> jiebei  Jiebei </br> huabei  Huabei </br>  cr  Sesame Credit </br>  wsd  MyBank Loan </br>  **personal  Personal Information Page** </br>  **idcard  ID Information** | Mobile App |
| app-alipaydata-any | Alipay Information (Sesame Credit, Huabei, and Jiebei, depending on your selection) | Alipay App - Multiple Items | Weixin Miniapp; SDK; H5 | zip: 1, </br> unpacked into xml total 3~5,  </br> including public ID page and personal information page, **asynchronous download, 30-40s** </br> **recommend passing childSites according to actual user needs** including: </br> app-alipay-cr Sesame Credit </br> app-alipay-quota Alipay Quota Data (Huabei + Jiebei) </br></br> **Parsed file is a zip packag File name Field Corresponding:** </br> **cr  Sesame Credit** </br> **jiebei  Jiebei** </br> **huabei  Huabei** </br> **personal  Personal Information Page** </br> **idcard  ID Information** | Mobile App |
| app-alipay-wsd | Alipay - MyBank Loan | Alipay - MyBank Loan | Weixin Miniapp; SDK; H5 | xml: 3,  </br> including public ID page and personal information page, **asynchronous download, 30-40s**  </br> </br> **Parsed file is a zip package** **File nam Field Corresponding:**  </br> **wsd MyBank Loan Information** </br> **personal  Personal Information Page**  </br> **idcard  ID Information** | Mobile App |
| app-tmri-any | Electronic Driver's License, Vehicle License, Safe Driving Record, etc. (depending on your selection) | 12123 App - Multiple Items (Vehicle License, Driver's License, Safe Driving Record) | Weixin Miniapp; SDK; H5 | zip: 1,  </br> **asynchronous download, 30s~6min** (Safe Driving Record requires 5min)  </br> **recommend passing childSites according to actual user needs** including:  </br> app-tmri-xsz Vehicle License   </br> app-tmri-jsz Driver's License  </br> app-tmri-jsjl Safe Driving Record  </br> </br>**Parsed file is a zip package** **File name field corresponding:**  </br> jsjl-aqjsjl Safe Driving Record is in PDF format, 1|
| app-jst-bd | Compulsory Traffic Insurance Policy | Compulsory Traffic Insurance Policy | Miniapp; SDK; H5 | app-jst-bd-jqx_0.pdf Index increment naming | Mobile app |
| app-gjzwfw-hyzj | Marriage Certificate | Marriage Certificate (Marriage Certificate, Divorce Certificate)Note: Main process mandatory face swipe | Miniapp; SDK; H5 | zip: 1, </br> asynchronous download, unzip to n certificates, the file name suffix is a digital sequence, up to 4 files per certificate.File name field correspondence:  </br> jhz-index-1.xml: Marriage certificate result page  </br> jhz-1.xml: Marriage certificate details  </br> jhz-original-1.xml: Marriage certificate original  </br> jhz-original-img-1.png Marriage certificate photo  </br> lhz-index-1.xml: Divorce certificate result page  </br> lhz-1.xml: Divorce certificate details  </br> lhz-original-1.xml: Divorce certificate original  </br> lhz-original-img-1.png Divorce certificate photo | Mobile app |

Note: For asynchronous download data types, a notification with daStatus = 10 will only be issued after all files have been successfully downloaded.  
Note2: Updates on the current regional support for individual social security participation records (app-gjzwfw-dzsb).  

20240507: Currently, social security parsing is supported in 17 regions:
* 11 regions support the participation certificates and rights and interests documents for urban workers: Shanghai, Beijing, Guangdong, Hubei, Jiangsu, Zhejiang, Shandong, Sichuan, Shaanxi, Guizhou, Chongqing;
* 5 regions support the participation certificates for urban workers (local queries have no rights and interests documents): Henan, Fujian, Hunan, Anhui, Shanxi (rights and interests documents only have 2018 data and are not currently supported for parsing);
* 1 region supports the rights and interests documents for urban workers: Liaoning (participation certificates are embedded PNG in PDF, temporarily not supported).

### 2.2 Email Transaction Data Types

Note: Not Supported Now
## 3. Possible values of daStatus
### 3.1 daStatus

|Status Name|daStatus|Description|Final State?|Notify System Integrator?|Valid Operation?|Mode|
|:----|:----|:----|:----|:----|:----|:----|
|Initial State|0|Initial State|Not final state (will eventually become final)|No|N|VDI/ Beehive|
|Email Received State|4|In **Beehive mode**, indicates that an email has been received from the data type website|Not final state (will eventually become final)|No|N| Beehive|
|Data Downloading|5|Data is in the process of being downloaded|Not final state (will eventually become final)|Notify (by default none, needs to be additionally configured by the System Provider)|N|VDI|
|Data Upload Successful|8| Data has been successfully uploaded to the cloud storage, waiting to generate download link|Not final state (will eventually become final)|No|N|VDI|
|First Stage Evidence Collection Complete|9|Only valid for specific data sources; after the main file is downloaded, this notification can be sent to allow the System Integrator to download the main file; detail files will be sent in subsequent notifications|Not final state (will eventually become 10) First stage file can be downloaded|Notify (by default none, needs to be additionally configured by the System Provider)|Y|VDI|
|**Evidence Collection Successful**|**10**|**The evidence collection process automatically ends after the  data is successfully downloaded, indicating that the  data has been successfully uploaded, and the video has been successfully uploaded**|**Successful final state**|**Notify, indicating successful evidence collection**|**Y**|**VDI/ Beehive**|
|Data Upload Failed|13|After the data is downloaded, the upload of the data failed|Final State|Notify|N|VDI|
|Illegal data Download|14|This state has not been launched yet. Due to some anomalies, the user has downloaded a file other than the target data|Final State|Notify|Y|VDI|
|Evidence Video Processing Failed|15|The processing of the evidence video failed for various reasons, such as the failure to upload the video file, or an error in the recording software (the data has been successfully uploaded)|Final State|Notify|N|VDI|
|Clean Environment Use Timeout|20|Evidence collection timed out and exited (VDI for 10min,  Beehive 60min) </br> Note: In  Beehive mode, the email has been received but still timed out and exited. At this time, the user can still reuse the previous email to complete a new evidence collection within 23 hours, without the need to resend the email.|Final State|Notify|Y|VDI/ Beehive|
|vcode expired|21|After the start-vdi request is called, if the System End-User takes too long to enter the Clean Environment, it will cause the vcode to expire, thus preventing entry into the Clean Environment for that Data Acquisition attempt|Final State|Notification|Y|VDI|
|vcode expired, no charge situation|22|After the start-vdi request is called, for reasons not attributable to the System End-User, leading to vcode expiration and thus preventing entry into the Clean Environment for that Data Acquisition attempt|Final State|    |N| Beehive Payment Score|
|System End-User re-entry|24|After the System End-User re-enters, that Data Acquisition attempt is terminated|Final State|Notification|Y|VDI|
|System End-User actively terminates Data Acquisition state|25 |The situation where the System End-User actively terminates the Data Acquisition (for example, swiping right inside the Weixin Miniapp and then actively confirming exit) </br> Note: Under  Beehive mode, this is when the email is received but still actively exited. In this case, the System End-User can still reuse the previous email to complete a new Data Acquisition within 23 hours, without the need to resend the email.|Final State|Notification|Y|VDI/ Beehive|
|Clean Environment anomaly|30|When the inspection process discovers an anomaly in the Clean Environment, such as the browser crashing, or for any accidental reason displaying information outside of the Data Acquisition process (such as the desktop), the Clean Environment will be preemptively reclaimed and the Data Acquisition ended|Final State|Notification|N|VDI|
|Data source type system failure (Invalid operation)|41, detailed error reason see Chapter 9|Deterministic data source type unavailable (4xx,5xx, system maintenance), invalid operation type|Final State|Notification|N|VDI|
|Data source type system failure (Valid operation)|42|This state is not yet online. System failure, valid operation type. (Reserved)|Final State|Notification|Y|VDI|
|Data source type business failure (Invalid operation)|43|Other system failure conditions that meet the no-charge criteria. Such as **device does not support facial recognition**|Final State|Notification|N|VDI|
|Data source type business failure (Valid operation)|44, detailed error reason see Chapter 9|Due to reasons such as the nature of the System End-User's account, the System End-User is unable to complete the Data Acquisition, such as a user of the China Higher Education Student Information website (CHESICC) having no academic qualifications, **System End-User refuses facial recognition permissions**|Final State|Notification|Y|VDI|
| Beehive mode Data Acquisition timeout|50|Under  Beehive mode, email not received, Data Acquisition timeout closed|Final State|Notification|N| Beehive|
| Beehive System End-User actively terminates Data Acquisition state|51|Under  Beehive mode, email not received, System End-User actively exits|Final State|Notification|N| Beehive|
| Beehive System End-User actively deletes email without submission|53|(Front-end only) Under  Beehive mode, the System End-User actively deletes the email without submission, considered as the System End-User not authorizing|Final State|    |    | Beehive|
| Beehive Weixin Payment Score, QR code not obtained|60|Under  Beehive Weixin Payment Score mode, QR code not obtained, ultimately timing out|Final State|    |N| Beehive Weixin Payment Score|
| Beehive Weixin Payment Score, not joined group|61|Under  Beehive Weixin Payment Score mode, QR code obtained but not joined group chat, ultimately timing out|Final State|    |N| Beehive Weixin Payment Score|
| Beehive Weixin Payment Score, card not shared|62|Under  Beehive Weixin Payment Score mode, card not shared, ultimately timing out|Final State|    |N| Beehive Weixin Payment Score|
|start error|92|Error returned after calling start-vdi request|Final State|    |N|VDI|
|No allocation of machine position|94|Under VDI mode, after the System End-User enters the VDI guide page and does not proceed to the next step for Data Acquisition|Final State|Notification|N|VDI|
|Other (Reserved)|100|This state is not yet online. Other failure situations|Final State|Notification|N|    |
|Other2 (Reserved)|101|This state is not yet online. Other failure situations|Final State|Notification|Y|    |
|Front-end fallback general error|-60000|Only received when front-end redirection URL is encountered, indicating that this attempt failed|Final State|    |N|    |

* **Notes:**
    * daStatus = -4 represents the status value pulled when the user has not yet clicked "Agree" on the pre-page, which is an intermediate state.
    * The range of daStatus values for final state failures: [13,100], that is, greater than or equal to 13 and less than or equal to 100.
    * The data format downloaded from the data type may be pdf/xls/csv/txt, etc.
    * For  Beehive mode, the daStatus is 4 when the email is received but not acted upon; 20 when the email is received but ultimately times out; 25 when the email is received but the user actively exits; 50 when the email is not received and times out; 51 when the email is not received and the user actively exits. Since  Beehive emails are deleted from the server 24 hours after receipt and not submitted, the integrator can actively reach out and retain users to re-enter data collection without sending emails for statuses 20/25 within 23 hours, by directly reusing the previous email, thus improving the conversion rate.
    * **For the same user (idno) from the same integrator (appId), on the same** **calendar day** **(counted by the time the start-vdi** **request is initiated**), obtaining the same data type (site), only the first valid operation is charged. Other repeated data collection operations for the same site, whether valid or not, are not charged.

### 3.2 jsonResult

| Value | Other |
|:----|:----|
| 5 | Initial state of parsing; if daStatus = 10, it indicates parsing failure |
| **10** | **Final state of successful parsing** |
| 11 | Final state where no parsing is required |
| 12 | No user data after file parsing |
| 13 | The company name parsed for the enterprise version data type does not match the input name |


## 4. Possible values for accessWay  

| accessWay Value | Description |
|:----|:----|
| miniapp | Miniapp redirection mode, the access party has its own CA-signed user agreement |
| miniappwithca | Miniapp redirection mode, the access party does not have a CA-signed user agreement, uses the face recognition and agreement services |
| fullminiapp | Standalone Miniapp access, users only need to scan a QR code and fill in information such as name and ID card |
| weh52miniapp | Access from within WeChat H5 page to Miniapp (Official accounts, Service accounts), see note 4.1 |
| weh52miniappwithca | Access from within WeChat H5 page to Miniapp (Official accounts, Service accounts), using the face recognition and agreement services, see note 4.1 |
| h52miniapp | Access from outside WeChat H5 page to Miniapp (Static H5 link), see note 4.2 |
| h52miniappwithca | Access from outside WeChat H5 page to Miniapp (Static H5 link), using the face recognition and agreement services, see note 4.2 |
| h52fullminiapp | H5 redirection to standalone Miniapp |
| sdk | Access via iOS sdk / Android sdk |
| h5 | Access via h5 |

Note 4.1  
If you need to access via weh52miniapp or weh52miniappwithca, you need to integrate the WeChat JS SDK and use its built-in redirection method to enter the clean environment for data retrieval. You can contact us to get the demo code for H5 redirection.

Note 4.2  
If you need to access via h52miniapp or h52miniappwithca, you need to call the interface to pull the URL for redirecting from an H5 page outside WeChat (static link) to the Miniapp.

## 5. How to Generate RSA Public and Private Keys

It is recommended to generate them using the command line in a Linux environment.

```plain
// Generate a 2048-bit RSA private key in pkcs1 format named rsa_private_key.pem
openssl genrsa -out rsa_private_key.pem 2048

// Generate the public key rsa_public_key.pem from the pkcs1 format private key
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

// Convert pkcs1 format private key to pkcs8 format private key rsa_private_key_pkcs8.pem openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem
```


## 6. How to Download Files Encrypted by Server-Side File Encryption
If file storage service server-side encryption is configured, the fileKey field returned by the file pull interface is not empty. You need to decrypt it into a base64 filekey, and use it together with the decrypted fileUrl to download the file using the code below. The difference from normal file download is that three additional parameters for file download decryption are set in the header.    

Note: Starting from August 21, 2023, as the business volume continues to increase, to ensure the quality and efficiency of query and data retrieval services, only files within 10 days can be retrieved (including original evidence, analysis results, custody certificates). Please timely retrieve and store the files.

```
@Test
void testDownloadUsingPresignedUrl() throws Exception{
        String presignedUrl = "https://evidence-file-1308262583.cos.ap-guangzhou.myqcloud.com/de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail-alipay_jyls-0.pdf?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1646480278%3B1646480878%26q-key-time%3D1646480278%3B1646480878%26q-header-list%3Dhost%3Bx-cos-server-side-encryption-customer-algorithm%3Bx-cos-server-side-encryption-customer-key%3Bx-cos-server-side-encryption-customer-key-md5%26q-url-param-list%3D%26q-signature%3D7e752832991291f92df05edb949f56a3f99c2d2d";
        String fileKey = "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=";
        String downloadFileSavePath = "E:\\de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a _qqmail-alipay_jyls-0.pdf";
        MessageDigest md5 = MessageDigest.getInstance("md5");
        byte[] md5Bytes = md5.digest(Base64Decoder.decode(fileKey));
        String base64Md5 = Base64Encoder.encode(md5Bytes);
        URL url = new URL(presignedUrl);
        HttpURLConnection httpURLConnection = (HttpURLConnection)url.openConnection();
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-algorithm", "AES256");
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key-MD5", base64Md5);
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key", fileKey);
        byte[] fileBytes = IOUtils.toByteArray(httpURLConnection.getInputStream());
        FileUtils.writeByteArrayToFile(new File(downloadFileSavePath), fileBytes);
}
```



## 7. Test and Production Environment Export IPs

Test notification callback outbound (from the clean environment to the partner):  


Test environment domain inbound (from partner to clean environment, port is 443):  


Production notification callback outbound (from the clean environment to the partner):  


Production environment domain inbound (from partner to clean environment, port is 443):


## 8. Domain names involved in network policy opening for partners pulling files from Tencent Cloud COS

Test environment related COS domains:  
 

Production environment related COS domains:  


Note: You need to open network outbound access for the above domains. All file domains are listed above and will not change. These domains do not have corresponding fixed IP addresses. If your outbound public network does not support opening permissions for domains individually, please contact your counterpart.  

## 9. daSubStatus Enum Table

Note: daSubStatus is only for detailing the reasons for authentication failure and is not a criterion for billing.
(This table will be iteratively updated with supported data sources, the listed error codes will not be changed)

General:

|daStatus|daSubstatus|    |
|:----|:----|:----|
|41|80020|Website is not accessible|
|43|60026|User device or environment does not support trtc function|
|    |60028|trtc processing exception|
|    |60029|iOS SDK does not support face brushing|
|    |60030|Android SDK does not support face brushing|
|44|81535|No data|
|    |60027|User denied camera access|
|    |100099|Not the person themselves|

Alipay Data Source

|Evidence site|Evidence result|Scenario|daStatus|jsonResult|daSubStatus|
|:----|:----|:----|:----|:----|:----|
|Alipay General|Evidence failed|Account logged in on another device|44|5|100401|
|    |    |Blank page|    |    |100414|
|    |    |Unauthenticated|    |    |100430|
|    |    |Account has security risk|43|5|100500|
|Sesame Score|Evidence successful, data available|1. Normal data available situation|10|10|0|
|    |Evidence failed|1. Not real-name authenticated|44|5|100402|
|    |    |2. User not subscribed|    |    |100404|
|    |    |3. Sesame Credit service has stopped|    |    |100403|
|Ant Credit Pay (Huabei)|Evidence successful, data available|1. Normal data available situation|10|10|0|
|    |    |2. Available credit is 0, total credit is empty|    |    |0|
|    |    |3. Available credit is --, total credit is --|    |    |0|
|    |Evidence successful, no data|1. Ant Credit Pay temporarily unable to serve you|10|12|0|
|    |    |2. Opening Ant Credit Pay not supported|    |    |0|
|    |    |3. Sorry, you are temporarily unable to upgrade|    |    |0|
|    |    |4. Ant Credit Pay limit XX%|    |    |0|
|    |Evidence failed|1. Not real-name authenticated|44|5|100408|
|    |    |2. User not subscribed|    |    |100407|
|    |    |3. Complete shared Ant Credit Pay security verification|    |    |100413|
|Borrow (Jiebei)|Evidence successful, data available|1. Normal data available situation|10|10|0|
|    |    |2. Credit used up|    |    |0|
|    |    |3. You are overdue|    |    |0|
|    |Evidence successful, no data|1. Borrow service not opened to you|10|12|0|
|    |    |2. Temporarily unable to provide you with loan service|    |    |0|
|    |    |3. The account you are currently logged in does not qualify for application|    |    |0|
|    |    |4. Service not opened to you|    |    |0|
|    |    |5. Service temporarily not open to you|    |    |0|
|    |Evidence failed|1. Not real-name authenticated|44|5|100411|
|    |    |2. User not subscribed|    |    |100410|
|    |    |3. Sorry, due to changes in your account information, for security reasons, you need to log in again|    |    |100412|
|MYbank|Evidence successful, data available|1. You can borrow|10|10|0|
|    |    |2. You have an experiential credit line available|    |    |0|
|    |Evidence successful, no data|1. Sorry, temporarily unable to serve you|10|12|0|
|    |    |2. Credit calculation in progress|    |    |0|
|    |Evidence failed|1. Not real-name authenticated|44|5|100418|
|    |    |2. User not subscribed (go apply)|    |    |100415|

Personal Income Tax (PC) Data Source

|Evidence site|Evidence result|Scenario|daStatus|jsonResult|daSubStatus|
|:----|:----|:----|:----|:----|:----|
|Tax (tax)|Evidence failed|System maintenance|41|5|81530|
|    |    |Personal tax system exception|    |    |81531|
|    |    |Cannot connect to the server|    |    |81532|
|    |    |Cannot access the network|    |    |81533|
|    |    |Server response slow|    |    |81534|
|    |Evidence failed|Annual settlement declaration not completed|44|    |100503|

China Higher Education Student Information (CHESICC) Data Source (PC)

|Evidence site|Evidence result|Scenario|daStatus|jsonResult|daSubStatus|Analysis result|
|:----|:----|:----|:----|:----|:----|:----|
|CHESICC General (Education/Academic/Degree)|Evidence failed|No education|44|5|82549|None|
|    |    |User has canceled|    |    |82550|None|
|    |    |School verification exceeded times|    |    |82551|None|

Traffic Management 12123 APP Data Source

|Failure type|Sub-site end code daStatus|Sub-site sub-end code daSubStatus|Reason|Suggested handling method|
|:----|:----|:----|:----|:----|
|Traffic Management 12123 Exception|41|100551|Data cannot be found in some areas periodically, or risk control is triggered|Suggest the user to retry at an appropriate time|
|    |43|100562|APP server issue|Suggest the user to retry at an appropriate time|
|    |41|100563~100566|Triggered APP risk control black box|Suggest the user to retry at an appropriate time|
|    |43|100550~100599|System failure|Suggest the user to retry at an appropriate time|
|General download failure|44|100524|Traffic Management 12123 APP does not support multi-end login, logging in again will automatically log off the previous device, causing download failure|Advise the user to authorize download and not to log in their Traffic Management 12123 APP on their phone within 15 minutes|
|Electronic driving license|44|100510|User does not have a driving license, or there is an error in Traffic Management 12123 APP data|If the user insists on having a driving license, then appeal on the Traffic Management 12123 APP themselves|
|    |44|100517|User has applied for an electronic driving license, but it has not been approved yet|Suggest guiding the user to log in the Traffic Management 12123 APP, confirm the application is successful, then return to retrieve data again|
|    |44|100518|User has not applied for an electronic driving license|Suggest guiding the user to log in the Traffic Management 12123 APP, apply for an electronic driving license, confirm the application is successful, then return to retrieve data again|
|    |44|100519|User did not enter the validity period of the document|Suggest guiding the user to log in the Traffic Management 12123 APP, enter the validity period of the identity document, then return to retrieve data again|
|    |44|100525|User did not upload certificate photo information|Suggest guiding the user to log in the Traffic Management 12123 APP, successfully upload the document photo, then return to retrieve data again|
|    |44|100526|Official re-download required|Suggest the user log in the Traffic Management 12123 APP, confirm the download is successful, then return to retrieve data again|
|Vehicle license information|44|100511|User has not bound the vehicle license|Suggest guiding the user to log in the Traffic Management 12123 APP, bind the vehicle license, then return to retrieve data again|
|Safe driving record|44|100523|During the download duration, the official did not approve the safe driving record application in time|Suggest letting the user wait until they receive a text message notification from Traffic Management 12123 that the application is successful, then return to retrieve data again|

## 10. Production Pre-Launch Checklist

1. Common Sections

* Before going live, ensure that at least one full process (from a real entry point, completing Data Acquisition, receiving notifications, pulling files, and completing the business) has been tested successfully.
* Confirm that the production environment public key has been provided, the callback address remains unchanged, and all outbound IPs have been provided. Any changes must be notified at least 2 days in advance.
    * If possible, please provide the https certificate for the callback address, as our operations require it for security verification. If the https certificate for the callback address server was ignored in the test environment, please ensure to provide it.
* Confirm that the relevant IPs and domain names of the System Provider have been added to the whitelist.
* **If using localized deployment for Original-File-Parse, refer to the following Webhook configuration to promptly receive updates on the Original-File-Parse project code changes.**
* Confirm that the correct format of the System End-User agreement has been uploaded, and urge the product and Tech Support to verify. Agreement handling requirements:
    1. When the System End-User selects the corresponding data type (site in the interface), use the corresponding agreement template to sign (we provide the template, only the Chinese name of the data type changes according to the site, everything else remains the same), in PDF format. The content to be replaced is in green (replaced twice throughout), the site and the corresponding Chinese names are listed in Appendix 2 above.
    2. Dynamically write the current user's name and ID number (in plaintext) at the beginning of the document.
    3. At the end of the document, use CA signature (invoke the electronic signature given to the end-user by the System Integrator), and add the date.
    4. After signing, upload the signed PDF file through interface 3.4 each time it is invoked.
        * Note: The agreement can be reused; the dimension is the user’s ID number (idNo in the interface) + data type (site in the interface).
        * Example: Zhang San has acquired data type A, the agreement can be signed once, but each time Zhang San submits A, this agreement must be transmitted through the interface.
    5. The agreement needs to be transmitted before the end-user operation is completed to ensure timely notification and timely pulling of Data Acquisition files.

2. If using Weixin Miniapp for integration

* Confirm the Weixin Miniapp ID, original ID in the production environment, and the envVersion should be set to release.
* If using H5 redirection to Weixin Miniapp link integration, confirm the awareness of the link expiration time.

3. If using SDK for integration

* Confirm that the privacy policy and permission requests of the SDK package meet the requirements.

4. If using H5 for integration

* Confirm the entry page and Success Page of the production environment again.

5. **If using localized deployment for Original-File-Parse, it is recommended to configure Webhook**

The Original-File-Parse project is deployed on Gitee. Since the Original-File-Parse project will be updated regularly, it is recommended that the System Integrator deploy the Webhook to receive project code changes before going live to keep track of code updates.

Gitee webhook instructions: [https://gitee.com/help/categories/40](https://gitee.com/help/categories/40); Enterprise WeChat, DingTalk, Feishu natively support Gitee webhooks, and you can check the specific operation steps on this page; you can also use third-party HTTP interface to receive notifications.

The System Integrator needs to provide the notification URL to us for configuration; once configured, they can receive real-time updates of the Original-File-Parse project code.

---

## 11. National Encryption Suite Reference Implementation Document

Please refer to: [https://shimo.im/docs/wV3VV8g0voTXj13y](https://shimo.im/docs/wV3VV8g0voTXj13y)

## 12. Deployment Resource Suggestions

The resources and deployment that the System Integrator may need are as follows:

| Scenario | Description | System Environment | CPU | Memory | Disk | Quantity |
|:--------|:------------|:-------------------|:----|:------|:-----|:-------|
| Localized Original-File-Parse deployment | Environment for running localized Original-File-Parse | Linux, JDK 1.8+ | 4C | 8G | 100G | 1 |
| Notification reception backend | Receives status change notifications of Data Acquisition from the Clean Environment | Linux | 1C | 1G | - | 1 |
