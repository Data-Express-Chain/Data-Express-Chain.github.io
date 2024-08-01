## 1. Supported AccessWay

Only "h5" is supported.

## 2. Supported Data Sources

Note: For asynchronous download data sources, a notification with daStatus = 10 will only be issued after all files have been successfully downloaded.

| site                 | Official Name                     | Description                   | accessway | File count & format | Data source type (PC/App) |
| :------------------- | :-------------------------------- | :---------------------------- | :-------- | :------------------ | :------------------------ |
| chrome-chiyubank-jyj | Chiyu banking transaction records | Chiyu Bank Website            | h5        | csv: 1 (zip)        | PC                        |
| chrome-govhk-tax     | Tax payment e-receipt (HK)        | Hongkong Personal Tax Website | h5        | pdf: 1 (zip)        | PC                        |

## 3. daStatus Values

| Status Name                                                | daStatus                                | Description                                                                                                                                                                                                                                                                                                               | Final State?                                                                   | Notify System Integrator?                                                            | Valid Operation? |
| :--------------------------------------------------------- | :-------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :----------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- | :--------------- |
| Initial State                                              | 0                                       | Initial State                                                                                                                                                                                                                                                                                                             | Not final state (will eventually become final)                                 | No                                                                                   | N                |
| Data Downloading                                           | 5                                       | Data is in the process of being downloaded                                                                                                                                                                                                                                                                                | Not final state (will eventually become final)                                 | Notify (by default none, needs to be additionally configured by the System Provider) | N                |
| Data Upload Successful                                     | 8                                       | Data has been successfully uploaded to the cloud storage, waiting to generate download link                                                                                                                                                                                                                               | Not final state (will eventually become final)                                 | No                                                                                   | N                |
| First Stage Evidence Collection Complete                   | 9                                       | Only valid for specific data sources; after the main file is ready, this notification can be sent to allow for downloading the main file; detail files will be sent in subsequent notifications                                                                                                                           | Not final state (will eventually become 10) First stage file can be downloaded | Notify (by default none, needs to be additionally configured by the System Provider) | Y                |
| **Original File Collection Successful**              | **10**                            | **The evidence collection process automatically ends after the  data is successfully downloaded, indicating that the  data has been successfully uploaded, and the video has been successfully uploaded**                                                                                                           | **Successful final state**                                               | **Notify, indicating successful file collection**                              | **Y**      |
| Data Upload Failed                                         | 13                                      | After the data is downloaded, the upload of the data failed                                                                                                                                                                                                                                                               | Final State                                                                    | Notify                                                                               | N                |
| Illegal data Download                                      | 14                                      | This state has not been launched yet. Due to some anomalies, the user has downloaded a file other than the target data                                                                                                                                                                                                    | Final State                                                                    | Notify                                                                               | Y                |
| Evidence Video Processing Failed                           | 15                                      | The processing of the evidence video failed for various reasons, such as the failure to upload the video file, or an error in the recording software (the data has been successfully uploaded)                                                                                                                            | Final State                                                                    | Notify                                                                               | N                |
| Clean Environment Use Timeout                              | 20                                      | Data collection timed out and exited (VDI for 10min)``                                                                                                                                                                                                                                                                    | Final State                                                                    | Notify                                                                               | Y                |
| vcode expired                                              | 21                                      | After the start-vdi request is called, if the System End-User takes too long to enter the Clean Environment, it will cause the vcode to expire, thus preventing entry into the Clean Environment for that Data Acquisition attempt                                                                                        | Final State                                                                    | Notification                                                                         | Y                |
| vcode expired, no charge situation                         | 22                                      | After the start-vdi request is called, for reasons not attributable to the System End-User, leading to vcode expiration and thus preventing entry into the Clean Environment for that Data Acquisition attempt                                                                                                            | Final State                                                                    |                                                                                      | N                |
| System End-User re-entry                                   | 24                                      | After the System End-User re-enters, that Data Acquisition attempt is terminated                                                                                                                                                                                                                                          | Final State                                                                    | Notification                                                                         | Y                |
| System End-User actively terminates Data Acquisition state | 25                                      | The situation where the System End-User actively terminates the Data Acquisition``                                                                                                                                                                                                                                        | Final State                                                                    | Notification                                                                         | Y                |
| Clean Environment anomaly                                  | 30                                      | When the inspection process discovers an anomaly in the Clean Environment, such as the browser crashing, or for any accidental reason displaying information outside of the Data Acquisition process (such as the desktop), the Clean Environment will be preemptively reclaimed and the Data Acquisition ended           | Final State                                                                    | Notification                                                                         | N                |
| Data source type system failure (Invalid operation)        | 41, detailed error reason see Chapter 9 | Deterministic data source type unavailable (4xx,5xx, system maintenance), invalid operation type                                                                                                                                                                                                                          | Final State                                                                    | Notification                                                                         | N                |
| Data source type system failure (Valid operation)          | 42                                      | This state is not yet online. System failure, valid operation type. (Reserved)                                                                                                                                                                                                                                            | Final State                                                                    | Notification                                                                         | Y                |
| Data source type business failure (Invalid operation)      | 43                                      | Other system failure conditions that meet the no-charge criteria. Such as**device does not support facial recognition**                                                                                                                                                                                             | Final State                                                                    | Notification                                                                         | N                |
| Data source type business failure (Valid operation)        | 44, detailed error reason see Chapter 9 | Due to reasons such as the nature of the System End-User's account, the System End-User is unable to complete the Data Acquisition, such as a user of the China Higher Education Student Information website (CHESICC) having no academic qualifications,**System End-User refuses facial recognition permissions** | Final State                                                                    | Notification                                                                         | Y                |
| start error                                                | 92                                      | Error returned after calling start-vdi request                                                                                                                                                                                                                                                                            | Final State                                                                    |                                                                                      | N                |
| No allocation of machine position                          | 94                                      | Under VDI mode, after the System End-User enters the VDI guide page and does not proceed to the next step for Data Acquisition                                                                                                                                                                                            | Final State                                                                    | Notification                                                                         | N                |
| Other (Reserved)                                           | 100                                     | This state is not yet online. Other failure situations                                                                                                                                                                                                                                                                    | Final State                                                                    | Notification                                                                         | N                |
| Other2 (Reserved)                                          | 101                                     | This state is not yet online. Other failure situations                                                                                                                                                                                                                                                                    | Final State                                                                    | Notification                                                                         | Y                |
| Front-end fallback general error                           | -60000                                  | Only received when front-end redirection URL is encountered, indicating that this attempt failed                                                                                                                                                                                                                          | Final State                                                                    |                                                                                      | N                |

* **Notes:**
  * daStatus = -4 represents the status value pulled when the user has not yet clicked "Agree" on the pre-loading page, which is an intermediate state.
  * The range of daStatus values for final state failures: [13,100], that is, greater than or equal to 13 and less than or equal to 100.
  * The data format downloaded from the data source may be pdf/xls/csv/txt, etc.
  * **For the same user (idno) from the same integrator (appId), on the same** **calendar day** **(counted by the time the start-vdi** **request is initiated**), obtaining the same data source (site), only the first valid operation is charged. Other repeated data collection operations for the same site, whether valid or not, are not charged.

## 4. jsonResult Values

| Value        | Other                                                                                        |
| :----------- | :------------------------------------------------------------------------------------------- |
| 5            | Initial state of parsing; if daStatus = 10, it indicates parsing failure                     |
| **10** | **Final state of successful parsing**                                                  |
| 11           | Final state where no parsing is required                                                     |
| 12           | No user data after file parsing                                                              |
| 13           | The company name parsed for the enterprise version data source does not match the input name |

## 5. daSubStatus Values

Note: daSubStatus is only for detailing the reasons for authentication failure and is not a criterion for billing.
(This table will be iteratively updated with supported data sources, the listed error codes will not be changed)

| daStatus | daSubstatus |                           |
| :------- | :---------- | :------------------------ |
| 41       | 80020       | Website is not accessible |
| 44       | 81535       | No data                   |
|          | 100099      | Not the person themselves |

## 6. How to Generate RSA Public and Private Key-Pair

It is recommended to generate them using the command line in a Linux environment.

```plain
// Generate a 2048-bit RSA private key in pkcs1 format named rsa_private_key.pem
openssl genrsa -out rsa_private_key.pem 2048

// Generate the public key rsa_public_key.pem from the pkcs1 format private key
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

// Convert pkcs1 format private key to pkcs8 format private key rsa_private_key_pkcs8.pem openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem
```

## 7. How to Download Encrypted Data Fetching Results

If file storage service server-side encryption is configured, the fileKey field returned by the file pull interface is not empty. You need to decrypt it into a base64 filekey, and use it together with the decrypted fileUrl to download the file using the code below. The difference from normal file download is that three additional parameters for file download decryption are set in the header.

Note: Only files within 10 days can be retrieved (including original file and parsed result). Please timely retrieve and store the files.

```
@Test
void testDownloadUsingPresignedUrl() throws Exception{
        String presignedUrl = "https://evidence-file-1308262583.cos.ap-guangzhou.myqcloud.com/de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1646480278%3B1646480878%26q-key-time%3D1646480278%3B1646480878%26q-header-list%3Dhost%3Bx-cos-server-side-encryption-customer-algorithm%3Bx-cos-server-side-encryption-customer-key%3Bx-cos-server-side-encryption-customer-key-md5%26q-url-param-list%3D%26q-signature%3D7e752832991291f92df05edb949f56a3f99c2d2d";
        String fileKey = "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=";
        String downloadFileSavePath = "E:\\de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a _qqmail_jyls-0.pdf";
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

## 8. Production Pre-Launch Checklist

1. Common Sections

* Before going live, ensure that at least one full process (from a real entry point, completing Data Acquisition, receiving notifications, pulling files, and completing the business) has been tested successfully.
* Confirm that the production environment public key has been provided, the callback address remains unchanged, and all outbound IPs have been provided. Any changes must be notified at least 2 days in advance.

  * If possible, please provide the https certificate for the callback address, as our operations require it for security verification. If the https certificate for the callback address server was ignored in the test environment, please ensure to provide it.
* Confirm that the relevant IPs and domain names of the System Provider have been added to the whitelist.
* Confirm that the correct format of the System End-User agreement has been uploaded (if needed).
