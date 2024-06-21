## 1. Information Required from the System Integrator

Please Refer to the Corresponding H5 Integration Document.

## 2. Secure Login Authentication

When calling **all interfaces** in Chapter 3, it is **REQUIRED** to generate the authentication header using the method described in this chapter.

### 2.1 Notes

* All openapi requests are POST requests, and the content-type is always application/json.

### 2.2 Hash Algorithm

#### 2.2.1 Generate JSON Based on the Required Parameters of the Interface Request

For example, the interface request parameters are as follows:

```json
{
    "v": "1.0.0",
    "auth": {
        "appId": "IDAkEBvb",
        "nonce": "20rr7wbca98e8325f0fjd77yl130j6hi"
    },
    "arg": {
        "a": "xxx",
        "b": "xxx"
    }
}
```

#### 2.2.2 Sort the Keys of the Request Parameters JSON String in ASCII Dictionary Order

Note that the request parameters JSON is generally a multi-level structure, each level needs to be sorted by key in ASCII dictionary order.
For example, the sorted request parameters JSON are as follows:

```json
{
    "arg": {
        "a": "xxx",
        "b": "xxx"
    },
    "auth": {
        "appId": "IDAkEBvb",
        "nonce": "20rr7wbca98e8325f0fjd77yl130j6hi"
    },
    "v": "1.0.0"
}
```

#### 2.2.3 Serialize the JSON of the Request Parameters to a String

* Note: Remove all whitespace characters from the JSON string.

```java
{"arg":{"a":"xxx","b":"xxx"},"auth":{"appId":"IDAkEBvb","nonce":"20rr7wbca98e8325f0fjd77yl130j6hi"},"v":"1.0.0"}"
```

#### 2.2.4 Calculate the Hash

Append the appKey to the end of the sortedJson to get the sortedJsonWithKey string. Perform HMAC-SHA256 operation on sortedJsonWithKey (if needed, use the appKey as the key for the operation). Convert all characters of the resulting string to uppercase to get the unsignedData. Note: The length of the appKey is 64 bytes.

For example:

```java
sortedJsonWithKey = sortedJson + "FcuMaP8q39Q4IigraXdDKpvaOhF2PqNptq86ZHYRvtMjAdVZIOSEfW4t6IdxUJu9"; //Note: appKey is concatenated after sortedJson

decsHash = HMAC-SHA256("HmacSHA256", sortedJsonWithKey).toUpperCase() = "C3AF574420D41A7CEE9C44FCFC84FE15D36D5C97A80111278B82CCEAFCDC7C96";
```

Note: If using National Encryption Suite, use HMAC-SM3 to calculate the hash. Refer to  [HMAC-SM3 Code Example](https://shimo.im/docs/wV3VV8g0voTXj13y#anchor-jsmB)

#### 2.2.5 Add the Hash to the Request Header

Add a field DECSHASH to the HTTP Header, with the value being the hash calculated in the previous step.

```java
Map<String, String> header = new HashMap<>();
header.put("DECSHASH", decsHash);
```

#### 2.2.6 Full Example

```java
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

public class DecsHashTool {
    /**
     * 
     * @param data 
     * @param appKey  appKey
     * @return hash
     */
    public static String genDecsHash(String jsonString, String appKey) throws Exception {
        ObjectMapper sortedMapper = new ObjectMapper();
        sortedMapper.configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true);

        JsonNode node = sortedMapper.readTree(jsonString);
        Object obj = sortedMapper.treeToValue(node, Object.class);
        String sortedJson = sortedMapper.writeValueAsString(obj);

        StringBuilder sb = new StringBuilder(sortedJson);
        sb.append(appKey);

        return hMacSha256(sb.toString(), appKey);
    }

    /**
     * generate HmacSHA256
     * @param data 
     * @param appKey  
     * @return result
     * @throws Exception
     */
    public static String hMacSha256(String data, String appKey) throws Exception {
        Mac sha256_Hmac = Mac.getInstance("HmacSHA256");
        SecretKeySpec secret_key = new SecretKeySpec(appKey.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        sha256_Hmac.init(secret_key);
        byte[] array = sha256_Hmac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        StringBuilder sb = new StringBuilder();
        for (byte item : array) {
            sb.append(Integer.toHexString((item & 0xFF) | 0x100).substring(1, 3));
        }
        return sb.toString().toUpperCase();
    }

    public static void main(String[] args) throws Exception {
<<<<<<< HEAD
        // 1. 
=======
        // 1. get appKey
>>>>>>> 40ed950 (- Polish Grammar I)
        String appKey = "FcuMaP8q39Q4IigraXdDKpvaOhF2PqNptq86ZHYRvtMjAdVZIOSEfW4t6IdxUJu9";

        // 2. 
        String arg = "{\"v\":\"1.0.0\",\"auth\":{\"appId\":\"IDAkEBvb\",\"nonce\":\"20rr7wbca98e8325f0fjd77yl130j6hi\"},\"arg\":{\"a\":\"xxx\",\"b\":\"xxx\"}}";

        // 3. 
        String decsHash = genDecsHash(arg, appKey);
        System.out.println(decsHash);

        // 4. 
        Map<String, String> header = new HashMap<>();
        header.put("DECSHASH", decsHash）
    }
}
```

### 2.3 General Interface Error Code

When calling any interface, there is a small chance that some common interface errors may occur, as follows:

| Error Code | Error Message   | Description                                                         |
| :--------- | :-------------- | :------------------------------------------------------------------ |
| -48007     | ExternalLBError | External network redirect error (temporary), please try again later |
| -50005     | SignInvalid     | DECSHASH calculation error                                          |

## 3 Interface List

### 3.1 Update AES Encryption Key Interface

When the System Integrator calls the related interfaces of the Clean Environment (or receives notifications), in order to protect the sensitive information of the System End-User (user agreement, user name, user ID number, user's Original-File URL) from leakage, these sensitive information need to be encrypted using the AES algorithm. To ensure the security of the encryption and decryption key, it is recommended that the System Integrator periodically calls this interface to update the AES encryption key (hereinafter referred to as aesKey) together with the Clean Environment System Provider.

**Note**:

1. The frequency of updating the aesKey is controlled by the System Integrator. It is recommended to update it when the number of users is relatively small.
2. During the process of updating the aesKey by the System Integrator, there may be a time difference between the System Integrator and the Clean Environment System Provider in saving and using the new aesKey. At the moment of updating, the aesKey used for encryption and decryption on both sides may be inconsistent. If this happens, the request will fail and a specific encryption or decryption failure error code will be received. It is recommended that the System Integrator resend the request upon receiving such error code to avoid this issue.
3. If using National Encryption Suite, the returned aesKey is a symmetric encryption key of SM4. The SM4 algorithm uses ECB mode and P5 padding. For the following interfaces, both encryption and decryption need to use the SM4 algorithm instead of AES: start-vdi-x/start-vdi-miniapp-x/upload-user-protocol-x/get-original-files-x/get-parse-result-x/get-cert-result-x/sbox-white-list-x.

* Interface Call Method:

| Interface Name                                                                                 | Method | Content-Type     |
| :--------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Test Environment) https://testing-vdi.xxxx.xxx(System Provider Domain)/api/das/update-aes-key | POST   | application/json |
| (Production Environment) https://vdi.xxxx.xxx(System Provider Domain)/api/das/update-aes-key   | POST   | application/json |

Note: For the specific System Provider domain, please contact your Tech Support

* Request:

| Parameter Name | Type   | Description                                                                                   | Required | Length |
| :------------- | :----- | :-------------------------------------------------------------------------------------------- | :------- | :----- |
| v              | String | Version number, default is 1.0.0                                                              | Y        | 8      |
| auth           | Object |                                                                                               | Y        |        |
| auth.appId     | String | Pre-assigned appId                                                                            | Y        | 8      |
| auth.nonce     | String | 32-character random string (letters and numbers), a different value is required for each call | Y        | 32     |
| arg            | Object |                                                                                               | Y        |        |
| arg.ext        | Object | Reserved field, ext is an object used for extension                                           | N        |        |

* Request Parameter Example

```json
{
    "v": "1.0.0",
    "auth": {
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg": {
    }
}
```

* Response Parameters| Parameter    | Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                 | Required |
  | :----------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- |
  | errorCode    | int    | Return code: 0 for success, non-0 for failure                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               | Y        |
  | errorMessage | String | Description of the result                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   | Y        |
  | data         | Object | Return result (null if the call fails)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      | Y        |
  | data.aeskey  | String | Generated by the Clean Environment System Provider, encrypted with the System Integrator's RSA public key (provided when applying for appId), and then Base64 encoded. After receiving it, the System Integrator needs to decode it with Base64 and then decrypt it with their own RSA private key. Note: If using National Encryption Suite, the System Integrator needs to use SM2 private key to decrypt the aesKey, refer to[SM2 Decryption aesKey Code Example](https://shimo.im/docs/wV3VV8g0voTXj13y#anchor-oL6J) "National Encryption Suite Reference" | Y        |
* Response Parameter Example

```json
{
    "errorCode": 0,
    "errorMessage": "success",
    "data": {
        "aeskey":"B1gDtH8jPR8EL7P+NbuGOMiNA9rq9W4jwhfp/ucTxemktB41LgUGCK95e3obVfzzheJ0M+WpBD2O5fsacWWdYEany5PZLPWZH+jUhS02YySZCQQDeJEHQBnpYo66FZWAng6Yphs+8HDx8JBAC1prrGg4xJDt8X/xrItzMtHEPREpF+IR66NgNVLfiuSLXloNvi5irLHTatuP8glfriZnb1qHz26ocvNsepkVAXar4kmbXXf+L4VRn5fob5OedAZENObR/YH3vHGeEHfBTPLyAyG6cGOj1vkCRVgVIrW/HYIp9I5fPzNVTlu7xtmW18F5EbDOE+P3lOs/nj2PAWMlGg=="
    }
}
```

#### 3.1.1 Example for Decoding the aeskey in response

Java:

```java
@Test
void testRsaDecryptAesKey() throws  Exception {
    String base64AesEncyptedKey = "B1gDtH8jPR8EL7P+NbuGOMiNA9rq9W4jwhfp/ucTxemktB41LgUGCK95e3obVfzzheJ0M+WpBD2O5fsacWWdYEany5PZLPWZH+jUhS02YySZCQQDeJEHQBnpYo66FZWAng6Yphs+8HDx8JBAC1prrGg4xJDt8X/xrItzMtHEPREpF+IR66NgNVLfiuSLXloNvi5irLHTatuP8glfriZnb1qHz26ocvNsepkVAXar4kmbXXf+L4VRn5fob5OedAZENObR/YH3vHGeEHfBTPLyAyG6cGOj1vkCRVgVIrW/HYIp9I5fPzNVTlu7xtmW18F5EbDOE+P3lOs/nj2PAWMlGg==";
    String base64PrivateKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCfwaZpVL2K+1ZRMzublDVOL+S2GUPnnHULt+tQKCU1k9njQJx4Y288Opr5adXsXFbczTpl8nUL6823yVPH3Q46xSkbQ4oNEmHUU0sk5cwc9UURuyKYv+N8dm+ucxNB0uAYcQMmKnRt+jcoUoGoVX/S+0wb9WSnEGHrXVFvX+BdF1Y/R/kalJYeEgE2OwhMgZ3SiXGIPnozQyErp6/dxDClZJq2xukr5jNi0cCMYrSfrGdDdeiGceRy5B3g2TmcP046Ru1JgurkV5CpNKm9jtGB+Z/x4JrFRFY5eTsd4XxtJT4ZiScx+Ai7yNt3cdkTzku2VzuafG7grQNiEeIR6PabAgMBAAECggEAay+fen5bqdsWP+bS8ICQ/0OM/UyYTdaghVtB64bz6C2p/BpGoVN9t3hOsFb9K9eMhBrCOtJhC72LSesvZiJ/wJi2Cs/W2QxjTPURrtDrkOZTECFxhfEBLWm9ZttYqUpWBrAUf8/uTDecOFabHZk36ROoLf4IKTsJp8P1tncqbun/fJwDTn24oLH+8Nmp2f1J5xhgDID2KG+Wg8sI0mMQLD9Q+oUFGTVN9slJFM5OddufuAd4pOWbYN3h311L+eSzzMtH0nQgSyM0OHDXtJpBgv3eYsTh19Yb9Px+f+bPyhMPzGiNdy14QRpynGmt145WsnWCC1Asp1AcZDgVN+kjEQKBgQDhhOxYk1HUVeGSLh9MGwW0dtCenaObWEiCELbtSsCaprnndKl/UWe2V9zFCpaH3KZSerTALOdCRG/fMKtipBJIWZET4Pm4ZMlmH4Diw3VmsRnd5gl787gkREvBT9Rk2hXFlk4VIdUBzkuzxAdxGA4amC0b7Jsec1hAtJIos3Mo0wKBgQC1WU1MsDfwX4jmwywP0qL+0mP8DjZd8p+qFVYkICVwDQbhAjZhaoLTKV0plPqWILSTTHcHGpklbig3di3a7uFGQrZA0hJseO7MRpF0oi/gwEjvt1345ULirz8qhLEfmorndEuTo7O8lT8MJWLEJoGw5pMgcuJkNRv2aoUH/tHeGQKBgQCTyq2s+pbE5adXSjyefpMFilv7puliU7/o5RVMexGwCBWK9qxh0LJ8ECaRRvgRf2vMX7f2vTas+faquNWIZmfI3FG0Slq9GefWskyfz2Iv8141Spzqi3Ug51USEcPqd/WOsIrpVGuorE52N8B8wDv198aQJ0Yc9ZBfjza9z6RnmwKBgCaEsUZ4p2kG4a0iB1nVA4ncZiBDZIjP39ngbkt+CHWkTrG8JpDKbr8rKf6LBi6dA73FoAKCQ8UPgLtG/rZhxreFs/BQrlkb1pzM4FhFmqXCMbu41tzm1S4Qyvnc9UIhMR+4M9VIEAUeLiYGStQe2a0ZTGa4AB4IqcfNGDR6i1kBAoGALQyuNCWcNN7Soopjj6H4NHh/8G6Bbu/OeV5xFk5To15XWvaQNkSAdFL3OMdCBW8Mf8DNyeEi0VWZ2TrUkCCPUFvIAE9n9MJ3C/J6fI3Psmh4vvdJedMi3KNKWTqupAqqk5CZVegxUSj2XYEaORTd37Zhc+xTJTkR2XFb5ZbaNmo=";
    String base64AesKey = rsaDecryptBase64AesKey(base64AesEncyptedKey, base64PrivateKey);
        System.out.println(base64AesKey);
    }

    public String rsaDecryptAesKey(String base64AesEncyptedKey, String base64PrivateKey) throws Exception {
        byte[] aesEncyptedBytes =  Base64.getDecoder().decode(base64AesEncyptedKey);
        PrivateKey privateKey = string2PrivateKey(base64PrivateKey);
        byte[] aesBytes = privateDecrypt(aesEncyptedBytes, privateKey);
        String base64AesKey = Base64.getEncoder().encodeToString(aesBytes);
        return base64AesKey;
    }

    public byte[] publicEncrypt(byte[] content, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public byte[] privateDecrypt(byte[] content, PrivateKey privateKey) throws  Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] bytes = cipher.doFinal(content);
        return bytes;
    }

    public PublicKey string2PublicKey(String base64PublicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    public PrivateKey string2PrivateKey(String base64PrivateKey)  throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(base64PrivateKey);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }
```

NodeJs:

Due to NodeJs's default encryption component `node-rsa` library, which uses pkcs1-oaep mode by default for RSA requests with pkcs1 mode, you need to manually specify the library to use pkcs1:

![图片](data:image/jpg;base64,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H9raf/z1/wDHW/wo/snT/wDnl/483+NH9k6f/wA8v/Hm/wAaAD+1tP8A+ev/AI63+FIdW0/H+t/8db/Cl/snT/8Anl/483+NI2k6fj/Vf+PN/jQBH/a2n9fN/wDHT/hTP7W0/p5vH+6cfyqT+ydP/wCeX/jzf41H/ZOn/wDPL3+8f8aAGDVbAn/W/wDjrH+lO/tWw/56/wDjjf4Uw6Tp+ceTn23N/jR/ZFh/z7/+PNQB/9b9/K5PSP8AkafEH/bp/wCizXWVyekf8jT4g/7dP/RZoA6yiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigAooooAKKKKACiiigApD0paDQBEvI/SmA5GfepE+6frUS/dH1oAFG4Z6fSnbPc/nSR/dFSUAf/9k=)

For AES, use aes-128-ecb as default ciper

<!-- ### 3.2 start-vdi-miniapp-x Interface (for accessway: miniapp)

* Interface Description:

Before redirecting to the Clean Environment, the System Integrator needs to call this interface to apply for a VDI machine. After a successful call, the backend will return some information for the System Integrator's miniapp to redirect to the Clean Environment Data Acquisition miniapp page.

* Note: If the user experience involves clicking a button that triggers the backend to call this interface, ensure proper interaction limitations to prevent users from quickly repeating clicks (which could prematurely end the data acquisition). The recommended experience is:

  1. The user clicks the button.
  2. The button shows a loading spinner (during which the button is disabled to prevent further clicks, **with a click frequency limit set**).
  3. The backend of the System Integrator triggers the call to this interface (i.e., start-vdi-miniapp-x).
  4. The interface request returns or times out.
  5. The spinner stops. If the interface returns successfully, redirect to the Clean Environment miniapp; if the interface fails, display the corresponding error message.
* Note: When using the Weixin Miniapp integration, it is recommended that the System Integrator implement necessary gray-scale release on the user side. After validating the production environment, then proceed to full-scale release. The gray-scale proportion of the miniapp, service number, and public account is controlled by the Weixin backend system. Therefore, setting the gray-scale proportion on the frontend can improve the system's stability threshold and prevent a system crash.
* Interface Call Method:

| Interface Name                                                                                      | Method | Content-Type     |
| :-------------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Testing Environment)  https://testing-vdi.`<System Provider Domain>`/api/das/start-vdi-miniapp-x | POST   | application/json |
| (Production Environment)  https://vdi.`<System Provider Domain>`/api/das/start-vdi-miniapp-x      | POST   | application/json |

Note: For the specific System Provider domain, contact your Tech Support.

* Request Param

| Parameter Name                                | Type         | Description                                                                                                                                                                                                                                                                                                      | Required | Length Limit                                                       |
| :-------------------------------------------- | :----------- | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :----------------------------------------------------------------- |
| v                                             | String       | Version number, default is 1.0.0                                                                                                                                                                                                                                                                                 | Y        | 8                                                                  |
| auth                                          | Object       |                                                                                                                                                                                                                                                                                                                  | Y        |                                                                    |
| auth.appId                                    | String       | Pre-assigned appId                                                                                                                                                                                                                                                                                               | Y        | 32                                                                 |
| auth.nonce                                    | String       | 32-character random string (letters and numbers), must be different for each call                                                                                                                                                                                                                                | Y        | 32                                                                 |
| arg                                           | Object       |                                                                                                                                                                                                                                                                                                                  | Y        |                                                                    |
| arg.bizScenario                               | String       | Business type, System Integrator should fill in "general"                                                                                                                                                                                                                                                        | Y        | 32                                                                 |
| arg.site                                      | String       | Data Source of the user                                                                                                                                                                                                                                                                                          | Y        | 32                                                                 |
| arg.bizNo                                     | String       | Business serial number. It is recommended to design a unified rule such as entry channel for future expansion                                                                                                                                                                                                    | Y        | 60                                                                 |
| arg.openId                                    | String       | User identifier in the System Integrator, used to locate the user of this VDI session.*Note: The System Integrator needs to encrypt this field using aesKey and then encode it in Base64.*                                                                                                                     | Y        | 128                                                                |
| arg.idNo                                      | String       | User's ID number.**The System Integrator must first verify the validity of the ID number and reject requests that do not match the ID number format and length.** Note: The System Integrator needs to encrypt this field using aesKey and then encode it in Base64.                                       | Y        |                                                                    |
| arg.userName                                  | String       | Real name of the user after the System Integrator's KYC, displayed on our page.*Note: The System Integrator needs to encrypt this field using aesKey and then encode it in Base64.*                                                                                                                            | Y        |                                                                    |
| arg.userClaim                                 | String       | A statement from the user, currently "This user has completed face verification/password verification/police/WeChat police identity verification".*Note: The business side fills in the text based on the actual verification method.*                                                                         | Y        | 128 characters (bytes), note that it is not 128 Chinese characters |
| arg.width                                     | unsigned int | Phone screen width, must be an integer                                                                                                                                                                                                                                                                           | Y        |                                                                    |
| arg.height                                    | unsigned int | Phone screen height, must be an integer                                                                                                                                                                                                                                                                          | Y        |                                                                    |
| arg.accessWay                                 | String       | Possible accessWay values                                                                                                                                                                                                                                                                                        | Y        |                                                                    |
| arg.ext                                       | Object       | Backup field, ext is an object used for expansion                                                                                                                                                                                                                                                                | N        |                                                                    |
| arg.ext.attach                                | String       | Additional data. If passed, it will be included in the notification data's ext field                                                                                                                                                                                                                             | N        | 128 characters (bytes), note that it is not 128 Chinese characters |
| arg.ext.urlattach                             | String       | Return URL additional field (only for h5 integration). Used to attach extra parameters when redirecting back to the frontend page of the System Integrator. Pass it in start-vdi, and after data acquisition is completed, the URL will carry this parameter: key is attach_url, value is the value passed here. | N        | 12 characters                                                      |
| arg.ext.childSites                            | Array        | When arg.site is Alipay all-in-one, the values in the childSites array can only be selected from the following fields: [app-alipay-huabei, app-alipay-jiebei, app-alipay-cr, app-alipay-wsd]                                                                                                                     | N        |                                                                    |
| arg.ext.tmriValidDays                         | Integer      | Valid days of safe driving records, must pass an integer between 1-90. If not passed or the value is not in the 1-90 range, it will be automatically set to the default value of 7.                                                                                                                              | N        | 1-90 integer                                                       |
| arg.ext.companyFullName                       | String       | Organization name (only open for specific channels)                                                                                                                                                                                                                                                              | N        | 32 characters                                                      |
| arg.ext.companyShortName                      | String       | Organization abbreviation (only open for specific channels)                                                                                                                                                                                                                                                      | N        | 32 characters                                                      |
| arg.ext.contactInfo                           | String       | Contact information (only open for specific channels)                                                                                                                                                                                                                                                            | N        | 32 characters                                                      |
| arg.ext.downloadAuthorizationSeparateDocument | String       | Separate download authorization text (only open for specific channels)                                                                                                                                                                                                                                           | N        | 128 characters                                                     |
| arg.ext.downloadAuthorizationMergeDocument    | String       | Merged download authorization text (only open for specific channels)                                                                                                                                                                                                                                             | N        | 50 characters                                                      |

**Remark 1：Getting Weixin Miniapp Resolution (arg.width and arg.height)：**

Use **wx.getSystemInfo(Object object)** to get **windowWidth** and **windowHeight** and pass into start-vdi-miniapp API.

```plain
let windowWidth = 0
let windowHeight = 0
wx.getSystemInfo({
  success: (result) => {
    windowWidth = result.windowWidth
    windowHeight = result.windowHeight
  }
})
```

* start-vdi-miniapp-x Request Parameter Example

```json
{
    "v": "1.0.0",
    "auth": {
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg": {
        "accessWay": "miniapp",
        "bizScenario": "general",
        "site": "tax",
        "bizNo": "we1386584661349863900",
        "openId": "YUIQMwxnnDCkcqxhkXKxfsonbNSlxK",
        "idNo": "CgTQVFABGQMwxnnDCkcqxhkXKxfsonbNSlxK",
        "userName": "IYTQMwxnnDCkcqxhkXKxfsonbNSlxK",
        "userClaim": "User KYCed using Passport",
        "ua": "xxxx",
        "width": 750,
        "height": 1334,
        "ext": {
            "unzipPassword": "123456"
        }
    }
}
```

* Response Parameters:

| Parameter        | Type   | Description                                          | Required |
| :--------------- | :----- | :--------------------------------------------------- | :------- |
| errorCode        | int    | Result return code: 0 for success, non-0 for failure | Y        |
| errorMessage     | String | Description of the return result                     | Y        |
| data             | Object | Return result (if the call fails, return null)       | Y        |
| data.daId        | String | Globally unique data acquisition request ID: daId    | Y        |
| data.redirectUrl | String | URL for miniapp redirection                          | Y        |
| data.mpAppId     | String | AppId of the miniapp to be redirected to             | N        |

* Special Error Codes

| Error Code | Error Message                                 | Description                                                                                                                                                                                                                                                                                                                                                                                                                            |
| :--------- | :-------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -43037     | AES_DECRYPT_EXCEPTION                         | AES decryption failed, please use the latest AES key                                                                                                                                                                                                                                                                                                                                                                                   |
| -45001     | StartLockVMError                              | No available VDI machines, please try again later                                                                                                                                                                                                                                                                                                                                                                                      |
| -45004     | StartVMError                                  | Temporary network error, please try again later                                                                                                                                                                                                                                                                                                                                                                                        |
| -45027     | ExistingDownloadingDaTask                     | Current user has a data acquisition task downloading, please try again later                                                                                                                                                                                                                                                                                                                                                           |
| -45030     | StartParamIdNoLessError                       | ID number indicates age less than 18                                                                                                                                                                                                                                                                                                                                                                                                   |
| -45031     | StartParamIdNoError                           | ID number format error                                                                                                                                                                                                                                                                                                                                                                                                                 |
| -45028     | IdNoDailyRequestError                         | Daily access limit exceeded                                                                                                                                                                                                                                                                                                                                                                                                            |
| -45032     | IdNoCurrentRequestError                       | User access too frequent, please try again later                                                                                                                                                                                                                                                                                                                                                                                       |
| -48007     |                                               | Temporary network error                                                                                                                                                                                                                                                                                                                                                                                                                |
| -48025     | DataSourceUnavailable                         | Current data type unavailable (critical!). When receiving this request, it is recommended to temporarily close the data type acquisition entry.**It is recommended that the System Integrator regularly call the [3.7 Interface](/en/access/main?id=_37-pull-interface-for-current-data-type-status) in this page.**                                                                                                                |
| -50001     | Miniapp generic error after entry             | Troubleshoot based on the following:   - Check the sign algorithm and related code   - Check if the public/private key pair is configured correctly  - Check if the miniapp ID is correctly filled  - Check if the front-end specified envVersion is correct (release for production, trial for testing)  - Check if the appId is correctly filled during the redirection and matches the one used for generating the redirection link |
| -50002     | SiteInvalid                                   | Data source not enabled, please contact your support                                                                                                                                                                                                                                                                                                                                                                                   |
| -50006     | Sign calculation error after entering miniapp | Troubleshoot based on the following:   - Check if the miniapp is correctly redirected and if the envVersion is correctly set  - Check if the public key is correctly provided and configured  - Check if the public key works without issues in the testing environment                                                                                                                                                                |

```json
{
    "errorCode": 0,
    "errorMessage": "succ",
    "data": {
        "daId":"de1tuknz1500809629993668608",
        "redirectUrl": "pages/vdi/vdi/?daId=de1tuknz1500809629993668608&vcode=vnLoTSazp7-n6W3vOtioPkU1RQHneTlrQ43Ii4QFVXg%3D&site=tax&appId=de3AtDFY&bizScenario=general&accessWay=miniapp&fullUrl=true",
        "mpAppId": "wx73a4bdd6ff058974"
    }
}
```

* Note: When the returned errorCode is 0, both daId and redirectUrl must not be empty to redirect to the Clean Environment Weixin Miniapp.
* Note: The generated link is valid for 8 minutes (vcode expiration time). If not clicked within this time, it will prompt that it has expired; if clicked and entered for data acquisition, the operation timeout is 10 minutes for non-email mode and 60 minutes for email mode. If it times out, it will prompt that the link has expired.
* Note: Regarding re-entry to this generated link: For security and anti-re-entry considerations, the generated link can only be used to create a login state once. This means that as long as the login state is maintained, the miniapp can be refreshed inside, and it can also be briefly sent to the background and brought back without affecting the current data acquisition. However, if the System End-User re-clicks the previous URL, it will cause the login state to be recreated, and it will feedback that the link has expired, requiring a new call to start-vdi.

#### 3.2.1 How to Enter the Clean Environment's Weixin Miniapp

#### 3.2.1.1 Generating Signature Field

Using the private key from the RSA key pair generated by the System Integrator (the public key needs to be provided in advance), sign the `redirectUrl` in the returned parameters to obtain the `sign` field. Refer to the `sign` method for details:

```java
String sign = sign(redirectUrl, privateKey)；

import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;

public class CryptoTool {
    /**
     * 
     * @param plainText  
     * @param privateKey 
     * @return 
     * @throws Exception
     */
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(plainText.getBytes());
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * 
     * @param plainText 
     * @param signature 
     * @param publicKey 
     * @return 
     * @throws Exception
     */
      public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(plainText.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }
}
```

#### 3.2.1.2 Generating Redirect Page Path

* **Call `encodeURIComponent()` on the `sign` value to perform URI encoding; note that this method is in JavaScript, not Java. These two implementation methods are different! If you must use Java to encode, you can refer to our sample code.**
* **Concatenate the `sign` parameter to our miniapp path to obtain the complete path for redirecting to our miniapp.**

Sample code for concatenating the path is as follows:

```java
StringBuilder sb = new StringBuilder();
sb.append(redirectUrl);
sb.append("&")
sb.append("sign=")
sb.append(URIEncoder.encodeURIComponent(sign))
path = sb.toString();

public class URIEncoder {

private static final String CHARSET = StandardCharsets.UTF_8.name();

    private static final String[][] CHARACTERS = {
        { "\\+", "%20" },
        { "%21", "!"   },
        { "%27", "'"   },
        { "%28", "("   },
        { "%29", ")"   },
        { "%7E", "~"   }
    };

    public static String encodeURIComponent(String text) {
        String result;
        try {
            result = URLEncoder.encode(text, CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        for (String[] entry : CHARACTERS) {
            result = result.replaceAll(entry[0], entry[1]);
        }
        return result;
    }
}

```

```plain
pages/vdi/vdi/?daId=de1tuknz1500809629993668608&vcode=vnLoTSazp7-n6W3vOtioPkU1RQHneTlrQ43Ii4QFVXg%3D&site=tax&appId=de3AtDFY&bizScenario=general&accessWay=miniapp&fullUrl=true&sign=tR2vuBjqGasXKvXlP7wTjU5dL53iQU%2F9qeCjOepqTKoTv4RyO5dLIlvnyjRclOEY1j5lb1sBIkPd3C20IBSJDoz3%2BY9knNcBX0%2FCloNxAxnOsnCqtuNkferW%2BfZzbgOyGvTDEbZ%2Fmqe6BXco%2BOCyE%2FqNF0hAj7lMIn76Hb3IpzMz0%2FC0lg7rko3gm7JURB%2BQoKeTv3m7hGLXRSwjSsWZDOHNZSq5csn9Do1Q81FzoAmwJbXKkma0DzeyQvjYheGC%2BF2SrNe3NccXh59VTkCI%2FwykEp7Zl2XgHOPu8KLGrUN68b5QERlhOC9VSM8EueAOordlYHlW8Sy6JTWr%2FZEqxQ%3D%3D
```

#### 3.2.1.3 Entering the data acquisition Collection Page

**I. If you are using accessWay as miniapp or miniappwithca:**

You need to use the complete path and concatenated parameters obtained in step 3 to redirect to our miniapp data acquisition collection page. Please use this API from the Weixin SDK: https://developers.weixin.qq.com/miniprogram/dev/api/navigate/wx.navigateToMiniProgram.html

* Our miniapp
  * Original ID for the test environment miniapp (Cunzhengbao): gh_30e07f8dff2a
    * AppId: **Use the `mpAppId` value returned by the start-vdi-miniapp-x interface**
    * Also, specify: envVersion: 'trial'
    * Also, provide the WeChat ID of the tester for enabling trial permissions
  * **Original ID for the production environment miniapp: gh_0239e2817df3,** ***keep `envVersion` as release***

**II. If you are using accessWay as weh52miniapp or weh52miniappwithca:**

You need to integrate the Weixin JS SDK and use its built-in redirection method. In your public account configuration, redirect to enter the clean environment for data acquisition. You can contact us to obtain the demo code for Weixin H5 redirection.

Note: **This method does not require setting `envVersion`**. Tencent officially restricts this method to only redirect to the release version of the miniapp.

Note: The link used to launch the miniapp returned by start-vdi must be clicked to access the data acquisition within 8 minutes, otherwise, it will expire. If in the scenario of the integrator, users cannot click this link in time, it is recommended to regenerate the link for the user; a better solution is to direct the user's link to a H5 transit page of the partner, and then call start-vdi to generate the link and redirect for data acquisition on this page.

#### 3.2.2 Handling of the Return Value after data acquisition Ends

* To return to the source miniapp, the integrator's miniapp needs to use the Weixin Miniapp API to jump back from our miniapp to the original miniapp, and at the same time, use the global App.onShow to get the returned parameters (daId, site, daStatus, with the key as status) —— but the values of these parameters are not reliable (such as many times they may not be obtained). **You need to obtain accurate data acquisitionprocess status and results through receiving backend notifications (section 7.3) or polling data acquisition status (interface 3.8).**

#### 3.2.3 Code Example for Symmetric Encryption of Parameter Fields

```java
@Test
void testEncryptAes() throws Exception {
    String base64AesKey = "2EdTm/RolkL0RjVBXhSAUA==";
    SecretKey key = loadAesKey(base64AesKey);

    String base64EncryptedValue = encryptAES("this is test string", key);
    log.info("base64EncryptedValue:{}", base64EncryptedValue);
}

public SecretKey loadAesKey(String base64Aeskey) {
        byte[] bytes = Base64.getDecoder().decode(base64Aeskey);
        SecretKey key = new SecretKeySpec(bytes, "AES");
        return key;
}

public String encryptAES(String value, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        String base64EncryptedValue = Base64.getEncoder().encodeToString(bytes);
        return base64EncryptedValue;
}
``` -->

### 3.3 start-vdi-x interface (for accessway: H5/SDK)

* Interface Description:

Before accessing the clean environment, the integrator needs to call this interface to request a VDI slot. After successful invocation, the backend will return a URL link for the integrator's frontend page to redirect to.

* Note: If the user experience triggers the integrator's backend call to this interface by clicking a button, be sure to limit the interaction to prevent rapid repetitive clicks by users (rapid repetitive clicks will cause premature termination of user data acquisition). Recommended user experience is as follows:

  1. User clicks the button
  2. Button starts triggering animation (during animation triggering, user cannot click again)
  3. Trigger integrator's backend call to this interface (start-vdi-x)
  4. This interface request returns or times out
  5. Stop triggering animation. If this interface returns successfully, redirect to the clean environment; if it fails, prompt the corresponding error.
* Interface Invocation Method:

| Interface Name                                                                                    | Method | Content-Type     |
| :------------------------------------------------------------------------------------------------ | :----- | :--------------- |
| (Testing Environment)  https://testing-vdi..xxxx.xxx(Service Provider Domain)/api/das/start-vdi-x | POST   | application/json |
| (Production Environment)  https://vdi..xxxx.xxx(Service Provider Domain)/api/das/start-vdi-x      | POST   | application/json |

Note: Please contact your tech support for specific Service Provider Domain.

* Request Param

| Parameter Name                                | Type         | Description                                                                                                                                                                                                                                                                                                                                                                | Required | Length Limit                                           |
| :-------------------------------------------- | :----------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :----------------------------------------------------- |
| v                                             | String       | Version number, default is 1.0.0                                                                                                                                                                                                                                                                                                                                           | Y        | 8                                                      |
| auth                                          | Object       |                                                                                                                                                                                                                                                                                                                                                                            | Y        |                                                        |
| auth.appId                                    | String       | Pass in the pre-assigned appId                                                                                                                                                                                                                                                                                                                                             | Y        | 8                                                      |
| auth.nonce                                    | String       | 32-bit random string (random string composed of letters and numbers), different values must be passed each time it is called                                                                                                                                                                                                                                               | Y        | 32                                                     |
| arg                                           | Object       |                                                                                                                                                                                                                                                                                                                                                                            | Y        |                                                        |
| arg.bizScenario                               | String       | Business type, fill in general directly for integrators                                                                                                                                                                                                                                                                                                                    | Y        | 32                                                     |
| arg.site                                      | String       | The data source                                                                                                                                                                                                                                                                                                                                                            | Y        | 32                                                     |
| arg.bizNo                                     | String       | Business serial number. It is recommended to design a unified rule such as entry channel, etc., for easy expansion in the future                                                                                                                                                                                                                                           | Y        | 60                                                     |
| arg.openId                                    | String       | Identity identifier of the user in the integrator, used to locate the user using VDI this time*Note: The integrator needs to encrypt this field using aesKey first, and then Base64 encode it.*                                                                                                                                                                          | Y        | 128                                                    |
| arg.idNo                                      | String       | The ID card number of the user using VDI.**The integrator needs to validate the legality of the ID card number first and reject requests that do not conform to the format and length of the ID card number.**  *Note: The integrator needs to encrypt this field using aesKey first, and then Base64 encode it.*                                                  | Y        |                                                        |
| arg.userName                                  | String       | The real name of the user after completing the KYC of the integrator, which will be displayed on our page.*Note: The integrator needs to encrypt this field using aesKey first, and then Base64 encode it.*                                                                                                                                                              | Y        |                                                        |
| arg.userClaim                                 | String       | The text of the user's declaration, which is currently "The user has completed face recognition/password verification/public security/wechat police identity authentication".*Note: Business entities fill in the text according to the actual identity verification method.*                                                                                            | Y        | 128 characters (byte) Note: Not 128 Chinese characters |
| arg.ua                                        | String       | User agent of the user's terminal device, the purpose is to simulate the user's real mobile phone environment as much as possible, can be obtained from the front-end webview attribute. If it cannot be obtained (such as in the H5 scenario), a fixed value can be passed.                                                                                               | Y        |                                                        |
| arg.width                                     | unsigned int | Terminal screen width (the width of the expected user's visible area), must be an integer                                                                                                                                                                                                                                                                                  | Y        |                                                        |
| arg.height                                    | unsigned int | The height of the expected user's visible area (the height of the terminal screen, excluding the height of the top nav bar, bottom tab bar, etc.), must be an integer                                                                                                                                                                                                      | Y        |                                                        |
| arg.accessWay                                 | String       | Access method. Fill in "h5".                                                                                                                                                                                                                                                                                                                                               | Y        |                                                        |
| arg.ext                                       | Object       | Spare field, ext is an object for extension                                                                                                                                                                                                                                                                                                                                | N        |                                                        |
| arg.ext.attach                                | String       | Additional data, if passed in, this field will be carried in the ext of the backend notification data                                                                                                                                                                                                                                                                      | N        | 128 characters (byte), note not 128 Chinese characters |
| arg.ext.urlattach                             | String       | Additional field for callback URL (only for H5 access). Used to carry additional parameters when returning from our authorization page to the integrator's H5 page. When the user returns from our authorization page to the integrator's H5 page after completing data acquisition, the URL will carry this parameter: key is attach_url, value is the value passed here. | N        | 12 characters                                          |
| arg.ext.childSites                            | Array        | Child Sites information                                                                                                                                                                                                                                                                                                                                                    | N        |                                                        |
| arg.ext.tmriValidDays                         | Integer      | The number of days the secure driving record is valid, needs to be an integer value between 1-90. If not passed or passed value is not in the range of 1-90, the default value of 7 will be automatically set                                                                                                                                                              | N        | Integer value between 1-90                             |
| arg.ext.companyFullName                       | String       | Organization name (only open to specific channels)                                                                                                                                                                                                                                                                                                                         | N        | 32 characters                                          |
| arg.ext.companyShortName                      | String       | Organization abbreviation (only open to specific channels)                                                                                                                                                                                                                                                                                                                 | N        | 32 characters                                          |
| arg.ext.contactInfo                           | String       | Contact information (only open to specific channels)                                                                                                                                                                                                                                                                                                                       | N        | 32 characters                                          |
| arg.ext.downloadAuthorizationSeparateDocument | String       | Download authorization separate document (only open to specific channels)                                                                                                                                                                                                                                                                                                  | N        | 128 characters                                         |
| arg.ext.downloadAuthorizationMergeDocument    | String       | Download authorization merge document (only open to specific channels)                                                                                                                                                                                                                                                                                                     | N        | 50 characters                                          |

* Request Param Example

```json
{
    "v": "1.0.0",
    "auth": {
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg": {
        "bizScenario": "general",
        "site": "tax",
        "bizNo": "we1386584661349863900",
        "openId": "IIIQMwxnnDCkcqxhkXKxfsonbNSlxK",
        "idNo": "YUIQMwxnnDCkcqxhkXKxfsonbNSlxK",
        "userName": "OOOEwxnnDCkcqxhkXKxfsonbNSlxK",
        "userClaim": "User KYCed using Passport",
        "ua": "xxxx",
        "width": 750,
        "height": 1334,
        "ext": {
            "unzipPassword": "123456"
        }
    }
}
```

* Response Param

| Parameter        | Type   | Description                                               | Required |
| :--------------- | :----- | :-------------------------------------------------------- | :------- |
| errorCode        | int    | The return code of the result: 0: success, non-0: failure | Y        |
| errorMessage     | String | Description of the return result                          | Y        |
| data             | Object | Return result (null if the call fails)                    | Y        |
| data.daId        | String | The globally unique data acquisition serial ID: daId      | Y        |
| data.redirectUrl | String | The page for accessing VDI                                | Y        |

* Special Error Codes

| ErrorCode | ErrorMessage              | Description                                                                                                                                                                                                                            |
| :-------- | :------------------------ | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| -43037    | AES_DECRYPT_EXCEPTION     | AES decryption failed, please use the latest AES key                                                                                                                                                                                   |
| -45001    | StartLockVMError          | No available VDI slots, please try again later                                                                                                                                                                                         |
| -45004    | StartVMError              | Temporary network error, please try again later                                                                                                                                                                                        |
| -45027    | ExistingDownloadingDaTask | The current user already has a data acquisition task in progress, please try again later                                                                                                                                               |
| -45030    | StartParamIdNoLessError   | ID card number is less than 18 years old                                                                                                                                                                                               |
| -45031    | StartParamIdNoError       | Incorrect format of ID card number                                                                                                                                                                                                     |
| -45028    | IdNoDailyRequestError     | Exceeded the total number of visits for the day                                                                                                                                                                                        |
| -45032    | IdNoCurrentRequestError   | User access is too frequent, please try again later                                                                                                                                                                                    |
| -48007    |                           | Temporary network error                                                                                                                                                                                                                |
| -48025    | DataSourceUnavailable     | The current data type is unavailable (serious!). When receiving this request, please temporarily close the data type access. It is recommended that the integrator regularly call interface 3.7 to fetch the current data type status. |
| -50002    | SiteInvalid               | Data source not enabled, please contact your tech support                                                                                                                                                                              |

* Response Parameter Example

```json
{
    "errorCode": 0,
    "errorMessage": "succ",
    "data": {
        "daId":"de1tuknz1500809629993668608",
        "redirectUrl": "https://testing-vdi.<Service Provider Domain>/vdi/vdi.html?daId=de1tuknz1500809629993668608&vcode=A86uXkYbIEwuFnr2y0ibZ9qjBGC3-X0D5HJKiylEMwA=&site=chsi&bizScenario=general&appId=de1tuknz&accessWay=sdk&fullUrl=true"
    }
}
```

Note: The generated link is valid for 8 minutes (expiration time of vcode). If it is not clicked to enter within this time, it will expire. If clicked and entered, the operation timeout is 10 minutes. If timed out, it will prompt that the link has expired.

Note: Regarding re-entry to this link: For security and prevention of re-entry, the generated link can only be used to generate a login state once, meaning as long as the login state is maintained, it can be refreshed in the webview or suspended (such as pulling down to the bottom right corner in H5 mode within the WeChat ecosystem), or switched to the background, all without affecting the current data acquisition. However, if the integrator's user clicks the URL again to enter, it will cause the login state to be rebuilt, and at this time, it will prompt that the link has expired, and start-vdi needs to be called again.

Note: If accessing through H5 within the app, and the data source type that needs to be integrated requires face recognition (such as housing fund), please pay attention to the following points:

* Your app needs to have already requested camera permissions;
* If your app is an Android version, it needs to be able to respond to webview's camera activation request. If your app has not implemented this function yet, we can provide sample reference code.

#### 3.3.1 How to redirect to and load the returned URL

1. Sign the `redirectUrl` in the returned parameters using the private key of the RSA key pair generated by the integrator itself (the public key needs to be provided to us in advance), and obtain the `sign` field.

```java
String sign = sign(redirectUrl, privateKey)；
```

2. Generate the complete URL to enter the VDI page:

- Concatenate the generated signature after the redirectUrl. Example:

```plain
https://testing-vdi.<Service Provider Domain>/vdi/vdi.html?daId=de1tuknz1500809629993668608&vcode=A86uXkYbIEwuFnr2y0ibZ9qjBGC3-X0D5HJKiylEMwA=&site=chsi&bizScenario=general&appId=de1tuknz&accessWay=sdk&fullUrl=true&sign=mGXan8cwSEpdoQaYU/wHD+Pos4Kxi+7NlLKvm3EcYaqUu8aJGqpgmmtfJqYSzhqhyPZw19iMGn16G9dd5ZzsYC3fNXYTRcn2jOmlFAPWGmi04WZGZUMt9d6uQy3Yfmlf7OLCFMFXDAFubv6QStuVegLYuBA2kdc4iMpqHcEOtT1YyL4fTepJRSiMQA21i+NE6Y8oxOaPj+qW7vl9RpK1dOxkio6eb6/c22IGVapwXHrKsOp1RoS+nO2ddk1MKFTYI9xsrPkry5LL2GCL80DEhinQ5uc90bgwd7Rh8tDm3qjxVdtVPZxAO2Bdic+4YGwJzoCyJ82NNf0dpmIzBbDgRw==
```

3. Load the URL

* Simply Load this concatenated URL in your WebView container

4. Example

```
import java.security.PrivateKey;
import java.security.Signature;
import java.util.Base64;
public class CryptoTool {
    /**
     * 
     * @param plainText  
     * @param privateKey
     * @return 
     * @throws Exception
     */
    public static String sign(String plainText, PrivateKey privateKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(privateKey);
        sig.update(plainText.getBytes());
        byte[] signatureBytes = sig.sign();
        return Base64.getEncoder().encodeToString(signatureBytes);
    }

    /**
     * 
     * @param plainText 
     * @param signature 
     * @param publicKey 
     * @return 
     * @throws Exception
     */
      public static boolean verify(String plainText, String signature, PublicKey publicKey) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(plainText.getBytes());
        return sig.verify(Base64.getDecoder().decode(signature));
    }
}
```

#### 3.3.2 Handling of Data Acquisition Completion Return Values

* After the user completes the operation, the VDI page will open the integrator's result page and carry the parameters bizNo, daId, daStatus, site, and possibly attach_url and status.
* Example of the result URL:

```plain
https://www.yyy.com/jumpChannel.html?attach_url=channel_a&bizNo=acf1700443444e7b9206c6d5b36ec955&daId=zd240e1e1722158295759228928&site=app-tax-income&daStatus=10
```

#### 3.3.3 Example Code for Encrypting Parameters Before Calling

```
@Test
void testEncryptAes() throws Exception {
    String base64AesKey = "2EdTm/RolkL0RjVBXhSAUA==";
    SecretKey key = loadAesKey(base64AesKey);

    String base64EncryptedValue = encryptAES("this is test string", key);
    log.info("base64EncryptedValue:{}", base64EncryptedValue);
}

public SecretKey loadAesKey(String base64Aeskey) {
        byte[] bytes = Base64.getDecoder().decode(base64Aeskey);
        SecretKey key = new SecretKeySpec(bytes, "AES");
        return key;
}

public String encryptAES(String value, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(value.getBytes(StandardCharsets.UTF_8));
        String base64EncryptedValue = Base64.getEncoder().encodeToString(bytes);
        return base64EncryptedValue;
}
```

### 3.4 User Agreement Signing Interface

* Interface Description:

Before accessing the clean environment officially, the System Integrator needs to prompt the System Provider's end user to sign a user agreement with the clean environment service provider and upload it upon completion.**For this interface, it is not necessary to call in scenarios where miniappwithca and fullminiapp are used for access.****This interface can be called asynchronously. If the call fails, it does not affect the mainstream process of user data acquisition.**

* Agreement Requirements:

1) When the user selects to submit the corresponding data type (site) in the interface, the corresponding agreement template should be used for signature (we provide a template, only the **Chinese name of the data type** changes according to the **site**, others remain consistent), and it should be in PDF format. The content to be replaced is in green (replaced twice throughout the document). The correspondence between the Chinese name of the data type and the site can be found in Appendix Chapter Two, the last column of the English values.
2) The current user's name and ID card number (plaintext) should be dynamically written in the space for name and ID card number at the beginning of the document.
3) At the end of the document, use CA signature (call the System Integrator to provide electronic signature to the end user), and add the date.
4) After signing, upload the signed PDF file through the 3.4 interface each time it is called.Note: The agreement can be reused, based on the user's ID card number (idNo) + data type (site) dimension. For example: If Zhang San retrieves data type A, one agreement can be signed, but each time Zhang San submits A, this agreement needs to be sent through the interface.
5) The agreement needs to be sent before the user operation is completed to ensure timely receipt of notifications and timely pulling of data acquisition files.
   Attention: **According to business requirements, each System Integrator must ensure that each user, and each data type requested by the user, uploads a user agreement, otherwise we reserve the right to suspend services**.

* Interface Invocation Method:

| Interface Name                                                                                          | Method | Content-Type     |
| :------------------------------------------------------------------------------------------------------ | :----- | :--------------- |
| (Test Environment) https://testing-vdi.xxxx.xxx(Service Provider Domain)/api/das/upload-user-protocol-x | POST   | application/json |
| (Production Environment) https://vdi.xxxx.xxx(Service Provider Domain)/api/das/upload-user-protocol-x   | POST   | application/json |

Note: For the specific Service Provider Domain, please contact your Tech Support for assistance.

* Request:

| Parameter Name      | Type         | Description                                                                                                                                                                                                                                                                                                                   | Required | Length |
| :------------------ | :----------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :----- |
| v                   | String       | Version number, default is 1.0.0                                                                                                                                                                                                                                                                                              | Y        | 8      |
| auth                | Object       |                                                                                                                                                                                                                                                                                                                               | Y        |        |
| auth.appId          | String       | Enter the pre-assigned appId                                                                                                                                                                                                                                                                                                  | Y        | 8      |
| auth.nonce          | String       | 32-bit random string (a combination of letters and numbers), a different value must be passed each time the call is made                                                                                                                                                                                                      | Y        | 32     |
| arg                 | Object       |                                                                                                                                                                                                                                                                                                                               | Y        |        |
| arg.idNo            | String       | ID card number of the user using VDI.**The System Integrator needs to first validate the legality of the ID card number and reject requests that do not comply with the format and length of the ID card number.**  *Note: The System Integrator needs to encrypt this field using aesKey and then Base64 encode it.* | Y        |        |
| arg.site            | String       | Data Source                                                                                                                                                                                                                                                                                                                   | Y        |        |
| arg.files[]         | Object Array | Array of protocol files                                                                                                                                                                                                                                                                                                       | Y        |        |
| arg.files[].name    | String       | File name                                                                                                                                                                                                                                                                                                                     | Y        |        |
| arg.files[].content | String       | File content.*Note: Encrypt the file stream using aesKey, then Base64 encode the encrypted file stream.*                                                                                                                                                                                                                    | Y        |        |
| arg.ext             | Object       | Reserved field, ext is an object for extension                                                                                                                                                                                                                                                                                | N        |        |

* Request

```json
{
    "v": "1.0.0",
    "auth": {
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg": {
        "idNo": "UETETEooFDFEEFUFEFEFEFE",
        "site": "xlcx",
        "files": [
            {
                "name": "aaa.pdf",
                "content": "MTIzNDU2Nzg5"
            }
        ]
    }
}
```

* Response| Parameter    | Type    | Description                                       | Required |
  | :----------- | :------ | :------------------------------------------------ | :------- |
  | errorCode    | int     | Result return code: 0: Success, non-zero: Failure | Y        |
  | errorMessage | String  | Description of the return result                  | Y        |
  | data         | Object  | Return result (returns null if the call fails)    | Y        |
  | data.result  | boolean | File upload result                                | Y        |
* Special Error Codes

| Error Code       | Error Message         | Description                                          |
| :--------------- | :-------------------- | :--------------------------------------------------- |
| -43037 or -44050 | AES_DECRYPT_EXCEPTION | AES decryption failed, please use the latest AES key |

* Example of Return Parameters

```json
{
    "errorCode": 0,
    "errorMessage": "success",
    "data": {
        "result": true
    }
}
```

#### 3.4.1 Code Example for Encrypting the 'file content' Field of the Request

```java
@Test
void testEncyptFileContent() throws Exception{
    File file = new File("D:\\user_proto.pdf");
    String base64AesKey = "Ht6SPOmfGv6VjSo0Z5F3ng==";
    byte[] fileBytes = FileUtils.readFileToByteArray(file);
    SecretKey aesKey = loadAesKey(base64AesKey);
    byte[] encryptedFileBytes = encryptAES(fileBytes, aesKey);
    String base64encryptedFileStr = Base64.getEncoder().encodeToString(encryptedFileBytes);
    log.info(base64encryptedFileStr);
}

public byte[] encryptAES(byte[] bytes, SecretKey key) throws Exception {
    Cipher cipher = Cipher.getInstance("AES");
    cipher.init(Cipher.ENCRYPT_MODE, key);
    byte[] encryptedBytes = cipher.doFinal(bytes);
    return encryptedBytes;
}

public SecretKey loadAesKey(String base64Aeskey) {
    byte[] bytes = Base64.getDecoder().decode(base64Aeskey);
    SecretKey key = new SecretKeySpec(bytes, "AES");
    return key;
}
```

If there are issues such as blank files, you can try local processing with the following code to see if you can restore 'base64encryptedFileStr' to the original PDF file.

```java
byte[] encyptedBytes = Base64.getDecoder().decode(base64encryptedFileStr);
Cipher cipher = Cipher.getInstance("AES");
cipher.init(Cipher.DECRYPT_MODE, aesKey);
byte[] decodedBytes = cipher.doFinal(encyptedBytes);
String downloadFileSavePath = "D:\\save.pdf";
FileUtils.writeByteArrayToFile(new File(downloadFileSavePath), decodedBytes);
```

### 3.5 System Integrator Pulling original data File Interface

Through this interface, retrieve the files downloaded by the end user from our backend in the current data acquisition session. Only files within 10 days of data acquisition (including original data & parsing results) are supported for retrieval. Please pull the files into the database promptly.

* The download link will expire in 5 minutes
* Interface Invocation Method:

| Interface Name                                                               | Method | Content-Type     |
| :--------------------------------------------------------------------------- | :----- | :--------------- |
| (Test Environment) https://testing-vdi.xxxx.xxx/api/efp/get-original-files-x | POST   | application/json |
| (Production Environment) https://vdi.xxxx.xxx/api/efp/get-original-files-x   | POST   | application/json |

Note: Please contact your Tech Support to obtain the specific Service Provider Domain.

* Request:

| Parameter Name | Type   | Description                                                                                                              | Required | Length |
| :------------- | :----- | :----------------------------------------------------------------------------------------------------------------------- | :------- | :----- |
| v              | String | Version number, default is 1.0.0                                                                                         | Y        | 8      |
| auth           | Object |                                                                                                                          | Y        |        |
| auth.appId     | String | Enter the pre-assigned appId                                                                                             | Y        | 8      |
| auth.nonce     | String | 32-bit random string (a combination of letters and numbers), a different value must be passed each time the call is made | Y        | 32     |
| arg            | Object |                                                                                                                          | Y        |        |
| arg.daId       | String | data aquisition ID                                                                                                       | Y        | 32     |
| arg.ext        | Object | Reserved field, ext is an object for extension                                                                           | N        |        |

* Return Parameters:

| Parameter                        | Type   | Description                                                                                                                                                                                                                                                                                                                                           | Field Always Exists |
| :------------------------------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------ |
| errorCode                        | int    | Result return code: 0: Success, non-zero: Failure (0 only represents the success of this request, no backend service error, does not represent the success of data acquisition; specifically,**if the user-signed agreement certificate file sent by the System Integrator has not been received yet, a specific error code will be returned**) | Y                   |
| errorMessage                     | String | Description of the return result                                                                                                                                                                                                                                                                                                                      | Y                   |
| data                             | Object |                                                                                                                                                                                                                                                                                                                                                       | Object              |
| data.daId                        | String | data aquisition ID                                                                                                                                                                                                                                                                                                                                    | string              |
| data.bizNo                       | String | Business-level transaction number (not returned in the case of fullminiapp)                                                                                                                                                                                                                                                                           | Y                   |
| data.fileUrl                     | Array  | URL of the downloaded source file, it is an array indicating that there may be multiple files (pdf, csv, or xls, etc.). If data acquisition fails, this array is empty*Note: Upon receiving this field, the System Integrator needs to first decode it using Base64, then decrypt it using aesKey.*                                                 | Y                   |
| data.site                        | String | Data type accessed by the user:[possible values for site](/en/access/appendix?id=_2-supported-data-types-site)                                                                                                                                                                                                                                           | Y                   |
| data.ext                         | Object | Reserved field, ext is an object for extension                                                                                                                                                                                                                                                                                                        | N                   |
| data.ext.fileKey                 | String | Key for decrypting file download*Note: Upon receiving this field, the System Integrator needs to first decode it using Base64, then decrypt it using aesKey.*                                                                                                                                                                                       | N                   |
| data.ext.pdfPassword             | Array  | PDF password (returned only if it is not the last 6 digits of the ID card and has a PDF password)*Note: Upon receiving this field, the System Integrator needs to first decode it using Base64, then decrypt it using aesKey.*                                                                                                                      | N                   |
| data.ext.companyId               | String | Only present when the user accesses a WeChat payment merchant, representing the social credit code of the merchant (business license registration code)                                                                                                                                                                                               | Optional            |
| data.ext.companyName             | String | Only present when the user accesses a WeChat payment merchant, representing the merchant name                                                                                                                                                                                                                                                         | Optional            |
| data.ext.dl                      | Array  | Download status of files, only present when the site is a WeChat payment merchant, it is an array                                                                                                                                                                                                                                                     | Optional            |
| data.ext.dl[].fileName           | String |                                                                                                                                                                                                                                                                                                                                                       | Optional            |
| data.ext.dl[].**dlResult** | String | Specific file download status (possible values below)                                                                                                                                                                                                                                                                                                 | Optional            |
| data.ext.dl[].**type**     | String | One of the bill types (possible values below)                                                                                                                                                                                                                                                                                                         | Optional            |
| data.ext.fileTypeMapping         | Map    | When the user accesses a WeChat payment merchant, it is the file index and file type dictionary (deprecated)                                                                                                                                                                                                                                          | Optional            |

* errorCode (Special Error Codes)

| Error Code | Error Message                        | Description                           | Is Error Code Final     |
| :--------- | :----------------------------------- | :------------------------------------ | :---------------------- |
| 0          |                                      | Success                               | Final                   |
| -44028     | DA_NOT_AUTHORIZED_EXCEPTION          | User is not authorized                | Non-final, needs retry  |
| -44017     | NOT_RECEIVED_USER_PROTOCOL_EXCEPTION | User agreement not received           | Non-final, needs retry  |
| -44062     | DA_IN_PROGRESS_EXCEPTION             | data acquisition is still in progress | Non-final, needs retry  |
| -44021     | DA_FAILED_EXCEPTION                  | data acquisition failed for this case | Final, no need to retry |

**Note:**

1. For some data types such as Postal Savings Bank and Bank of China, the 'fileUrl' field returned by this interface will contain two or more URLs, so the System Integrator needs to download and process multiple URLs of this type of data.
2. The URL returned by the interface invocation is valid for 5 minutes, so the file download must be completed within 5 minutes. If it expires, you can call this interface again to get a new URL.

* Response

```json
{
    "data": {
        "daId": "de1uahd81493120767678877696",
        "bizNo": "Acf5EBaefB9ErFWPHz",
        "fileUrl": [
            "ZjkJD3UrtkM8EOr70OrCJP7uj671NocN3ObdxSMlqjlSvJPDlH4z85jKHlz2HVuJnj+tU7fHem88QYNr545HYcGJSJ0EKgRdRY+Bn+yAUc5+xAjIUD+UGRxof1o3MrErlaQytexIOf8yjfcMt0HoFQQGRvzNMFha6fRFRibYn0x+8yUnscaDIkEmwKFja2r2a3kezroVlB1dVuY0DQbd5cALbmTXXN+sNU4xzR9npROBVRspwh6jMeUbhLX5phRx/YDEbxBcNshP3qWYNt/ywzrl74T/Ve/05iVrY4iM8MUeYjWjxo9B/MCizIJfLBEak5zaaDMI7aEHgBXA0qw1CYk1wzVW8THbYrcbWikB14tlt8b6Bwi3Dr8Av7fwUzG0W4DzCxZZVgb8MzChYNKAxWvfKq4a1Ivu+IzbgRJm0z681eKe5h0TPGuFRrKtXW4nCG973jTPz//6JpdIjnB92YMfxsYI0T+YZhP7mV/pJxAFbWWbdGIaXKcyPj+ABHvPDk0R7UhKWXcRJX5SYhx9UlgDKpK9LBYnqyGukMymd9/Hw3cz5/rklJWTynpS8eMlDqJ9w9Bzpn1KOtKKWfKYXpfozvbovXNh3E83MaG8JyzlpT6FPD41FJa6D7fyuTA7L126f8rYrQ00xBHAHilPTK2LRhITSABhlUySDrroNjWxV6Wu5LI+1oK7WAaTyK9I+z1gXTrpSHcd2oRrxU2Lo9+mTdvjAbs2Mbp6pxeSYYc="
        ],
        "site": "tax",
        "ext": {
            "dl": [],
            "fileKey": "7pfdqjwnUAy2GZXHy02Pdxz2S6wZEp1U7wOzycwmoorRI4nkTz5jC+dXK6ORRuLS"
        }
    },
    "errorCode": 0,
    "errorMessage": "success"
}
```

#### 3.5.1 Example to decrypt the reponse

```java
@Test
    void testDecryptAes() throws Exception {
        String base64AesKey = "2EdTm/RolkL0RjVBXhSAUA==";
        SecretKey key = loadAesKey(base64AesKey);

        String value = decryptAes("RTukZZStW/+4XiToo1WzXIRDSPC3w2ceVco/vPcwYFs=", key);
        log.info(value);
}

public SecretKey loadAesKey(String base64Aeskey) {
        byte[] bytes = Base64.getDecoder().decode(base64Aeskey);
        SecretKey key = new SecretKeySpec(bytes, "AES");
        return key;
}

public String decryptAes(String base64EncryptedValue, SecretKey key) throws Exception {
        byte[] encyptedBytes = Base64.getDecoder().decode(base64EncryptedValue);
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] bytes = cipher.doFinal(encyptedBytes);
        String value = new String(bytes);
        return value;
}
```

#### 3.5.2 Downloading files after decoding fileUrl and fileKey

The Cloud storage service configuration of the clean environment backend uses server-side encryption for file storage, so that the 'fileKey' field in the interface response will not be empty. It needs to be decrypted into a base64 key using the method above, and used together with the decrypted 'fileUrl' to download the file with the following code. The difference from normal file download is that the header is set with three additional parameters for file download decryption.

```java
@Test
void testDownloadUsingPresignedUrl() throws Exception{
        String presignedUrl = "https://evidence-file-1308262583.cos.ap-guangzhou.myqcloud.com/de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1646480278%3B1646480878%26q-key-time%3D1646480278%3B1646480878%26q-header-list%3Dhost%3Bx-cos-server-side-encryption-customer-algorithm%3Bx-cos-server-side-encryption-customer-key%3Bx-cos-server-side-encryption-customer-key-md5%26q-url-param-list%3D%26q-signature%3D7e752832991291f92df05edb949f56a3f99c2d2d";
        String fileKey = "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=";
        String downloadFileSavePath = "E:\\de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf";
        MessageDigest md5 = MessageDigest.getInstance("md5");
        byte[] md5Bytes = md5.digest(Base64.getDecoder().decode(fileKey));
        String base64Md5 = Base64.getEncoder().encodeToString(md5Bytes);
        URL url = new URL(presignedUrl);
        HttpURLConnection httpURLConnection = (HttpURLConnection)url.openConnection();
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-algorithm", "AES256");
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key-MD5", base64Md5);
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key", fileKey);
        byte[] fileBytes = IOUtils.toByteArray(httpURLConnection.getInputStream());
        FileUtils.writeByteArrayToFile(new File(downloadFileSavePath), fileBytes);
}
```

<!-- 
### 3.6 System Integrator Pulling "Evidence Certificate" Interface

#### 3.6.1 Interface Description

* Through this interface, pull the download address of the evidence certificate for the current data acquisition from the backend.
* The download link will expire in 5 minutesNote: Starting from August 21, 2023, with the continuous increase in business volume, to ensure the quality and efficiency of querying data, only files within 10 days of data acquisition (including original evidence, parsing results, and evidence certificates) are supported for retrieval. Please pull the files into the database promptly.
* **The System Integrator needs to download and decrypt the parsing result JSON in the same way as in 3.5.1 and 3.5.2**
* Interface Invocation Method:

| Interface Name                                                                                     | Method | Content-Type     |
| :------------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Test Environment) https://testing-vdi.xxxx.com(Service Provider Domain)/api/efp/get-cert-result-x | POST   | application/json |
| (Production Environment) https://vdi.xxxx.com(Service Provider Domain)/api/efp/get-cert-result-x   | POST   | application/json |

Note: Please contact your Tech Support to obtain the specific Service Provider Domain.

* Request:

| Parameter Name | Type   | Description                                                                                                              | Required | Length Limit |
| :------------- | :----- | :----------------------------------------------------------------------------------------------------------------------- | :------- | :----------- |
| v              | String | Version number, default is 1.0.0                                                                                         | Y        | 8            |
| auth           | Object |                                                                                                                          | Y        |              |
| auth.appId     | String | Enter the pre-assigned appId                                                                                             | Y        | 8            |
| auth.nonce     | String | 32-bit random string (a combination of letters and numbers), a different value must be passed each time the call is made | Y        | 32           |
| arg            | Object |                                                                                                                          | Y        |              |
| arg.daId       | String | data acquisition ID                                                                                                      | Y        | 32           |
| arg.ext        | Object | Reserved field, ext is an object for extension                                                                           | N        |              |

* Return Parameters

| Parameter          | Type    | Description                                                                                                                                                                                                                        | Required |  |
| :----------------- | :------ | :--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :- |
| errorCode          | int     | Return code: 0 success, non-zero failure (0 only represents the success of this request and there is no backend service error, does not represent the success of business logic)                                                   | Y        |  |
| errorMessage       | String  | Description of the return result                                                                                                                                                                                                   | Y        |  |
| data               | Object  |                                                                                                                                                                                                                                    | Y        |  |
| data.daId          | String  | data aquisition ID                                                                                                                                                                                                                 | Y        |  |
| data.bizNo         | String  | Business-level transaction number (not returned in the case of fullminiapp)                                                                                                                                                        | Y        |  |
| data.certResult    | Integer | Result of evidence certificate generation (success or failure, possible values below)                                                                                                                                              | Y        |  |
| data.certFileUrl[] | Array   | List of evidence certificates, an array, each element is a download URL for an evidence certificate*Note: Upon receiving this field, the System Integrator needs to first decode it using Base64, then decrypt it using aesKey.* | Y        |  |
| data.ext           | String  | Reserved field, ext is an object for extension                                                                                                                                                                                     | N        |  |
| data.ext.fileKey   | String  | Key for decrypting file download*Note: Upon receiving this field, the System Integrator needs to first decode it using Base64, then decrypt it using aesKey.*                                                                    | N        |  |

* errorCode

| Error Code    | Error Message                        | Description                                                                                                             | Is Error Code Final     |
| :------------ | :----------------------------------- | :---------------------------------------------------------------------------------------------------------------------- | :---------------------- |
| 0             |                                      | Success                                                                                                                 | Final                   |
| -44009 -43024 | NO_DB_RECORD_EXCEPTION               | daId does not exist                                                                                                     | Non-final, needs retry  |
| -44028        | DA_NOT_AUTHORIZED_EXCEPTION          | User is not authorized, so the System Integrator cannot pull the user's data aquisition files and evidence certificates | Non-final, needs retry  |
| -44017        | NOT_RECEIVED_USER_PROTOCOL_EXCEPTION | User agreement not received                                                                                             | Non-final, needs retry  |
| -44007        | GET_EVIDENCE_DETAILS_EXCEPTYION      | Not successfully on the chain, this error only affects the pulling of the evidence certificate interface                | Non-final, needs retry  |
| -44062        | DA_IN_PROGRESS_EXCEPTION             | data acquisition is still in progress                                                                                   | Non-final, needs retry  |
| -44021        | DA_FAILED_EXCEPTION                  | data acquisition failed for this case                                                                                   | Final, no need to retry |

#### 3.6.2 Possible Values of certResult

| Possible Value | Description                                 |
| :------------- | :------------------------------------------ |
| 5              | Evidence certificate not generated          |
| 10             | Evidence certificate generated successfully |
| 100            | Evidence certificate failed to generate     |

* Return Parameters

```json
{
    "data": {
        "daId": "de1uahd81493120767678877696",
        "bizNo": "Acf5EBaefB9ErFWPHz",
        "certResult": 10,
        "certFileUrl": [
            "ZjkJD3UrtkM8EOr70OrCJJhnZ9qU7//Og5cuKQldauVSvJPDlH4z85jKHlz2HVuJMr4PhXlcch5T5ZwCbkRgKAg9BRxpaQ9Yb77U9j730tq1L+OGW85FR3/5cXDuVPLEaTtGFWwprVuT8+sWDGX2IHAX1lFtUwaDiFyknTI+wU7FE7Afcl8b09m63PumFPWsl/kqeQIDpNk7o8TzGQpGojFDA2FJf7ksGPaYEdBtEoea8roSTFM4QoayC6ZcSMU0fcnWC59A3dfNgllEp0zK3UsCl4v3HJxLIlliVcMwN0vrfsAPb768wI6oycS3mhpSIM+M1l4N/4nctLKkE0LNn9YP0ODeJTbEnZ2lzjzMHUrOohwCJx5NYsevuBjHSuIj2UZgvqx01sG7xQi6V2GrrLXqvAG7zn6cGN3pHEoy3Ctf6FyeErLmtGNosmTL4ewCmD8ANk6I+eZKPt6KEJ2b0hBtIgnPGDcG4iwYCr+zOhkFjEmf25oDC3lYZtVrDa8ZcpE39tnR9RvqyD0k3lScHiTVQP6Tyl6GQIe9v1zGpkmqfeO/16gfuDu2xQiShr/Vz8wKl3zyaaKG3dD7lmTBubdiijN+GDhZPCL1GlgUPxWyHh8V1EYk1GIEB9q0Ql4trlXCbnEVv32hGPRTc51LxdXKK72WEMWx/+DEUAjvsKZ+YqDSq6KIgAPyl9xv5jRPL2cuczpv6gw6DYpjvFa7C47/9Vx6LC4PZvXRbz7XITs="
        ],
        "ext": {
            "fileKey": "7pfdqjwnUAy2GZXHy02Pdxz2S6wZEp1U7wOzycwmoorRI4nkTz5jC+dXK6ORRuLS"
        }
    },
    "errorCode": 0,
    "errorMessage": "success"
}
```

**Attention:**

1. **For certain data types, the 'fileUrl' field returned by this interface may contain two or more URLs. Therefore, the System Integrator needs to download and process multiple URLs for such data types when calling the interface.**
2. **The URL returned upon successful invocation of the interface is valid for 5 minutes. Therefore, file downloads must be completed within 5 minutes. If the URL expires, you can call this interface again to get a new URL.**
   Note: Starting from August 21, 2023, with the continuous increase in business volume, to ensure the quality and efficiency of data retrieval, only files within 10 days of data acquisition (including original data, parsing results, and evidence certificates) are supported for retrieval. Please pull the files and store them into the database promptly; files older than 10 days need to be regularly processed in batches by the Clean Environment backend service provider. -->

### 3.7 Pull Interface for Current Data Type Status

* Description: **Through this interface, you can pull the running status of specific data types. [Important]**
* Due to possible maintenance/upgrades of the data official website, resulting in short-term unavailability, this interface is used for the business party to regularly obtain the available status of the corresponding data type. Suggestions for the business party:

  1. **Regularly pull the available status of data types via scheduled tasks (cronjob) and save this status**, preferably every 5 minutes. If there is a large number of users, the frequency can be increased.
  2. **Based on the locally saved site availability status, control the display/hide of corresponding site user entry points on the business entry page using switches**.
* Interface Call Method:

| Interface Name                                                                                       | Method | Content-Type     |
| :--------------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Test Environment)  https://testing-vdi.xxxx.xxx(Service Provider Domain)/api/config/get-sites-state | POST   | application/json |
| (Production Environment)  https://vdi.xxxx.xxx(Service Provider Domain)/api/config/get-sites-state   | POST   | application/json |

Note: Please contact your tech support to obtain the specific service provider domain.

* Request:

| Parameter Name | Type   | Description                                                                                                      | Required | Length Limit |
| :------------- | :----- | :--------------------------------------------------------------------------------------------------------------- | :------- | :----------- |
| v              | String | Version number, default is 1.0.0                                                                                 | Y        | 8            |
| auth           | Object |                                                                                                                  | Y        |              |
| auth.appId     | String | Pass in the pre-allocated appId                                                                                  | Y        | 8            |
| auth.nonce     | String | 32-character random string (a combination of letters and numbers), different values must be passed for each call | Y        | 32           |
| arg            | Object |                                                                                                                  | Y        |              |
| arg.sites      | Array  | Status of the required data types, array, pass in all data types that need to be pulled for status               | Y        |              |
| arg.ext        | Object | Reserve field, ext is an object used for extension                                                               | N        |              |

* Request Example:

```json
{
    "v":"1.0.0",
    "auth":{
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg":{
        "sites":["tax", "payweixin", "ccb"]
    }
}
```

* Return Parameters

| Parameter        | Type   | Description                                                                                                                                                                                  | Required |
| :--------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- |
| errorCode        | int    | Return code: 0 for success, non-zero for failure (0 only represents that the request was successful without any backend service errors, it does not represent the success of business logic) | Y        |
| errorMessage     | String | Return result description                                                                                                                                                                    | Y        |
| data             | Array  |                                                                                                                                                                                              | Y        |
| data.status      | Array  | 1 means available, 0 means unavailable                                                                                                                                                       | Y        |
| data.site        | Array  | Data type name                                                                                                                                                                               | Y        |
| data.description | Array  | Data type description                                                                                                                                                                        | Y        |

* Return Example

```json
{
    "errorCode": 0,
    "errorMessage": "success",
    "data":  [
            {
                "status": "1",
                "site": "tax",
                "description": "个税"
            },
            {
                "status": "1",
                "site": "ccb",
                "description": "建设银行"
            }
        ]
}
```

### 3.8 Retrieving Data Acquisition Status

* Description: This interface allows retrieving the operational status of a specific data acquisition business.
* Interface Invocation:

| Interface Name                                                                                  | Method | Content-Type     |
| :---------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Test Environment)  https://testing-vdi.xxxx.xxx(Service Provider Domain)/api/das/get-da-status | POST   | application/json |
| (Production Environment)  https://vdi.xxxx.xxx(Service Provider Domain)/api/das/get-da-status   | POST   | application/json |

Note: Please contact your integration colleague to obtain the specific service provider domain.

* Request:

| Parameter Name | Type   | Description                                                                                                                | Required | Length Limitation |
| :------------- | :----- | :------------------------------------------------------------------------------------------------------------------------- | :------- | :---------------- |
| v              | String | Version number, default is 1.0.0                                                                                           | Y        | 8                 |
| auth           | Object |                                                                                                                            | Y        |                   |
| auth.appId     | String | Pass in the pre-allocated appId                                                                                            | Y        | 8                 |
| auth.nonce     | String | 32-character random string (a combination of letters and numbers), a different value must be passed in for each invocation | Y        | 32                |
| arg            | Object |                                                                                                                            | Y        |                   |
| arg.daId       | String | daId                                                                                                                       | Y        | 32                |
| arg.ext        | Object | Spare field, ext is an object used for extension                                                                           | N        |                   |

* Request Example

```json
{
    "v":"1.0.0",
    "auth":{
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg":{
        "daId": "359713244643861591"
    }
}
```

* Return Parameters:

| Parameter            | Type   | Description                                                                                                                                                                                                                                                                                                                                                   | Required |
| :------------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | :------- |
| errorCode            | int    | Return code: 0 for success, non-0 for failure (0 only indicates that this request was successful and there were no backend service errors, does not represent business logic success)                                                                                                                                                                         | Y        |
| errorMessage         | String | Description of the returned result                                                                                                                                                                                                                                                                                                                            | Y        |
| data                 | Object |                                                                                                                                                                                                                                                                                                                                                               | Y        |
| data.daStatus        | int    | Status value of the VDI machine occupied by the user, see details:[possible values of daStatus](/en/access/appendix?id=_3-possible-values-of-dastatus). If the user exits the VDI during the file download process, it is impossible to enter another VDI until the download task is completed, and a new VDI can only be opened after the download is complete. | Y        |
| data.browsingSite    | String | User access site                                                                                                                                                                                                                                                                                                                                              | Y        |
| data.daId            | String | Data acquisition ID                                                                                                                                                                                                                                                                                                                                           | Y        |
| data.bizNo           | String | Integration partner serial number                                                                                                                                                                                                                                                                                                                             | Y        |
| data.jsonResult      | Int    | File parsing status                                                                                                                                                                                                                                                                                                                                           | Y        |
| data.certResult      | Int    | Evidence certificate status (No longer usable)                                                                                                                                                                                                                                                                                                                | Y        |
| data.appId           | String | Partner's appId                                                                                                                                                                                                                                                                                                                                               | Y        |
| data.authorizedTs    | Long   | Timestamp when the user completes the authorization, in milliseconds. A value of 0 indicates unauthorized. Unauthorized users will not have their files pulled by the integration party. Therefore, it can be confirmed that the status is correct before downloading by checking authorizedTs > 0.                                                           | Y        |
| data.ext             | Object |                                                                                                                                                                                                                                                                                                                                                               | N        |
| data.ext.daSubStatus | Int    | Sub completion code. If the user fails to access the data, the specific reason for the error. Enumerated values can be found at Appendix document. Not always required; if the integration party requires this feature to be configured, please inform.                                                                                                       | N        |
| data.ext.childDaList | Object | Not always required; if the integration party requires this feature to be configured, please inform. Displays the details of each order for the child site, as shown in the example below.                                                                                                                                                                    | N        |
| data.ext.province    | String | When using the national social security data source, it indicates the selected province, municipality, or autonomous region                                                                                                                                                                                                                                   | N        |
| data.ext.city        | String | When using the national social security data source, it indicates the selected city                                                                                                                                                                                                                                                                           | N        |

* Special Error Codes

| Error Code | Error Message          | Description             |
| :--------- | :--------------------- | :---------------------- |
| -43024     | NO_DB_RECORD_EXCEPTION | No daId exists          |
| -48007     | NETWORK_ERROR          | Temporary network error |

* Return Example

```json
{
    "data": {
        "daId": "de1jvbe11492495098561302528",
        "daStatus": 10,
        "appId": "de1jvbe1",
        "browsingSite": "chsi",
        "bizNo": "we1386584661349863900",
        "jsonResult": 10,
        "certResult": 10,
        "authorizedTs": 1644673569661
    },
    "errorCode": 0,
    "errorMessage": "success"
}
```

Another example with child sites:

```json
{
    "errorCode":0,
    "errorMessage":"success",
    "data":{
        "daId":"zd20kldt1691346833000402944",
        "daStatus":10,
        "appId":"zd20kldt",
        "browsingSite":"tax-any",
        "bizNo":"1692083483002",
        "jsonResult":10,
        "certResult":10,
        "authorizedTs":1692083552361,
        "ext":{
            "childDaList":[
                {
                    "daId":"zd20kldt1691346833000402944-0",
                    "site":"tax-a",
                    "daStatus":10,
                    "daSubStatus":null
                },
                {
                    "daId":"zd20kldt1691346833000402944-1",
                    "site":"tax-b",
                    "daStatus":10,
                    "daSubStatus":null
                },
                {
                    "daId":"zd20kldt1691346833000402944-2",
                    "site":"tax-c",
                    "daStatus":10,
                    "daSubStatus":null
                }
            ],
            "fileKey":"mc27jdvniyo1EvvuJPAKiOWESnJ3OriWQjprbJBqEQI="
        }
    }
}
```

<!-- ### 3.9 Setting the Whitelist for Users Allowed to Enter the Clean Environment

* Description: When users of the system integrator directly rely on the QR code of the clean environment backend service provider to enter the clean environment, they can set the whitelist of users who can use the clean environment through this interface.
* This interface is only required to be called when the system integrator accesses using a standalone Weixin Miniapp.
* Interface Calling Method:

| Interface Name                                                                                         | Method | Content-Type     |
| :----------------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Testing Environment) https://testing-vdi.xxxx.xxx(Service Provider Domain)/api/admin/sbox-whitelist-x | POST   | application/json |
| (Production Environment) https://vdi.xxxx.xxx(Service Provider Domain)/api/admin/sbox-whitelist-x      | POST   | application/json |

Note: Please contact your tech support to obtain the specific service domain.

* Request:

| Parameter         | Type   | Description                                                                                                                                                                                                                                                                                                                                                                                                                                  | Required | Length Limit |
| :---------------- | :----- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- | :----------- |
| v                 | String | Version number, default is 1.0.0                                                                                                                                                                                                                                                                                                                                                                                                             | Y        | 8            |
| auth              | Object |                                                                                                                                                                                                                                                                                                                                                                                                                                              | Y        |              |
| auth.appId        | String | Pre-allocated appId                                                                                                                                                                                                                                                                                                                                                                                                                          | Y        | 8            |
| auth.nonce        | String | 32-bit random string (combination of letters and numbers), a different value must be passed each time the call is made                                                                                                                                                                                                                                                                                                                       | Y        | 32           |
| arg               | Object |                                                                                                                                                                                                                                                                                                                                                                                                                                              | Y        |              |
| arg.wl            | Array  |                                                                                                                                                                                                                                                                                                                                                                                                                                              | Y        |              |
| arg.wl[].idNo     | String | ID card number of the user using the VDI.**The system integrator needs to first validate the legality of the ID card number and reject requests that do not comply with the format and length of the ID card number.**  *Note: The system integrator needs to encrypt this field using aesKey and then Base64 encode it.*                                                                                                            | Y        |              |
| arg.wl[].userId   | String | The ID representing this user set by the system integrator for this user, used to match this user; the system integrator ensures that userId can be uniquely mapped to the ID card number of this user, because the ID card number will not be returned in the notify notification, only this userId will be returned for matching users.*Note: The system integrator needs to encrypt this field using aesKey and then Base64 encode it.* | Y        | 64           |
| arg.wl[].userName | String | The real name of the user after the system integrator KYC, displayed on the clean environment page. Needs to be encrypted using aesKey.*Note: The system integrator needs to encrypt this field using aesKey and then Base64 encode it.*                                                                                                                                                                                                   | Y        |              |
| arg.wl[].action   | String | "add" indicates adding to the whitelist (returning an error if already exists); "del" indicates deleting from the whitelist;                                                                                                                                                                                                                                                                                                                 | Y        |              |
| arg.wl[].sites    | Array  | Currently unused                                                                                                                                                                                                                                                                                                                                                                                                                             | Y        |              |

* Return Parameters:

| Parameter    | Type   | Description                                                                                                                                                                                                                                                                                                                                                                         | Required |
| :----------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------- |
| errorCode    | int    | Return code: 0 for success, non-0 for failure.   -53022 idNo already exists during addition.   -53028 userId already exists during addition.   -53023 idNo does not exist during deletion.   Note: This interface checks before execution. If the return code is not 0, all additions and deletions will not be executed, and the request content needs to be modified and retried. | Y        |
| errorMessage | String | Description of the returned result. If the addition or deletion fails, it will return which item failed. If the ID card number does not exist, it returns userId; otherwise, it returns the ID card number.                                                                                                                                                                         | Y        |

* Return Example

```json
{
    "errorCode": 0,
    "errorMessage": "success"
}
{
    "data": null,
    "errorCode": -53022,
    "errorMessage": "421181198908185818 idNo已存在，请核查!"
}
``` -->

### 3.10 System Integrator Dimension End-of-Day Reconciliation Statement Retrieval Interface

Description: Every day at 3:30 AM, the end-of-day reconciliation statement of the system integrator dimension for the previous day is generated for downloading and reconciliation use. The reconciliation statement interface is crucial.

Interface Calling Method:

| Interface Name                                                                                                                                         | Method | Content-Type     |
| :----------------------------------------------------------------------------------------------------------------------------------------------------- | :----- | :--------------- |
| (Testing Environment)[https://testing-vdi.xxxx.xxx(Service Provider Domain)/api/efp/get-recon-file](https://testing-vdi.zdgzc.com/api/efp/get-recon-file) | POST   | application/json |
| (Production Environment)[https://vdi.xxxx.xxx(Service Provider Domain)/api/efp/get-recon-file](https://vdi.zdgzc.com/api/efp/get-recon-file)              | POST   | application/json |

Note: Please contact your tech support to obtain the specific service domain.

* Request:

| Parameter  | Type   | Description                                                                                                            | Required | Length Limit |
| :--------- | :----- | :--------------------------------------------------------------------------------------------------------------------- | :------- | :----------- |
| v          | String | Version number, default is 1.0.0                                                                                       | Y        | 8            |
| auth       | Object |                                                                                                                        | Y        |              |
| auth.appId | String | Pre-allocated appId                                                                                                    | Y        | 8            |
| auth.nonce | String | 32-bit random string (combination of letters and numbers), a different value must be passed each time the call is made | Y        | 32           |
| arg        | Object |                                                                                                                        | Y        |              |
| arg.date   | String | Date, format is yyyymmdd, for example: 20220801, here you need to pass the reconciliation date of T-1                  | Y        | 8            |

* Request

```json
{
    "v":"1.0.0",
    "auth":{
        "appId": "appid1",
        "nonce": "RandomCode.getRandomString(32)"
    },
    "arg":{
        "date": "20220221"
    }
}
```

* Return Parameters:

| Parameter    | Type   | Description                                   | Required |
| :----------- | :----- | :-------------------------------------------- | :------- |
| errorCode    | int    | Return code: 0 for success, non-0 for failure | Y        |
| errorMessage | String | Description of the returned result            | Y        |
| data         | Object |                                               | Y        |
| data.fileUrl | String | URL of the downloaded reconciliation file     | Y        |

* Return Example

```json
{
    "data": {
        "fileUrl": "https://recon-file-bj-1308262583.cos.ap-beijing.myqcloud.com/%E4%BA%A4%E6%98%93%E6%B5%81%E6%B0%B4%E5%AF%B9%E8%B4%A6%E5%8D%95_de1y1kdr_20220801.csv?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1659597612%3B1659598212%26q-key-time%3D1659597612%3B1659598212%26q-header-list%3Dhost%26q-url-param-list%3D%26q-signature%3Db9adb1ee461c7012298fd2d287db2cdb14be6108"
    },
    "errorCode": 0,
    "errorMessage": "success"
}
```

**Explanation:**

1. This interface retrieves a CSV file containing all transaction details of an access party for the previous day (T-1).
2. To download this file, no fileKey is required. Directly use HTTP GET for download. The link is valid for 5 minutes. If you are unable to download within 5 minutes, you need to re-call this interface to get a new link.
3. The CSV file contains the following fields:

| Field Name                | Description                                                                                                                              |
| :------------------------ | :--------------------------------------------------------------------------------------------------------------------------------------- |
| da_id                     | ID of the acquisition, which can uniquely identify an acquisition record                                                                 |
| biz_no                    | Third-party business serial number                                                                                                       |
| app_id                    | AppID pre-assigned for access to the data express chain                                                                                  |
| site                      | Actual data type acquired                                                                                                                |
| original_site             | The original data type of the acquisition (Not usable)                                                                                   |
| access_way                | Access mode                                                                                                                              |
| da_status                 | Acquisition status code                                                                                                                  |
| da_sub_status             | Acquisition sub-status code                                                                                                              |
| json_result               | Status of file parsing (see below for values)                                                                                            |
| cert_result               | Status of evidence certificate (No longer usable)                                                                                        |
| authorize_time            | Authorization timestamp, >0L means there is a value                                                                                      |
| charge_flag               | Y means billing, N means no billing                                                                                                      |
| charge_package            | Y means using the number of items in the flow package for billing, N means not using the number of items in the flow package for billing |
| user_protocol_upload_flag | Y means user agreement uploaded, N means not uploaded                                                                                    |
| create_time               | Time of acquisition order creation                                                                                                       |

### 3.11 Access Party Pulls "Parsed-Original-File" Interface

Note:

1. At present, our side does not modify the data. The JSON parsed after decoding is a 1:1 reconstruction of the original text. The format only supports string type and does not include enumerations, numerical values, characters, booleans, or other types. If the business party needs to redefine the JSON format, they need to convert it themselves.
2. In the future, due to compliance considerations, there is a certain probability that parsing services may not be provided and need to be deployed locally.

Recommendation: We can provide parsing code for deployment by the business party locally. Upon receiving the original data, run the parsing locally. Deployment locally is recommended for cases where technical capabilities are sufficient.

#### 3.11.1 Interface Description

* This interface is used to pull the result (success or failure) of the current acquisition from the backend, along with the structured data download URL of the parsed file (if available).
* The download URL expires in 5 minutes.
* **The access party needs to download and decrypt the parsing results in the same way as 3.5.1 and 3.5.2.** Only files within 10 days of acquisition (including acquisition original text, parsing results, and custody certificates) are supported for retrieval. Please retrieve files promptly for storage.
* Interface Invocation:

| Interface Name                                                                | Method | Content-Type     |
| :---------------------------------------------------------------------------- | :----- | :--------------- |
| (Testing Environment) https://testing-vdi.xxxx.xxx/api/efp/get-parse-result-x | POST   | application/json |
| (Production Environment) https://vdi.xxxx.xxx/api/efp/get-parse-result-x      | POST   | application/json |

Note: Please contact your integration partner to obtain the specific service provider domain.

* Request:

| Parameter Name | Type   | Description                                                                     | Required | Length |
| :------------- | :----- | :------------------------------------------------------------------------------ | :------- | :----- |
| v              | String | Version number, default is 1.0.0                                                | Y        | 8      |
| auth           | Object |                                                                                 | Y        |        |
| auth.appId     | String | Pre-assigned appId                                                              | Y        | 8      |
| auth.nonce     | String | 32-bit random string (combination of letters and numbers), unique for each call | Y        | 32     |
| arg            | Object |                                                                                 | Y        |        |
| arg.daId       | String | Acquisition ID                                                                  | Y        | 32     |
| arg.ext        | Object | Spare field, ext is an object used for expansion                                | N        |        |

* Response Parameters:

| Parameter                         | Type   | Description                                                                                                                                                                                                                                           | Field Always Present |
| :-------------------------------- | :----- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | :------------------- |
| errorCode                         | int    | Result return code: 0 for success, non-0 for failure                                                                                                                                                                                                  | Y                    |
| errorMessage                      | String | Description of the returned result                                                                                                                                                                                                                    | Y                    |
| data                              | Object |                                                                                                                                                                                                                                                       | Y                    |
| data.daId                         | String | Acquisition ID                                                                                                                                                                                                                                        | String               |
| data.bizNo                        | String | Business layer serial number (not returned for fullminiapp mode)                                                                                                                                                                                      | Y                    |
| data.**jsonResult**         | int    | File parsing status (see below for values)                                                                                                                                                                                                            | Y                    |
| data.jsonFileUrl                  | String | Structured data corresponding to PDF and other files, an array where each element corresponds to structured data of a file.*Note: Upon receiving this field, the access party needs to first decode it in Base64 and then decrypt it using aesKey.* | Y                    |
| data.site                         | String | Site visited by the user                                                                                                                                                                                                                              | Y                    |
| data.ext                          | Object | Spare field, ext is an object used for expansion                                                                                                                                                                                                      | Y                    |
| data.ext.fileKey                  | String | Key for file download decryption.*Note: Upon receiving this field, the access party needs to first decode it in Base64 and then decrypt it using aesKey.*                                                                                           | optional             |
| data.ext.companyId                | String | Only available when the user visits a WeChat Pay merchant. It represents the merchant's Unified Social Credit Code (Business License Registration Code).                                                                                              | optional             |
| data.ext.companyName              | String | Only available when the user visits a WeChat Pay merchant. It represents the merchant's name.                                                                                                                                                         | optional             |
| data.ext.dl                       | Array  | File download status, only available when the site is a WeChat Pay merchant. It is an array.                                                                                                                                                          | optional             |
| data.ext.dl.[].fileName           | String |                                                                                                                                                                                                                                                       | optional             |
| data.ext.dl.[].**dlResult** | String | Specific file download status (see below for values)                                                                                                                                                                                                  | optional             |
| data.ext.dl.[].**type**     | String | One of the bill types (see below for values)                                                                                                                                                                                                          | optional             |
| data.ext.fileTypeMapping          | Map    | When the user visits a WeChat Pay merchant, the mapping of file index to file type                                                                                                                                                                    | optional             |

* errorCode (Special Error Codes)

| Error Code    | Error Message                        | Description                                                                                                       | Is Terminal Error Code           |
| :------------ | :----------------------------------- | :---------------------------------------------------------------------------------------------------------------- | :------------------------------- |
| 0             |                                      | Success                                                                                                           | Yes                              |
| -44009 -43024 | NO_DB_RECORD_EXCEPTION               | daId does not exist                                                                                               | No, Retry required               |
| -44028        | DA_NOT_AUTHORIZED_EXCEPTION          | The user is not authorized, so the access party cannot pull the user's acquisition files and custody certificates | No, Retry required               |
| -44017        | NOT_RECEIVED_USER_PROTOCOL_EXCEPTION | User agreement not received                                                                                       | No, Retry required               |
| -44001        | FILE_PARSE_EXCEPTION                 | Data parsing failed                                                                                               | No, Retry required within 7 days |
| -44062        | DA_IN_PROGRESS_EXCEPTION             | Acquisition is still in progress; if daStatus=10 at this time, parsing is not yet complete                        | No, Retry required               |
| -44021        | DA_FAILED_EXCEPTION                  | Acquisition failed and is in a terminal state                                                                     | Yes                              |

#### 3.11.2 Possible Values for jsonResult

| Value | Description                                                                         |
| :---- | :---------------------------------------------------------------------------------- |
| 5     | Parsing in progress                                                                 |
| 10    | Parsing successful, terminal state                                                  |
| 11    | Parsing not required, terminal state                                                |
| 12    | No user data after file parsing                                                     |
| 13    | Company name in enterprise version data type parsing does not match the passed name |
| 100   | Non-terminal state, recoverable                                                     |
| 101   | Terminal failure                                                                    |

#### 3.11.3 Possible Values for dlResult

| Value | Description                                                             |
| :---- | :---------------------------------------------------------------------- |
| 10    | Download successful                                                     |
| 100   | Download failed                                                         |
| 400   | The data type is not available on the website for this transaction file |

* Response

```json
{
    "data": {
        "daId": "de1uahd81493120767678877696",
        "bizNo": "Acf5EBaefB9ErFWPHz",
        "jsonResult": 10,
        "jsonFileUrl": [
            "ZjkJD3UrtkM8EOr70OrCJAkNPiwFnBE0i8tiiLlelGFSvJPDlH4z85jKHlz2HVuJnj+tU7fHem88QYNr545HYcGJSJ0EKgRdRY+Bn+yAUc5+xAjIUD+UGRxof1o3MrErlaQytexIOf8yjfcMt0HoFQQGRvzNMFha6fRFRibYn0x+8yUnscaDIkEmwKFja2r2dE2ZklmbBlTAl83X8mSkuge6iJ3ylFnQq769zpl7nmi0mTHzokgoKVUknuvn7SLMSXU7jmh3iACZ4I8W676DVZtkBQ1Bk6Kz9wWy37oxRZHCKhnopHA7maQZQo3ZArnsLAg0wMzCyPL93zlog7LirXh02/fV8EN0n1QZb7Kl93mSybrKZm6QlC2VVcN+flNmcSt4JOFF2lnO8xwDvRczHHo1i/LtnE32ITILnS2YnaXacoERF3AOtrAxUUqYvmvD9vkKFUrikeRV0mAI8tY3d2QUh5S0qTpWlZQpwTgcyUk9mCYzMOoFJH4dxxwuipNpz8wKl3zyaaKG3dD7lmTBubdiijN+GDhZPCL1GlgUPxUSMF9uAdbqXZkve12eXsjwMKg6ePllxwVol3dhDlaRJfYXPMj/FfzNvDZInX198l0UQfmdPf7PaRb4Brnx+fvtnhcQdVxX2BGBwaoiluGcQrAwv2/bJSIbviqYHOUGA/vL9zFUc0bDruDWK+0Mj8SAaU1RT3Jqnnk8WmX3DJNUpxo2ENzqTmWLDoTUHRg4Dk4="
        ],
        "site": "tax",
        "ext": {
            "dl": [],
            "fileKey": "7pfdqjwnUAy2GZXHy02Pdxz2S6wZEp1U7wOzycwmoorRI4nkTz5jC+dXK6ORRuLS"
        }
    },
    "errorCode": 0,
    "errorMessage": "success"
}
```

**Note:**

1. For some data types like Postal Savings Bank and Bank of China, the fileUrl field returned in the response may contain two or more URLs. Therefore, the access party needs to download and process multiple URLs for such data types when calling the interface.
2. The URLs returned upon successful invocation of the interface are valid for 5 minutes. Therefore, it is necessary to complete the file download within 5 minutes. If the URL expires, you can call this interface again to obtain a new URL.
3. Parsing may fail due to changes in the file format of user files of original data types or the emergence of new format use cases that are not covered, resulting in the temporary unavailability of jsonFileUrl. We will handle the re-adaptation of parsing and release a new version within 14 days to address this. Therefore, the access party needs to consider this exceptional scenario and support fallback retries within 14 days.

## 4 Notification (v2 Format) Interface Description for System Integrators

The process of data acquisition is asynchronous and handled by the clean environment backend service. After processing, it uses a notification method to call the interface (a single interface) that the System Integrator has pre-configured for the clean environment backend, to asynchronously notify the System Integrator of the business progress.

Note: The v2 format notification is currently in the trial operation phase. If there is a need, you can contact your Tech Support Product Manager. The difference between v2 notifications and the original version is:

* func contains the following fields: Data Acquisition Failure, Data Acquisition Completed and Authorized Successfully & Original-File-Parse Successful.
* The notification directly includes the download address of the result file.
* After receiving the notification, the System Integrator must immediately return an errorCode of 0, otherwise the notification will keep retrying. The System Integrator can still use the interface in section 3.8 to actively pull as a fallback.

### 4.1 What Notifications May Occur During the Entire Data Acquisition Cycle

* Notification of the final state of data acquisition failure (required): **daFailed**, issued immediately
* Data Acquisition Original File Notification/Authorization Completion Notification (required): **daUserAuthorized**, after the user data acquisition is successful and the user agreement is uploaded successfully, a file notification with the download address of the **Original-File** will be sent. If it is an asynchronous download data type, it needs to wait for the download to be completed, which may be issued about 30s after the front-end agrees to submit; otherwise, it is issued immediately.
* Parsed-Original-File Notification: **daFileParsed**, if it is not a localized parsing deployment, and the user agreement and authorization are completed, a notification with the download address of the **parsing result json file** will be sent after **parsing is completed**, generally delayed for 5 to 10 seconds after issuing daUserAuthorized.

### 4.2 Generation and Verification of Notification Signature

Note: To facilitate integration, **verifying the signature of the notifications issued by us is not a mandatory process**. The System Integrator only needs to verify in scenarios where verification is required, such as when it is necessary to ensure that the received notification information is indeed initiated by the clean environment server.

#### 4.2.1 System Provider Generates Signature

The clean environment operator signs the issued notifications using the RSA algorithm. The public key of the clean environment operator will be sent to the System Integrator by email when the System Integrator is integrated.
After calculating the signature value, the clean environment backend puts the digital signature value into the request Header.

* The System Integrator needs to verify the signature of the notification from the clean environment operator to ensure the authenticity and legality of the data.

#### 4.2.2 Verification Method for System Integrators to Verify Notification Signatures

* First, retrieve the hash of the notification request parameters from the DECSHASH field in the header (calculate the hash while ensuring the appKey is the same as the one allocated to the System Integrator).
* Extract the DECSSIGN field value from the notification's Header, which is the value of the sign.
* The clean environment operator will send the public key used for notifications to the System Integrator via email.
* Use the CryptoTool's verify interface, passing DECSHASH and DECSSIGN to verify if the signature is correct. A return result of true indicates a successful verification.

```java
@Test
public void testVerifySig() throws Exception {
    String decsHash = "6CE58493F9637A5F406D0A7DE516DECB5BFF467E89889AD094F1480185B357F2";
    String decsSig = "LsMtYfbzJ0QSE4NbbTIERypY5wMdaT3Xgy9le/ba9JwrpX+tN2heDYbrPHc5R/MJmy95D2tIQf8Tt9300Jly1XvaTq6bM8/R8N7FmVS5hMGMnKvunHWVJEqLXFwUZcM4OlvvoU3e4nTebjyVV6dDtQCFFn8QGnctVx1zx+M5YQxYn06b+FTnMj+7Nin1WDz31Sp1N5RX0AMdO8FRKes/Xigvzu+A4YCcd/ARDovdfLIDAeqW2bqjojEzPg1TQ4ly+dFqxOmw6sfq91aTeP0GLfXJhKAmekgpfoce3FYTodYOZYl7m55YcGbk3EdRWAK+yG80qbJ0RT9+oswRY7qlWQ==";
    String publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAiBv+aKtGmMwamUDdm0fEBZMRcGNU2+rCxVaFCdckD7Aj4v4usj141jLJuZQjFrehJI560OwDst0UEFhXWIKfBT+71czGaCUxVWqNazfPzoje3/WcTOUdGXlJunPjz+Ja70aFaJJYwWpkFdx0z925cs0Fs2JErPnXLB1D0ADivaO07tg9uqGB2VZOLg01eAKPb3hwZg/NuqX/3RauU503YuQkbD2wqN8Q3k1Gcl/th7KcJLqgTI/vf/hCiDMIAj91Ff3RCtuba240O1zP7wkz43c4mKgOc0OKhmZrnxtJgsEKIQgRfdn/VlvXo+yvSh6jbaFjqJjEaNJCRlbEpSajowIDAQAB";
    boolean result = verify(decsHash, decsSig, string2PublicKey(publicKey));
    System.out.println(result);
}
public static PublicKey string2PublicKey(String base64PublicKey) throws Exception {
    byte[] keyBytes = Base64.getDecoder().decode(base64PublicKey);
    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
    KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    PublicKey publicKey = keyFactory.generatePublic(keySpec);
    return publicKey;
}
```

### 4.3 Notification Interface

#### 4.3.1 Interface Description

* Description: Whenever there is a change in the data acquisition status, the System Integrator will be notified of the change in status.
* Request URL: Provided by the System Integrator
* Request Method: POST
* Request Header: Content-Type: application/json
* Notification Parameters:

| Parameter                           | Type       | Description                                                                                                                                                                                                                                                                     | Required | Length Limit   |
| ----------------------------------- | ---------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- | -------------- |
| func                                | String     | Notification type.  Data final state failure notification: daFailed,   data aquisition original file notification: daUserAuthorized,Parsed file generation notification: daFileParsed,   index page data submission notification: daSubmittedApp                                | Y        |                |
| v                                   | String     | Version number, 2.0.0                                                                                                                                                                                                                                                           | Y        |                |
| auth                                | Object     |                                                                                                                                                                                                                                                                                 | Y        |                |
| auth.nonce                          | String     | Random number, 32-character random string (letters and numbers)                                                                                                                                                                                                                 | Y        | 32 characters  |
| data                                | Object     |                                                                                                                                                                                                                                                                                 | Y        |                |
| data.bizAppId                       | String     | System Integrator's appId                                                                                                                                                                                                                                                       | Y        |                |
| data.daId                           | String     | Data Aquisition ID                                                                                                                                                                                                                                                              | Y        |                |
| data.bizNo                          | String     | System Integrator's transaction number (if entering directly from the clean environment, this field is an empty string, such as the fullminiapp standalone mini program method)                                                                                                 | Y        | 128 characters |
| data.site                           | String     | Data type accessed by the user:[site possible values](/en/access/appendix?id=_2-supported-data-types-site)                                                                                                                                                                         | Y        | 32 characters  |
| **data.daStatus**             | Int        | User data collection status                                                                                                                                                                                                                                                     | N        |                |
| **data.fileUrlList**          | Array      | URLs of the downloaded files, an array indicating that there may be multiple files (pdf, csv, or xls, etc.). If data acquisition fails, the array is empty. data aquisition original filenotification: for the original data. Parsed file notification: for the parsed file.    | N        |                |
| **data.jsonResult**           | Int        | File parsing completion (10 - parsing successful, 12 - no user data (for Housing Fund, employment information, income declaration data types), 13 - company name mismatch (for enterprise edition data types))                                                                  | N        |                |
| **data.certResult**           | Int        | Evidence Certificate generation completion (No longer usable)                                                                                                                                                                                                                   | N        |                |
| data.authorizedTs                   | Long       | User's authorization completion timestamp in milliseconds, a value of 0 indicates no authorization. Unauthorized users cannot pull user files from the System Integrator. Therefore, you can determine if authorizedTs > 0 to confirm the status is correct before downloading. | N        |                |
| data.ext                            | Object     | Reserved field, ext is an object for extension                                                                                                                                                                                                                                  | Y        |                |
| data.ext.userId                     | String     | The third-party userId of the data acquisition user of the System Integrator,**only available for customers with independent mini program access method**                                                                                                                 | N        |                |
| data.ext.fileKey                    | String     | The fileKey for downloading the file                                                                                                                                                                                                                                            | N        |                |
| data.ext.pdfPassword                | Array      | If the downloaded file is a PDF that requires a password, this field will be returned                                                                                                                                                                                           | N        |                |
| data.ext.daSubStatus                | Integer    | User data acquisition status subcode, indicating some failure details, such as no files for data acquisition. Possible values:[daSubStatus possible values](/en/access/appendix?id=_9-dasubstatus-enum-table)                                                                      | N        |                |
| data.ext.childDaList                | Array      | Present in N-in-1 data types                                                                                                                                                                                                                                                    | N        |                |
| data.ext.[].childDaList.daId        | String     | The sub daId for N-in-1 data type data acquisition                                                                                                                                                                                                                              | N        |                |
| data.ext.[].childDaList.site        | String     | The sub site for N-in-1 data type data acquisition                                                                                                                                                                                                                              | N        |                |
| data.ext.[].childDaList.daStatus    | String     | The sub daStatus for N-in-1 data type data acquisition                                                                                                                                                                                                                          | N        |                |
| data.ext.[].childDaList.daSubStatus | String     | The sub daSubStatus for N-in-1 data type data acquisition                                                                                                                                                                                                                       | N        |                |
| data.ext.province                   | String     | When using the national social security data source, it represents the selected province or municipality directly under the central government                                                                                                                                  | N        |                |
| data.ext.city                       | String     | When using the national social security data source, it represents the selected city                                                                                                                                                                                            | N        |                |
| data.submitId                       | String     | The submission ID when submitting data on the index page                                                                                                                                                                                                                        | N        |                |
| data.siteList                       | Array      | The list of data types submitted when submitting data on the index page:[possible values for site](/en/access/appendix?id=_2-supported-data-types-site)                                                                                                                            | N        |                |
| data.submitTime                     | LongString | The submission time when submitting data on the index page, format is: "2023-05-22 10:22:55"                                                                                                                                                                                    | N        |                |
| data.ext.exceptionPages             | Array      | Original file exception detection (currently only supports app-tax-income) format is: "exceptionPages": ["tax_income1.html","tax_income2.html"]                                                                                                                                 | N        |                |

**Note:** The notification return fields are **not encrypted with aesKey**. The timing of the aesKey call is determined by the System Integrator, and the clean environment data collection backend cannot store the old aesKey for each data collection. Therefore, all notification fields are unencrypted.
Note 2: There is **no unzipPassword** in the return fields of the notification.

* **The System Integrator must use the following return parameters as the response body**:

| Parameter    | Type   | Description                                     | Required |
| ------------ | ------ | ----------------------------------------------- | -------- |
| errorCode    | int    | Return code: 0 for success, non-zero for others | Y        |
| errorMessage | String | Return result description                       | Y        |

* Original File Example

```plain
{
	"func": "daUserAuthorized",
	"v": "2.0.0",
	"auth": {
		"nonce": "0Gm6jUHEF0LPdkpwyzuscBRVxBQZYnMm"
	},
	"data": {
		"bizAppId": "zd1zl4kd",
		"daId": "zd1zl4kd1589532382325882880",
		"bizNo": "we1386584661349863900",
		"site": "chsi",
		"daStatus": 10,
		"jsonResult": 10,
		"authorizedTs": 1667809068755,
		"ext": {
			"fileKey": "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=",
			"userId": "FRC001TM13598452"
		},
		"fileUrlList": ["https://evidence-file-bj-1308262583.cos.ap-beijing.myqcloud.com/zd1uahd81590677482946936832_7c41231b8b03346c7d61e3f8631d1404_chsi_origins.zip?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1668084600%3B1668085200%26q-key-time%3D1668084600%3B1668085200%26q-header-list%3Dhost%26q-url-param-list%3D%26q-signature%3Da2085647e1249c2ea748a018e7ad8894d032635c"]
	}
}
```

* Parsed-File example

```plain
{
	"func": "daFileParsed",
	"v": "2.0.0",
	"auth": {
		"nonce": "g7H4ngW1oxtiiDI7xgx8bopE0DRTQVat"
	},
	"data": {
		"bizAppId": "zd1zl4kd",
		"daId": "zd1zl4kd1589532382325882880",
		"bizNo": "we1386584661349863900",
		"site": "chsi",
		"daStatus": 10,
		"jsonResult": 10,
		"authorizedTs": 1667809068755,
		"ext": {
			"fileKey": "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY="
		},
		"fileUrlList": ["https://evidence-json-bj-1308262583.cos.ap-beijing.myqcloud.com/zd1uahd81590677482946936832_50bf4cc6bcad2fb13b3e1c5b384b28dd_chsi_xlzm.json?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1668084600%3B1668085200%26q-key-time%3D1668084600%3B1668085200%26q-header-list%3Dhost%26q-url-param-list%3D%26q-signature%3D41258450af080336f8ae4720de4dda218d75026c"]
	}
}
```

- Failure Example

```plain
{
	"func": "daFailed",
	"v": "2.0.0",
	"auth": {
		"nonce": "ZKFlNLhm9TKXYf4cpudGUVYvqZyRpXfm"
	},
	"data": {
		"bizAppId": "zd1uahd8",
		"daId": "zd1uahd81589468946623610880",
		"bizNo": "1667793902434",
		"site": "tax",
		"daStatus": 20,
		"jsonResult": 5,
		"authorizedTs": 0
	}
}
```

#### 4.3.2 Important Notes

**Note:**

1. Based on the received notification, the timing for file retrieval should be judged as follows:

   * Upon receiving the user authorization completion notification (func = daUserAuthorized, daStatus = 10), the download path for the original file can be obtained from fileUrlList, or retrieved by calling the get-original-file interface.
   * Upon receiving both the user authorization completion notification and the parsing completion notification (func = daFileParsed, jsonResult = 10), the download path for the parsed result json file can be obtained from fileUrlList, or retrieved by calling the get-parse-result interface.
   * Upon receiving the data acquisition failure notification (func = daFailed), there is no need to call any further retrieval interfaces, as the order has failed.
2. Parsing file notifications is an optional configuration. If local parsing deployment is used, it is possible to choose not to send and receive this type of notification.
3. For a successful data acquisition task, there may be three types of notifications received as mentioned above: the user data acquisition original file notification & the parsing file notification. However, the prerequisite for all successful related notifications to be sent is that **the user has authorized and the user agreement has been successfully uploaded;** otherwise, the notifications will not be sent. If it fails, only the failure notification will be received.
4. The clean environment access party will have multiple retries at certain time intervals when the first notification fails. However, notifications are not guaranteed to be delivered. If due to server issues of the sender and receiver or network problems, the notification cannot be delivered, the access party needs to make a contingency retrieval handling logic based on daId for this exceptional scenario. For details, see the following: Contingency Plan for Unreceived Notifications below.
5. **The access party must provide a callback notification URL, and the protocol for this interface in the production environment must use HTTPS, not HTTP.**
6. If using the fullminiapp independent mini program access, since the access party cannot know daId in advance, it is necessary to align the user through the userId in the ext field and timestamp.
7. **The notification response must strictly follow this JSON structure and key naming:** {"errorCode":0,"errorMessage":"OK"}. If the recipient receives this notification, the errorCode in the response must return 0, otherwise the sender will consider it a failure and continue to retry. It is recommended to respond directly upon successful receipt of the notification, and to handle subsequent data from the notification asynchronously to avoid the interface taking too long and causing the sender to time out and resend.
8. The fileKey and fileUrl in the notification are in plain text and are not encrypted, and can be downloaded directly using the method described in the next section "Return Value Download Example."
9. The validity period of the file URL in the notification is only 5 minutes, so please handle the file download asynchronously immediately after receiving to avoid the URL expiring and causing a download failure. Otherwise, the access party needs to call 3.5 (original file), and 3.11 (parsed json) again to retrieve the download URL and fileKey; at this time, the obtained download URL and fileKey are encrypted and need to be decrypted first using the method in 3.5.1 before downloading.

### 4.4 Downloading files

This section provides a code example on how to download using the encrypted fileKey and fileUrl returned from the notification interface.

Note: **The fileKey and fileUrl returned by the v2 notification are in plain text**, whereas the results obtained by proactive retrieval are encrypted with AES. Therefore, the fileKey and fileUrl from the v2 notification can be used without going through AES decryption (as in section 3.5.2); however, the results obtained by proactive retrieval require decryption before downloading (sections 3.5.1 and 3.5.2).

If the cloud storage service on the clean environment server side is configured to use server-side encryption, the fileKey field returned by the interface will not be empty. It needs to be decrypted into a base64 key and used together with the decrypted fileUrl in the following code to download the file. The difference from the regular file download is that three additional encryption parameters are set in the header.

Here is the code example for downloading the file using the pre-signed URL:

```java
@Test
void testDownloadUsingPresignedUrl() throws Exception{
        String presignedUrl = "https://evidence-file-1308262583.cos.ap-guangzhou.myqcloud.com/de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1646480278%3B1646480878%26q-key-time%3D1646480278%3B1646480878%26q-header-list%3Dhost%3Bx-cos-server-side-encryption-customer-algorithm%3Bx-cos-server-side-encryption-customer-key%3Bx-cos-server-side-encryption-customer-key-md5%26q-url-param-list%3D%26q-signature%3D7e752832991291f92df05edb949f56a3f99c2d2d";
        String fileKey = "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=";
        String downloadFileSavePath = "E:\\de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf";
        MessageDigest md5 = MessageDigest.getInstance("md5");
        byte[] md5Bytes = md5.digest(Base64.getDecoder().decode(fileKey));
        String base64Md5 = Base64.getEncoder().encodeToString(md5Bytes);
        URL url = new URL(presignedUrl);
        HttpURLConnection httpURLConnection = (HttpURLConnection)url.openConnection();
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-algorithm", "AES256");
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key-MD5", base64Md5);
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key", fileKey);
        byte[] fileBytes = IOUtils.toByteArray(httpURLConnection.getInputStream());
        FileUtils.writeByteArrayToFile(new File(downloadFileSavePath), fileBytes);
}
```

### 4.5 Fallback approach when notification interface is not applicable

Notifications cannot be guaranteed to be delivered due to server issues or network problems on either side, which may prevent the notification from reaching its destination. The accessing party needs to implement a contingency retrieval logic based on `daId` for this exceptional scenario. Generally, the time when the data aquisition link is generated is marked as T0, and the successful completion (with `daStatus=0` and `authorizedTs>0`) is marked as T. The average parsing completion time, and maximum timeout time are as follows:

| Data Collection Type (site) | Start/Completion Time | Parsing Completion Time | Maximum Timeout Time |
| --------------------------- | --------------------- | ----------------------- | -------------------- |
| Non-email Mode Collection   | T0 / T                | T+1s                    | T0 + 20min           |

**Best Practices:**

* For each phase of data aquisition, when the front end receives the end information (returned by h5/sdk webview, or the completion redirect information of the mini program), proceed as follows:

  * Call interface 3.5 to retrieve the original file: Make 3 attempts after receiving the front-end end information, with intervals of 0s, 10s, and 60s respectively, stop once successful.
  * Call interface 3.11 to retrieve the parsing results: Make 3 attempts after receiving the front-end end information, with intervals of 5s, 1min, and 10min respectively, stop once successful.
* If your front end cannot reliably receive the end information, then:

  * Call interface 3.5 to retrieve the original file: Make 1 attempt after the generation of the `daId`, with an interval of 20min.
  * Call interface 3.11 to retrieve the parsing results: Make 1 attempt after the generation of the `daId`, with an interval of 20min.
* You may also call interface 3.8 at regular intervals (recommended 60s) after the `daId` is generated, and call the following interfaces when the following conditions are met:

  * If `daStatus = 10` and `authorizedTs > 0`, call interface 3.5 to retrieve the original file.
  * If `daStatus = 10` and `authorizedTs > 0` and `jsonResult = 10`, call interface 3.11 to retrieve the parsing results.
  * If `daStatus < 10`, it is considered an intermediate state of the data aquisition process, and the call needs to continue.
  * If `daStatus > 10`, it is considered a final state of data aquisition failure, no further calls are needed.
  * Maximum call duration is 20min.

Note: For data aquisition via the fullminiapp method, `daId` cannot be used directly for fallback. It is necessary to first obtain the value of the `userId` field in the return data, establish its relationship with `daId`, and then use `daId` to attempt fallback. Alternatively, the daily reconciliation statement interface 3.10 can be used for fallback.
