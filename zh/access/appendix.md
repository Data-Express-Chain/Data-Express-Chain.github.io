## 1. 支持的接入方式
accessWay的可能取值  

|accessWay取值|描述|
|:----|:----|
|h5|通过h5方式接入|
<!-- |miniapp|小程序跳转模式，接入方自带CA签名的用户协议|
|miniappwithca|小程序跳转模式，接入方无CA签名的用户协议，使用公证处的刷脸和协议服务|
|fullminiapp|独立小程序接入，用户只需扫码并填写姓名身份证等信息|
|weh52miniapp|从微信内H5页面跳转小程序方式接入（公众号、服务号），见注4.1|
|weh52miniappwithca|从微信内H5页面跳转小程序方式接入（公众号、服务号），使用公证处的刷脸和协议服务，见注4.1|
|h52miniapp|通过微信外的H5页面跳转小程序方式接入（静态H5链接），见注4.2|
|h52miniappwithca|通过微信外的H5页面跳转小程序方式接入（静态H5链接），使用公证处的刷脸和协议服务，见注4.2|
|h52fullminiapp|h5跳转独立小程序|
|sdk|通过iOS sdk / Android sdk方式接入| -->


## 2. 支持的数据类型 

|site取值|在协议中所对应的中文名称（数据类型官方名称）|描述|支持接入方式|获取的取数文件格式及文件个数，是否为zip打包|类型|
|:----|:----|:----|:----|:----|:----|
|chrome-chiyubank-jyj|集友银行流水|集友银行网页|H5|csv: 1 (zip)|PC网页|
|chrome-govhk-tax|香港个税e-receipt|香港个税网页|H5|pdf: 1(zip)|PC网页|


## 3. daStatus

|状态名称|daStatus|描述|终态？|是否通知接入方|是否有效操作|模式|
|:----|:----|:----|:----|:----|:----|:----|
|初始状态|0|初始状态|非终态（最终会变为终态）|否|N|VDI|
|取数文件下载中|5|取数文件正在下载的状态|非终态（最终会变为终态）|通知（默认没有，需要由公证处额外配置）|N|VDI|
|取数文件上传成功|8|取数文件上传公证处云存储成功，待生成下载链接中|非终态（最终会变为终态）|否|N|VDI|
|第一阶段取数完成|9|仅特定数据源有效；当下载完主文件后，可配发此通知允许接入方来下载主文件；明细文件在后续通知中发出|非终态（最终变为10）可下载第一阶段文件|通知（默认没有，需要由公证处额外配置）|Y|VDI|
|**取数成功**|**10**|**下载取数文件成功后自动结束取数，表明上传取数文件成功，且上传视频成功**|**成功的终态**|**通知，表明取数成功**|**Y**|**VDI**|
|取数文件下载非法|14|目前暂未上线此状态。因某些异常，导致用户下载了非目标取数文件意外的文件|终态|通知|Y|VDI|
|取数视频处理失败|15|取数视频因为各种原因失败，例如上传视频文件失败，或录制软件出错（取数文件已上传成功）|终态|通知|N|VDI|
|清洁环境使用超时|20|取数超时退出|终态|通知|Y|VDI|
|vcode过期|21|开始取数请求调用后，如果用户过久未进入清洁环境，会导致vcode过期，从而无法再进入该次取数的清洁环境|终态|通知|Y|VDI|
|用户重入|24|用户重入后，该次取数被结束|终态|通知|Y|VDI|
|用户主动结束取数的状态|25<br>|用户主动结束取数的情况|终态|通知|Y|VDI|
|清洁环境异常|30|当检视进程发现清洁环境异常，例如浏览器挂掉，或者因为任何意外原因显示了取数流程外的信息（例如桌面），清洁环境会被提前被回收并结束取数|终态|通知|N|VDI|
|数据源类型系统失败<br>(无效操作)|41|确定性的数据源类型不可用(4xx,5xx，系统维护)，无效操作类型|终态|通知|N|VDI|
|数据源类型系统失败<br>(有效操作)|42|目前暂未上线此状态。系统失败，有效操作类型。(预留)|终态|通知|Y|VDI|
|数据源类型业务失败<br>(无效操作)|43|其他符合不计费的系统失败条件。如**设备不支持刷脸**等|终态|通知|N|VDI|
|数据源类型业务失败<br>(有效操作)|44|由于用户账号性质等原因导致用户无法完成取数|终态|通知|Y|VDI|
|start错误|92|开始取数接口请求调用返回错误|终态|    |N|VDI|
|未分配机位|94|VDI模式下，用户进入引导页后未进行下一步进行取数|终态|通知|N|VDI|
|其他(预留)|100|目前暂未上线此状态。其他失败情况|终态|通知|N|    |
|其他2(预留)|101|目前暂未上线此状态。其他失败情况|终态|通知|Y|    |
|前端兜底通用错误|-60000|仅在前端跳回url时会收到，表示该笔失败|终态|    |N|    |

* **备注：**
    * daStatus = -4为用户尚未点击前置页的“同意”时拉取的状态值，是中间态
    * 终态失败的 daStatus 取值范围：[13,100]，即大于等于13，小于等于100
    * 从数据类型下载的数据格式可能为 pdf/xls/csv/txt 等
    <!-- * 对于丰巢模式，收到邮件但未操作时daStatus为4；收到邮件但最终超时为20；收到邮件但主动退出为25；没有收到邮件且超时为50；没有收到邮件且主动退出为51。由于丰巢邮件在收到24小时后且未提交才会从公证处服务器上删除，因此**接入方可对于20/25状态的丰巢取数，在23小时内主动触达并挽留用户重新进入取数但不发邮件，此时可直接复用之前邮件，提高转化率** -->
    * **对于来自同一个接入方（appId）的同一个用户（idno），在同一自然日（按请求start-vdi的发起时间统计）获取同一个数据类型（site），只有第一次的有效操作算计费，其他重复取同一site的取数操作不论是否有效，都算不计费**



## 4. jsonResult

|取值|其他|
|:----|:----|
|5|解析初始态；若已经daStatus = 10，则表示解析失败|
|**10**|**解析成功的终态**|
|11|无需解析的终态|
|12|文件解析后无用户数据|
|13|企业版数据类型解析的公司名称与传入名称不匹配|


## 5. daSubStatus 

注：daSubStatus仅为取数失败详情描述。  
（本表格会随着支持的数据源不断迭代更新，已列出的错误码不会修改）

通用：  

|daStatus|daSubstatus|    |
|:----|:----|:----|
|41|80020|网站不可访问|
|44|81535|无数据|
|  |100099|非本人|

## 6. 如何生成RSA公私钥  

建议在Linux环境下使用命令行生成

```plain
// 生成pkcs1格式2048位RSA私钥rsa_private_key.pem
openssl genrsa -out rsa_private_key.pem 2048

// pkcs1格式私钥生成公钥rsa_public_key.pem
openssl rsa -in rsa_private_key.pem -pubout -out rsa_public_key.pem

// pkcs1格式私钥转成pkcs8格式私钥rsa_private_key_pkcs8.pem
openssl pkcs8 -topk8 -inform PEM -in rsa_private_key.pem -outform PEM -nocrypt -out rsa_private_key_pkcs8.pem
```

## 7. 服务端加密的下载使用

配置使用了文件存储服务端加密，则文件拉取接口返回的fileKey字段不为空，需用解密为一个base64的filekey，和解密后的fileUrl一起使用下面的代码下载文件，和普通文件下载的区别是header多设置了3个文件下载解密的参数。  
注：为确保查询取数的服务质量和效率，只支持拉取取数10天以内的文件（包括取数原文、解析结果等），请及时拉取文件落库。

```java
@Test
void testDownloadUsingPresignedUrl() throws Exception{
        String presignedUrl = "https://evidence-file-1308262583.cos.ap-guangzhou.myqcloud.com/de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a_qqmail_jyls-0.pdf?sign=q-sign-algorithm%3Dsha1%26q-ak%3DAKIDoRpxoOilX2GEuJRIsBDySfrnTszpOggP%26q-sign-time%3D1646480278%3B1646480878%26q-key-time%3D1646480278%3B1646480878%26q-header-list%3Dhost%3Bx-cos-server-side-encryption-customer-algorithm%3Bx-cos-server-side-encryption-customer-key%3Bx-cos-server-side-encryption-customer-key-md5%26q-url-param-list%3D%26q-signature%3D7e752832991291f92df05edb949f56a3f99c2d2d";
        String fileKey = "Nx1socBWUxPg8nceCqmANSzl6zJ0+IKwtgJPaMbv4CY=";
        String downloadFileSavePath = "E:\\de1uahd81493120767678877696_7e124dc1ada11b91527e6e6961acc97a _qqmail_jyls-0.pdf";
        MessageDigest md5 = MessageDigest.getInstance("md5");
        byte[] md5Bytes = md5.digest(Base64Decoder.decode(fileKey));
        String base64Md5 = Base64Encoder.encode(md5Bytes);
        URL url = new URL(presignedUrl);
        HttpURLConnection httpURLConnection = (HttpURLConnection)url.openConnection();
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-algorithm", "AES256");
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key-MD5", base64Md5);
        httpURLConnection.setRequestProperty("x-cos-server-side-encryption-customer-key", fileKey);
        byte[] fileBytes = IOUtils.toByteArray(httpURLConnection.getInputStream());
        FileUtils.writeByteArrayToFile(new File(downloadFileSavePath), fileBytes);
}
```


## 8. 生产上线前检视checklist
1. 公共部分
    * 面客前，确认全流程已走通至少一笔（真实入口进入，完成取数、收通知、拉取文件、完成业务）
    * 确认生产环境公钥已提供、回调地址不改变、以及所有的出网IP已提供，如有变化，必须提前2天告知
        * 如果方便的话，麻烦提供回调地址的https证书，我们运维要求需要进行安全校验；如果之前测试环境忽略过回调地址服务端的https证书，请务必提供
    * 确认已经添加公证处的相关IP和域名到白名单
    * **如果使用本地化部署解析，请参考下面配置Webhook方式及时接收解析工程代码变动**
    * 确认已经上传正确格式的用户协议，并敦促产品和对接技术同学验证。协议处理要求：
        1. 用户选择提交对应的数据类型（接口中的site）时，要使用对应的协议模板签署（我们提供模版，仅数据类型中文名称根据site变化，其他一致），且为pdf格式，需要替换的内容为绿色部分（全文替换2处），site与中文填写的对应关系见上文附录2。
        2. 在文初姓名、身份证的地方对应动态写入当前用户的姓名、身份证号码（明文）
        3. 文末用CA签名（调用接入方给C端用户的的电子签），并且加上日期
        4. 签署好之后，每次调用把签署好的PDF文件通过3.4接口上传。
            * 备注：协议可复用，维度是用户身份证号（接口中的idNo） + 数据类型（接口中的site）
            * 举例：张三取了A数据类型，协议可以签署一份，但是张三每次提交A的时候，这一份协议都要调用接口传送。
        5. 协议需要在用户操作完成之前传过来，这样确保可以及时收到通知和及时拉取取数文件  

<!-- 2. 如果使用小程序方式接入
    * 确认生产环境使用的小程序ID、原始ID，且envVersion需改为release
    * 如使用H5跳转小程序链接方式接入，需确认已知悉链接过期时间

3. 如果使用SDK方式接入
    * 确认SDK包的隐私政策、权限申请符合要求 -->

2. 如果使用H5方式接入
    * 再次确认生产环境的入口页和结果页
