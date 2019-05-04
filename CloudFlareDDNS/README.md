# CloudFlareDDNS

基于CloudFlareDDNS开放api更新动态IP到域名。

# Options

* **akid(必须):** 填写CloudFlare Access Key ID
* **aksct(必须):** 填写CloudFlare Access Key Secret
* **domain(必须):** 更新域名的全称，必须而完整填写域名。
* **redo(可选):** 单位秒，默认是600秒检测一次。
* **ipapi(可选):** 可填写自定义获取域名的url，例如:`http://myip.ipip.net`

> 关于如何获取CloudFlareDDNS Access key 请查看CloudFlareDDNS帮助文档[如何获取AccessKey ID和AccessKey Secret](https://www.cloudflare.com/dns/) 

# Support list

- amd64(测试通过)
- i368(未测试)
- armhf(未测试)
- aarch64(未测试)
