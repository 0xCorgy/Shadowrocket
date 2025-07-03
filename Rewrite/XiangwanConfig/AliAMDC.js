/*
# > AMDC
# 用于阿里系应用，拦截AMDC请求，并修改响应内容；
# 由向晚重写维护；

# 更新时间: 20250703
# 规则链接: https://raw.githubusercontent.com/XiangwanGuan/Shadowrocket/main/Rewrite/XiangwanConfig/AliAMDC.js

[rewrite_local]
^https?:\/\/amdc\.m\.taobao\.com url script-response-header https://xiangwanguan.github.io/Shadowrocket/Rewrite/JavaScript/AliAMDC.js 

[mitm]
hostname = amdc.m.taobao.com
*/

const url = $request.url;
const header = $request.headers;
const ua = header["User-Agent"] || header["user-agent"];
if (url.includes("/amdc/mobileDispatch")) {
  if (url.includes("appkey=23782110")) {
    $done({ status: "HTTP/1.1 404 Not Found" });
    return;
  }
  if (
    ua.includes("Alibaba") ||
    ua.includes("AMapiPhone") ||
    ua.includes("Hema4iPhone") ||
    ua.includes("Cainiao4iPhone") ||
    ua.includes("%E9%97%B2%E9%B1%BC") ||
    ua.includes("%E6%B7%98%E5%AE%9D") ||
    ua.includes("%E9%A3%9E%E7%8C%AA%E6%97%85%E8%A1%8C")
  ) {
    $done({ status: "HTTP/1.1 404 Not Found" });
  } else {
    $done({});
  }
} else {
  $done({});
}
