/*
# > AMDC
# 用于阿里系应用，拦截AMDC请求，并修改响应内容；
# 由向晚重写维护；

# 更新时间: 20250703
# 规则链接: https://raw.githubusercontent.com/XiangwanGuan/Shadowrocket/main/Rewrite/XiangwanConfig/AliAMDC.js

[rewrite_local]
^https?:\/\/amdc\.m\.taobao\.com\/amdc\/mobileDispatch$ url script-response-body https://xiangwanguan.github.io/Shadowrocket/Rewrite/JavaScript/AliAMDC.js 

[mitm]
hostname = amdc.m.taobao.com
*/

var ua = ($request.headers["User-Agent"] || $request.headers["user-agent"] || "").toLowerCase();
var url = $request.url;
var uaPattern = /(?:AMapiPhone|Alibaba|Cainiao4iPhone|Hema4iPhone|%E6%B7%98%E5%AE%9D|%E9%97%B2%E9%B1%BC|%E9%A3%9E%E7%8C%AA%E6%97%85%E8%A1%8C)/;
var appkeyPattern = /(?:23782110)/;
var appkeyMatch = url.match(/appkey=(\d+)/);
var appkey = appkeyMatch ? appkeyMatch[1] : "";
if (uaPattern.test(ua) || appkeyPattern.test(appkey)) {
    $done({ status: "HTTP/1.1 404 Not Found", body: "Not Found" });
} else {
    $done({});
}
