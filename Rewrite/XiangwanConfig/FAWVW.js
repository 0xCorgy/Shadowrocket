/*
# > 一汽大众
# 一汽大众应用净化；
# 由向晚制作维护；

# 更新时间: 20250703
# 规则链接: https://raw.githubusercontent.com/XiangwanGuan/Shadowrocket/main/Rewrite/XiangwanConfig/FAWVW.js

[rewrite_local]
^https?:\/\/oneapp-api\.faw-vw\.com\/search\/firstPage\/getPromptList\/v1\?.* mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/benefits\/benefitsCard\/getInfo\/v1\?.* mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/booth\/getBoothList\/v1\?.*showPositionCode=VWAPP_HOME_BUOY mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/booth\/getBoothList\/v1\?.*showPositionCode=VWAPP_(ICE|MEB)_(OPEN_SCREEN_ADS|CAR_ZHIHU_COLLEGE) mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/booth\/getBoothList\/v1\?.*showPositionCode=VWAPP_(ICE|MEB)_HOME_(OWNER_BANNER|PROSPECTS_BANNER|CUSTOM_BANNER|KONGO|CUSTOM_KONGO) mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/(customize\/getCustomizePageName|recommend\/getRecommendInfoFlows)\/v1\?.* mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/(activity\/getSquareActivityList|theme\/getThemeList|post\/getPostsByTags)\/v1\?.* mock-response-body data-type=text data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":[]}
^https?:\/\/oneapp-api\.faw-vw\.com\/content\/(evaluate\/getEvaluateCards|collection\/getCollectionList)\/v1\?.* mock-response-body data-type=json status-code=200 data={"returnStatus":"SUCCEED","hasMore":false,"data":{}}

[mitm]
hostname = oneapp-api.faw-vw.com
*/
