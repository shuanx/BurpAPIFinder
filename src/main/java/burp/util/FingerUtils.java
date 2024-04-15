package burp.util;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.IResponseInfo;
import burp.model.FingerPrintRule;
import burp.ui.datmodel.ApiDataModel;

import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author： shaun
 * @create： 2024/3/6 20:43
 * @description：TODO
 */
public class FingerUtils {


    public static ApiDataModel FingerFilter(ApiDataModel originalApiData, Map<String, Object> pathData, IExtensionHelpers helpers) {
        // 对originalApiData进行匹配

        // 对pathData进行匹配
        Map<String, Object> newPathData = new HashMap<>();
        for (Map.Entry<String, Object> entry : pathData.entrySet()) {
            Map<String, Object> onePathData = (Map<String, Object>) entry.getValue();
            String onePath = entry.getKey();
            IHttpRequestResponse onRequestsResponse = (IHttpRequestResponse) onePathData.get("responseRequest");
            byte[] oneResponseBytes = onRequestsResponse.getResponse();
            // status更新
            if (originalApiData.getStatus().equals("-")){
                originalApiData.setStatus((String)onePathData.get("status"));
            } else if (!originalApiData.getStatus().contains((String)onePathData.get("status"))) {
                originalApiData.setStatus(originalApiData.getStatus() + "," + onePathData.get("status"));
            }

            // 响应的body值
            String responseBody = new String(oneResponseBytes, StandardCharsets.UTF_8);
            for (FingerPrintRule rule : BurpExtender.fingerprintRules) {
                // 过滤掉白名单URL后缀、白名单路径
                if (rule.getType().contains("白名单")) {
                    continue;
                }

                String locationContent = "";
                if ("body".equals(rule.getLocation())) {
                    locationContent = responseBody;
                } else if ("urlPath".equals(rule.getLocation())) {
                    locationContent = onePath;
                } else {
                    BurpExtender.getStderr().println("[!]指纹出现问题：" + rule.getLocation());
                }
                boolean isMatch = true;
                for (String key : rule.getKeyword()) {
                    if (rule.getMatch().equals("keyword") && !locationContent.toLowerCase().contains(key.toLowerCase())) {
                        isMatch = false;
                    } else if (rule.getMatch().equals("rugular") && !locationContent.toLowerCase().matches(key)) {
                        isMatch = false;
                    }
                }

                if (isMatch) {
                    // 是否为重要
                    if (rule.getIsImportant()) {
                        onePathData.put("isImportant", true);
                        originalApiData.setHavingImportant(true);
                    }
                    String existingResult = (String) onePathData.get("result");
                    if (existingResult.equals("-") || existingResult.isEmpty()) {
                        onePathData.put("result", rule.getType());
                    } else if (!existingResult.contains(rule.getType())) {
                        onePathData.put("result", existingResult + "," + rule.getType());
                    }
                    if (originalApiData.getResult().equals("-")) {
                        originalApiData.setResult(rule.getType());
                    } else if (!originalApiData.getResult().contains(rule.getType())) {
                        originalApiData.setResult(originalApiData.getResult() + "," + rule.getType());
                    }
                    String resultInfo = (String) onePathData.get("result info");
                    if (resultInfo.equals("-")) {
                        resultInfo = rule.getInfo();
                    } else {
                        resultInfo = resultInfo + "\r\n\r\n" + rule.getInfo();
                    }
                    onePathData.put("result info", resultInfo);


                }
                newPathData.put(onePath, onePathData);
//                BurpExtender.getStdout().println(onePath + "===> " + onePathData);


            }

        }
        originalApiData.setPathData(newPathData);
        originalApiData.setPathNumber(String.valueOf(pathData.size()));
        return originalApiData;
    }
}
