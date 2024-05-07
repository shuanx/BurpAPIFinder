package burp.util;

import burp.BurpExtender;
import burp.IExtensionHelpers;
import burp.IHttpRequestResponse;
import burp.model.FingerPrintRule;
import burp.dataModel.ApiDataModel;

import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.*;
import java.util.regex.PatternSyntaxException;

/**
 * @author： shaun
 * @create： 2024/3/6 20:43
 * @description：TODO
 */
public class FingerUtils {

    private static final int MAX_SIZE = 40000; // 设置最大字节大小为40000

    public static ApiDataModel FingerFilter(String url, ApiDataModel originalApiData, Map<String, Object> pathData, IExtensionHelpers helpers) {
        // 对originalApiData进行匹配

        for (Map.Entry<String, Object> entry : pathData.entrySet()) {
            Map<String, Object> onePathData = (Map<String, Object>) entry.getValue();
            String onePath = entry.getKey();
            // 未进行爬取的，则直接入库
            if (((String) onePathData.get("status")).equals("等待爬取")){
                BurpExtender.getDataBaseService().insertOrUpdatePathData(Utils.getUriFromUrl(url), onePath, (Boolean) onePathData.get("isImportant"), (String) onePathData.get("status"), (String) onePathData.get("result"), (String) onePathData.get("describe"), onePathData);
                continue;
            }

            byte[] oneResponseBytes = Base64.getDecoder().decode((String) onePathData.get("response"));
            // 判断响应包是否超大，超大则截断
            // 如果数组超过20000个字节，则截断并添加一条消息
            if (oneResponseBytes.length > MAX_SIZE) {
                byte[] truncatedResponse = new byte[MAX_SIZE];
                System.arraycopy(oneResponseBytes, 0, truncatedResponse, 0, MAX_SIZE);
                // 用截断的响应替换原始响应
                onePathData.put("response", Base64.getEncoder().encodeToString(truncatedResponse));
            }

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
                if (!rule.getIsOpen()){
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
                StringBuilder matchedResults = new StringBuilder("match result：");
                for (String key : rule.getKeyword()) {
                    try {
                        Pattern pattern = Pattern.compile(key, Pattern.CASE_INSENSITIVE);
                        Matcher matcher = pattern.matcher(locationContent);

                        if (rule.getMatch().equals("keyword") && !locationContent.toLowerCase().contains(key.toLowerCase())) {
                            isMatch = false;
                        } else if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                            matchedResults.append(key).append("、");
                        } else if (rule.getMatch().equals("regular")) {
                            boolean foundMatch = false;
                            while (matcher.find()) {
                                foundMatch = true;
                                // 将匹配到的内容添加到StringBuilder中
                                matchedResults.append(matcher.group()).append("、");
                                if (matchedResults.length() > MAX_SIZE){
                                    break;
                                }
                            }
                            if (!foundMatch) {
                                isMatch = false;
                            }
                        }
                    } catch (PatternSyntaxException e) {
                        BurpExtender.getStderr().println("正则表达式语法错误: " + key);
                    } catch (NullPointerException e) {
                        BurpExtender.getStderr().println("传入了 null 作为正则表达式: " + key);
                    } catch (Exception e){
                        BurpExtender.getStderr().println("匹配出现其他报错: " + e);
                    }
                }


                if (isMatch) {
                    // 是否为重要
                    if (rule.getIsImportant()) {
                        onePathData.put("isImportant", true);
                    }
                    String existingDescribe = (String) onePathData.get("describe");
                    if (existingDescribe.equals("-") || existingDescribe.isEmpty()) {
                        onePathData.put("describe", rule.getDescribe());
                    } else if (!existingDescribe.contains(rule.getDescribe())) {
                        onePathData.put("describe", existingDescribe + "," + rule.getDescribe());
                    }

                    Set<String> uniqueDescribe = new HashSet<>();
                    Collections.addAll(uniqueDescribe, existingDescribe);
                    Collections.addAll(uniqueDescribe, rule.getDescribe());
                    originalApiData.setDescribe(String.join(",", uniqueDescribe));

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
                        resultInfo = "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo();
                    } else {
                        resultInfo = resultInfo + "\r\n\r\n" + "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo();
                    }
                    originalApiData.setResultInfo(originalApiData.getResultInfo().strip() + "\r\n\r\n" + "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo() + matchedResults.toString().replaceAll("、+$", ""));
                    onePathData.put("result info", resultInfo + matchedResults.toString().replaceAll("、+$", ""));
                }
            }
            BurpExtender.getDataBaseService().insertOrUpdatePathData(Utils.getUriFromUrl(url), onePath, (Boolean) onePathData.get("isImportant"), (String) onePathData.get("status"), (String) onePathData.get("result"), (String) onePathData.get("describe"), onePathData);

        }
        originalApiData.setPathNumber(BurpExtender.getDataBaseService().getPathDataCountByUrl(Utils.getUriFromUrl(url)));
        return originalApiData;
    }

    public static ApiDataModel FingerFilter(Map<String, Object> onePathData){
        String url = (String) onePathData.get("url");
        ApiDataModel originalApiData = BurpExtender.getDataBaseService().selectApiDataModelByUri(Utils.getUriFromUrl(url));
        // 响应的body值
        String onePath = (String) onePathData.get("path");

        byte[] oneResponseBytes = Base64.getDecoder().decode((String) onePathData.get("response"));
        // 如果数组超过20000个字节，则截断并添加一条消息
        if (oneResponseBytes.length > MAX_SIZE) {
            byte[] truncatedResponse = new byte[MAX_SIZE];
            System.arraycopy(oneResponseBytes, 0, truncatedResponse, 0, MAX_SIZE);
            // 用截断的响应替换原始响应
            onePathData.put("response", Base64.getEncoder().encodeToString(truncatedResponse));
        }

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
            if (!rule.getIsOpen()){
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
            StringBuilder matchedResults = new StringBuilder("match result：");
            for (String key : rule.getKeyword()) {
                try {
                    Pattern pattern = Pattern.compile(key);
                    Matcher matcher = pattern.matcher(locationContent);

                    if (rule.getMatch().equals("keyword") && !locationContent.toLowerCase().contains(key.toLowerCase())) {
                        isMatch = false;
                    } else if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                        matchedResults.append(key).append("、");
                    } else if (rule.getMatch().equals("regular")) {
                        boolean foundMatch = false;
                        while (matcher.find()) {
                            foundMatch = true;
                            // 将匹配到的内容添加到StringBuilder中
                            matchedResults.append(matcher.group()).append("、");
                            if (matchedResults.length() > MAX_SIZE){
                                break;
                            }
                        }
                        if (!foundMatch) {
                            isMatch = false;
                        }
                    }
                } catch (PatternSyntaxException e) {
                    BurpExtender.getStderr().println("正则表达式语法错误: " + key);
                } catch (NullPointerException e) {
                    BurpExtender.getStderr().println("传入了 null 作为正则表达式: " + key);
                } catch (Exception e) {
                    BurpExtender.getStderr().println("匹配出现其他报错: " + e);
                }
            }


            if (isMatch) {
                // 是否为重要
                if (rule.getIsImportant()) {
                    onePathData.put("isImportant", true);
                }
                String existingDescribe = (String) onePathData.get("describe");
                if (existingDescribe.equals("-") || existingDescribe.isEmpty()) {
                    onePathData.put("describe", rule.getDescribe());
                } else if (!existingDescribe.contains(rule.getDescribe())) {
                    onePathData.put("describe", existingDescribe + "," + rule.getDescribe());
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
                    resultInfo = "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo();
                } else {
                    resultInfo = resultInfo + "\r\n\r\n" + "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo();
                }
                originalApiData.setResultInfo(originalApiData.getResultInfo().strip() + "\r\n\r\n" + "URL: " + Utils.getUriFromUrl(url) + onePath + "\r\n" + rule.getInfo() + matchedResults.toString().replaceAll("、+$", ""));
                onePathData.put("result info", resultInfo + matchedResults.toString().replaceAll("、+$", ""));
            }
        }
        String[] onePathDataDescribe1 = ((String)onePathData.get("describe")).split(",");
        String[] exitDescribe = originalApiData.getDescribe().split(",");
        Set<String> describeSet = new HashSet<>();
        describeSet.addAll(Arrays.asList(onePathDataDescribe1));
        describeSet.addAll(Arrays.asList(exitDescribe));
        originalApiData.setDescribe(String.join(",", describeSet).replace("-,", "").replace(",-", "").replace(",误报", "").replace("误报,", ""));
        BurpExtender.getDataBaseService().insertOrUpdatePathData(Utils.getUriFromUrl((String) onePathData.get("url")), (String) onePathData.get("path"), (Boolean) onePathData.get("isImportant"), (String) onePathData.get("status"), (String) onePathData.get("result"), (String) onePathData.get("describe"), onePathData);
        return originalApiData;
    }
}
