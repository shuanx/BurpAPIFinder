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

    private static final int MAX_SIZE = 50000; // 设置最大字节大小为40000
    private static final int CHUNK_SIZE = 20000;
    private static final int RESULT_SIZE = 10000;

    private static final int CONTEXT_LENGTH = 40; // 前后各20个字符

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
                // 定义截断消息
                String truncationMessage = "[!] The response packet length exceeds: " + MAX_SIZE + ", so it is truncated and returned. The matching is not affected. If you need the complete response packet content, please send a packet for testing yourself.\r\n\r\n";
                // 将截断消息转换为byte数组
                byte[] truncationMessageBytes = truncationMessage.getBytes(StandardCharsets.UTF_8);
                // 确定新的截断长度，留出空间给截断消息
                int truncatedLength = MAX_SIZE - truncationMessageBytes.length;
                // 创建新数组，大小为截断响应加上截断消息
                byte[] truncatedResponse = new byte[MAX_SIZE];
                // 将截断消息复制到新数组开头
                System.arraycopy(truncationMessageBytes, 0, truncatedResponse, 0, truncationMessageBytes.length);
                // 将原始响应的一部分复制到新数组，紧接着截断消息之后
                System.arraycopy(oneResponseBytes, 0, truncatedResponse, truncationMessageBytes.length, truncatedLength);
                // 用截断的响应（包含截断消息）替换原始响应
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
            int responseBodyLength = responseBody.length();
            for (FingerPrintRule rule : BurpExtender.fingerprintRules) {
                String color = "blue";
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
                for (String key : rule.getKeyword()) {
                    try {
                        if (rule.getMatch().equals("keyword") && !locationContent.toLowerCase().contains(key.toLowerCase())) {
                            isMatch = false;
                            break;
                        } else if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                            continue;
                        } else if (rule.getMatch().equals("regular")) {
                            boolean foundMatch = false;
                            for (int start = 0; start < responseBodyLength; start += CHUNK_SIZE) {
                                int end = Math.min(start + CHUNK_SIZE, responseBodyLength);
                                String responseBodyChunk = responseBody.substring(start, end);

                                Pattern pattern = Pattern.compile(key, Pattern.CASE_INSENSITIVE);
                                Matcher matcher = pattern.matcher(responseBodyChunk);
                                if (matcher.find()) {
                                    foundMatch = true;
                                    // 将匹配到的内容添加到StringBuilder中
                                }
                                if (!foundMatch) {
                                    isMatch = false;
                                }
                            }
                            if (foundMatch) {
                                break;
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
                        color = "red";
                    }
                    StringBuilder matchedResults = new StringBuilder("");
                    for (String key : rule.getKeyword()) {
                        try {
                            if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                                String matchedContext = getMatchedContext(locationContent, key, color);
                                matchedResults.append(matchedContext);
                            } else if (rule.getMatch().equals("regular")) {
                                boolean foundMatch = false;
                                for (int start = 0; start < responseBodyLength; start += CHUNK_SIZE) {
                                    int end = Math.min(start + CHUNK_SIZE, responseBodyLength);
                                    String responseBodyChunk = responseBody.substring(start, end);

                                    Pattern pattern = Pattern.compile(key, Pattern.CASE_INSENSITIVE);
                                    Matcher matcher = pattern.matcher(responseBodyChunk);
                                    while (matcher.find()) {
                                        foundMatch = true;
                                        // 将匹配到的内容添加到StringBuilder中
                                        String matchedContext = getMatchedContext(responseBodyChunk, matcher.start(), matcher.end(), color);
                                        matchedResults.append(matchedContext);
                                        if (matchedResults.length() > RESULT_SIZE) {
                                            break;
                                        }
                                    }
                                }
                                if (foundMatch) {
                                    break;
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
                        resultInfo = "############################ NEXT ############################<br>URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color);
                    } else {
                        resultInfo = resultInfo + "<br><br>############################ NEXT ############################<br>" + "URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color);
                    }
                    originalApiData.setResultInfo(originalApiData.getResultInfo().strip() + "<br><br>############################ NEXT ############################<br>" + "URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color) + "match result: " + matchedResults.toString() + "<br>");
                    onePathData.put("result info", resultInfo + "match result：" + matchedResults.toString() + "<br>");
                }
            }
            BurpExtender.getDataBaseService().insertOrUpdatePathData(Utils.getUriFromUrl(url), onePath, (Boolean) onePathData.get("isImportant"), (String) onePathData.get("status"), (String) onePathData.get("result"), (String) onePathData.get("describe"), onePathData);

        }
        originalApiData.setPathNumber(BurpExtender.getDataBaseService().getPathDataCountByUrl(Utils.getUriFromUrl(url)));
        return originalApiData;
    }

    private static String getMatchedContext(String content, String key, String color) {
        int index = content.toLowerCase().indexOf(key.toLowerCase());
        return getMatchedContext(content, index, index + key.length(), color);
    }

    private static String getMatchedContext(String content, int start, int end, String color) {
        int contextEnd = Math.min(content.length(), end + CONTEXT_LENGTH);
        String match = "<span style='color: " + color + ";'>" +  Utils.encodeForHTML(content.substring(start, end)) + "</span>";
        String afterMatch =  Utils.encodeForHTML(content.substring(end, contextEnd));
        return "<br>=> " + match + afterMatch;
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
        if (originalApiData == null){
            BurpExtender.getStderr().println(onePathData);
        }
        // status更新
        if (originalApiData.getStatus().equals("-")){
            originalApiData.setStatus((String)onePathData.get("status"));
        } else if (!originalApiData.getStatus().contains((String)onePathData.get("status"))) {
            originalApiData.setStatus(originalApiData.getStatus() + "," + onePathData.get("status"));
        }

        // 响应的body值
        String responseBody = new String(oneResponseBytes, StandardCharsets.UTF_8);
        int responseBodyLength = responseBody.length();
        // 响应包是3开头或者404的则不进行匹配
        if (!((String)onePathData.get("status")).startsWith("3") || !((String)onePathData.get("status")).equals("404")){
            // 响应头
            for (FingerPrintRule rule : BurpExtender.fingerprintRules) {
                String color = "blue";
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
                StringBuilder matchedResults = new StringBuilder("");
                for (String key : rule.getKeyword()) {
                    try {
                        if (rule.getMatch().equals("keyword") && !locationContent.toLowerCase().contains(key.toLowerCase())) {
                            isMatch = false;
                            break;
                        } else if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                            continue;
                        } else if (rule.getMatch().equals("regular")) {
                            boolean foundMatch = false;
                            for (int start = 0; start < responseBodyLength; start += CHUNK_SIZE) {
                                int end = Math.min(start + CHUNK_SIZE, responseBodyLength);
                                String responseBodyChunk = responseBody.substring(start, end);

                                Pattern pattern2 = Pattern.compile(key, Pattern.CASE_INSENSITIVE);
                                Matcher matcher2 = pattern2.matcher(responseBodyChunk);
                                while (matcher2.find()) {
                                    foundMatch = true;
                                    // 将匹配到的内容添加到StringBuilder中
                                }
                                if (!foundMatch) {
                                    isMatch = false;
                                }
                            }
                            if (foundMatch) {
                                break;
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
                        color = "red";
                    }
                    matchedResults = new StringBuilder("");
                    for (String key : rule.getKeyword()) {
                        try {
                            if (rule.getMatch().equals("keyword") && locationContent.toLowerCase().contains(key.toLowerCase())) {
                                String matchedContext = getMatchedContext(locationContent, key, color);
                                matchedResults.append(matchedContext);
                            } else if (rule.getMatch().equals("regular")) {
                                boolean foundMatch = false;
                                for (int start = 0; start < responseBodyLength; start += CHUNK_SIZE) {
                                    int end = Math.min(start + CHUNK_SIZE, responseBodyLength);
                                    String responseBodyChunk = responseBody.substring(start, end);

                                    Pattern pattern = Pattern.compile(key, Pattern.CASE_INSENSITIVE);
                                    Matcher matcher = pattern.matcher(responseBodyChunk);
                                    while (matcher.find()) {
                                        foundMatch = true;
                                        // 将匹配到的内容添加到StringBuilder中
                                        String matchedContext = getMatchedContext(responseBodyChunk, matcher.start(), matcher.end(), color);
                                        matchedResults.append(matchedContext);
                                        if (matchedResults.length() > RESULT_SIZE) {
                                            break;
                                        }
                                    }
                                }
                                if (foundMatch) {
                                    break;
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
                        resultInfo = "############################ NEXT ############################<br>URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color);
                    } else {
                        resultInfo = resultInfo + "<br><br>############################ NEXT ############################<br>" + "URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color);
                    }
                    originalApiData.setResultInfo(originalApiData.getResultInfo().strip() + "<br><br>############################ NEXT ############################<br>" + "URL: " + Utils.encodeForHTML(Utils.getUriFromUrl(url) + onePath) + "<br>" + rule.getInfo(color) + "match result: " + matchedResults.toString() + "<br>");
                    onePathData.put("result info", resultInfo + "match result：" + matchedResults.toString() + "<br>");
                }
            }
        }
        String[] onePathDataDescribe1 = ((String)onePathData.get("describe")).split(",");
        String[] exitDescribe = originalApiData.getDescribe().split(",");
        Set<String> describeSet = new HashSet<>();
        describeSet.addAll(Arrays.asList(onePathDataDescribe1));
        describeSet.addAll(Arrays.asList(exitDescribe));
        originalApiData.setDescribe(String.join(",", describeSet).replace("-,", "").replace(",-", "").replace(",误报", "").replace("误报,", ""));
        BurpExtender.getDataBaseService().insertOrUpdatePathData(Utils.getUriFromUrl((String) onePathData.get("url")), (String) onePathData.get("path"), (Boolean) onePathData.get("isImportant"), (String) onePathData.get("status"), (String) onePathData.get("result"), (String) onePathData.get("describe"), onePathData);
        originalApiData.setPathNumber(BurpExtender.getDataBaseService().getPathDataCountByUrl(Utils.getUriFromUrl(url)));
        return originalApiData;
    }
}
