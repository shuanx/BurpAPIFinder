package burp.util;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author： shaun
 * @create： 2024/3/6 20:44
 * @description：TODO
 */
public class HTTPUtils {
    public static int MaxResponseContentLength = 5000000;

    public static Map<String, Object> makeGetRequest(Map<String, Object> pathDataModel) {
        Map<String, Object> onePathData = (Map<String, Object>) pathDataModel.get("path_data");
        onePathData.put("path", pathDataModel.get("path"));
        onePathData.put("url", pathDataModel.get("url"));
        // 插入投入信息
        String insertHeader = (String) pathDataModel.get("cookie");
        if (!insertHeader.equals("")){
            insertHeader = insertHeader + "\r\n";
        }
        // 解析URL
        String host = (String) onePathData.get("host");
        // 使用Number作为中间类型，以应对可能不同的数字类型
        Number portNumber = (Number) onePathData.get("port");
        int port = portNumber.intValue();
        String protocol = (String) onePathData.get("protocol");
        String path = (String) onePathData.get("path");
        // 创建IHttpService对象
        IHttpService httpService = BurpExtender.getHelpers().buildHttpService(host, port, protocol);

        // 构造GET请求的字节数组
        String request = "GET " + path + " HTTP/1.1\r\n" +
                "Host: " + host + "\r\n" + insertHeader +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/90.0.4430.212 Safari/537.36" + "\r\n" +
                "\r\n";
        byte[] requestBytes = request.getBytes();

        // 初始化返回数据结构
        onePathData.put("method", "GET");
        onePathData.put("time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));

        IHttpRequestResponse requestResponse = null;

        try {
            // 发起请求
            requestResponse = BurpExtender.getCallbacks().makeHttpRequest(httpService, requestBytes);
            // 空检查
            if (requestResponse == null || requestResponse.getResponse() == null) {
                throw new IllegalStateException("Request failed, no response received.");
            }

            // 获取响应字节
            byte[] responseBytes = requestResponse.getResponse();
            responseBytes = responseBytes.length  > MaxResponseContentLength ? Arrays.copyOf(responseBytes, MaxResponseContentLength) : responseBytes;
            String statusCode = String.valueOf(BurpExtender.getCallbacks().getHelpers().analyzeResponse(responseBytes).getStatusCode());

            // 添加请求和响应数据到返回数据结构
            onePathData.put("requests", Base64.getEncoder().encodeToString(requestBytes));
            onePathData.put("response", Base64.getEncoder().encodeToString(responseBytes));
            onePathData.put("status", statusCode);
        } catch (Exception e) {
            // 异常处理，记录错误信息
            onePathData.put("status", "请求报错");
            onePathData.put("requests", Base64.getEncoder().encodeToString(requestBytes));
            onePathData.put("response", Base64.getEncoder().encodeToString(e.getMessage().getBytes()));
        }

        return onePathData;

    }
}
