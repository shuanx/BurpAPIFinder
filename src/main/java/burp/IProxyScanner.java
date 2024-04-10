package burp;

import burp.ui.ConfigPanel;
import burp.ui.Tags;
import burp.ui.datmodel.ApiDataModel;
import burp.util.*;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;

/**
 * @author： shaun
 * @create： 2024/4/5 09:07
 * @description：TODO
 */
public class IProxyScanner implements IProxyListener {
    private final UrlScanCount scanedUrl = new UrlScanCount();
    private int scannedCount = 1;
    private final ThreadPoolExecutor executorService;  // 修改这行
    private static IExtensionHelpers helpers;
    public static Map<String, ApiDataModel> apiDataModelMap;

    public IProxyScanner() {
        apiDataModelMap = new HashMap<String, ApiDataModel>();
        helpers = BurpExtender.getHelpers();
        // 先新建一个进程用于后续处理任务
        executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(5);  // 修改这行
    }


    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            int newRequestsCount = Integer.parseInt(ConfigPanel.lbRequestCount.getText()) + 1;
            ConfigPanel.lbRequestCount.setText(Integer.toString(newRequestsCount));

            // 判断是否要进行指纹识别，如果关闭，则只展示数量
            if (ConfigPanel.toggleButton.isSelected()){
                return;
            }

            IHttpRequestResponse requestResponse = iInterceptedProxyMessage.getMessageInfo();
            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();
            String method = helpers.analyzeRequest(resrsp).getMethod();

            // 提取url，过滤掉静态文件
            String url = String.valueOf(helpers.analyzeRequest(resrsp).getUrl());
            if (this.scanedUrl.get(url) <= 0) {
                this.scanedUrl.add(url);
            } else {
                BurpExtender.getStdout().println("[-] 已识别过URL，不进行重复识别");
//                return;
            }
            if (Utils.isStaticFile(url) && !url.contains("favicon.") && !url.contains(".ico")){
                BurpExtender.getStdout().println("[+]静态文件，不进行url识别：" + url);
                return;
            }

            byte[] responseBytes = requestResponse.getResponse();
            String statusCode = "error";
            if (responseBytes != null) {
                // 解析响应
                statusCode = String.valueOf(BurpExtender.getCallbacks().getHelpers().analyzeResponse(responseBytes).getStatusCode());
            }

            // 网页提取URL并进行指纹识别
            String finalStatusCode = statusCode;
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    Map<String, Object> pathData = new HashMap<>();

                    // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
                    ApiDataModel originalApiData;
                    // 判断url是否已在totalUrlResult之中
                    if (apiDataModelMap.containsKey(Utils.getPathFromUrl(url))) {

                        originalApiData = apiDataModelMap.get(Utils.getUriFromUrl(url));
                        originalApiData.setTime(new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                    } else {
                        originalApiData = new ApiDataModel(
                                Constants.TREE_STATUS_COLLAPSE,
                                String.valueOf(iInterceptedProxyMessage.getMessageReference()),
                                Utils.getUriFromUrl(url),
                                "0",
                                false,
                                "-",
                                requestResponse,
                                new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()),
                                "-",
                                "-",
                                "-",
                                pathData);
                    }
                    if (!url.contains("favicon.") && !url.contains(".ico")) {
                        String mime = helpers.analyzeResponse(responseBytes).getInferredMimeType();
                        URL urlUrl = helpers.analyzeRequest(resrsp).getUrl();
                        // 针对html页面提取
                        Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtml(url, new String(responseBytes)));
                        // 针对JS页面提取
                        if (mime.equals("script") || mime.equals("HTML") || url.contains(".htm") || Utils.isGetUrlExt(url)) {
                            urlSet.addAll(Utils.findUrl(urlUrl, new String(responseBytes)));
                        }
                        BurpExtender.getStdout().println("[+] 进入网页提取URL页面： " + url + "==> URL result: " + urlSet);
                        // 判断原先是否已有uriData
                        if (!originalApiData.getPathData().isEmpty()) {
                            pathData = originalApiData.getPathData();
                        }
                        if (!pathData.containsKey(Utils.getPathFromUrl(url)) && !Utils.isStaticFile(url) && !Utils.isStaticPath(url) && !Utils.getPathFromUrl(url).endsWith(".js")) {
                            Map<String, Object> getUriData = new HashMap<String, Object>();
                            getUriData.put("responseRequest", requestResponse);
                            getUriData.put("isJsFindUrl", "N");
                            getUriData.put("method", method);
                            getUriData.put("status", finalStatusCode);
                            getUriData.put("time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                            pathData.put(Utils.getPathFromUrl(url), getUriData);
                        }

                        // 依次遍历urlSet获取其返回的response值
                        for (String getUrl : urlSet) {
                            pathData.put(Utils.getPathFromUrl(getUrl), HTTPUtils.makeGetRequest(getUrl));
                        }
                        if (pathData.isEmpty()) {
                            return;
                        }
                        originalApiData.setPathNumber(String.valueOf(pathData.size()));
                        originalApiData.setPathData(pathData);

                    }
                    if (apiDataModelMap.containsKey(Utils.getUriFromUrl(url))) {
                        BurpExtender.getTags().getMainPanel().editApiData(originalApiData);
                    } else {
                        BurpExtender.getTags().getMainPanel().addApiData(originalApiData);
                    }
                    apiDataModelMap.put(Utils.getUriFromUrl(url), originalApiData);
                }
            });

        }

    }

}
