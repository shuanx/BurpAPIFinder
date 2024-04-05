package burp;

import burp.application.ApiScanner;
import burp.ui.ApiDocumentListTree;
import burp.ui.ConfigPanel;
import burp.ui.ExtensionTab;
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
    private final ApiScanner apiScanner;
    private int scannedCount = 1;
    private final ThreadPoolExecutor executorService;  // 修改这行
    private static IExtensionHelpers helpers;
    public static Map<String, Object> totalUrlResult;

    public IProxyScanner() {
        totalUrlResult = new HashMap<String, Object>();
        helpers = BurpExtender.getHelpers();
        this.apiScanner = new ApiScanner();
        // 先新建一个进程用于后续处理任务
        executorService = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);  // 修改这行
    }



    public ApiScanner getApiScanner() {
        return apiScanner;
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

                    // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
                    Map<String, Object> originalData = new HashMap<String, Object>();
                    // 判断url是否已在totalUrlResult之中
                    if (totalUrlResult.containsKey(Utils.getPathFromUrl(url))){
                        originalData = (Map<String, Object>)totalUrlResult.get(Utils.getUriFromUrl(url));
                        originalData.put("Time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                    }else{
                        originalData.put("Url", Utils.getUriFromUrl(url));
                        originalData.put("requestResponse", requestResponse);
                        originalData.put("Uri Number", 1);
                        originalData.put("HavingImportant", false);
                        originalData.put("Status", finalStatusCode);
                        originalData.put("Result", "-");
                        originalData.put("Time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
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
                        BurpExtender.getStdout().println("[+] 进入网页提取URL页面： " + url + "\r\n URL result: " + urlSet);
                        Map<String, Object> uriData = new HashMap<>();
                        // 判断原先是否已有uriData
                        if (originalData.containsKey("uri")){
                            uriData = (Map<String, Object>) originalData.get("uri");
                        }
                        if (!uriData.containsKey(Utils.getPathFromUrl(url))){
                            Map<String, Object> getUriData = new HashMap<String, Object>();
                            getUriData.put("responseRequest", requestResponse);
                            getUriData.put("isJsFindUrl", false);
                            getUriData.put("method", method);
                            getUriData.put("time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                            uriData.put(Utils.getPathFromUrl(url), getUriData);
                        }

                        // 依次遍历urlSet获取其返回的response值
                        for (String getUrl : urlSet) {
                            uriData.put(Utils.getPathFromUrl(getUrl), HTTPUtils.makeGetRequest(getUrl));
                        }

                        originalData.put("uri", uriData);
                    }
                    totalUrlResult.put(Utils.getUriFromUrl(url), originalData);

                    //  清空表格数据的再刷新
                    synchronized (BurpExtender.getExtensionTab().getApiTable().getTableData()) {
                        BurpExtender.getExtensionTab().clearTableData();
                        // 结果展示
                        for (Map.Entry<String, Object> entry : totalUrlResult.entrySet()) {
                            ApiDocumentListTree apiDocumentListTree = getApiDocumentListTree(entry, iInterceptedProxyMessage);
                            BurpExtender.getExtensionTab().add(apiDocumentListTree);
                        }
                    }


                }
            });

        }

    }

    private static ApiDocumentListTree getApiDocumentListTree(Map.Entry<String, Object> entry, IInterceptedProxyMessage iInterceptedProxyMessage) {
        Map<String, Object> oneResult = (Map<String, Object>) entry.getValue();;
        Map<String, Object> uriData = (Map<String, Object>)oneResult.get("uri");
        ApiDocumentListTree apiDocumentListTree = new ApiDocumentListTree(BurpExtender.getExtensionTab());

        ExtensionTab.ApiTableData mainApiData = new ExtensionTab.ApiTableData(false,
                apiDocumentListTree,
                String.valueOf(iInterceptedProxyMessage.getMessageReference()),
                entry.getKey(),
                String.valueOf(uriData.size()),
                true,
                (String) oneResult.get("Result"),
                (IHttpRequestResponse) oneResult.get("requestResponse"),
                (String) oneResult.get("Time"),
                (String) oneResult.get("Status"),
                false,
                "-");
        ArrayList<ExtensionTab.ApiTableData> subApiData = new ArrayList<>();

        mainApiData.setTreeStatus(Constants.TREE_STATUS_COLLAPSE);

        apiDocumentListTree.setMainApiData(mainApiData);
        for (Map.Entry<String, Object> uriEntry : uriData.entrySet()){
            Map<String, Object> subUriValue = (Map<String, Object>)uriEntry.getValue();
            ExtensionTab.ApiTableData currentData = new ExtensionTab.ApiTableData(true,
                    apiDocumentListTree,
                    "-",
                    uriEntry.getKey(),
                    "-",
                    false,
                    "-",
                    (IHttpRequestResponse) subUriValue.get("responseRequest"),
                    (String) subUriValue.get("time"),
                    (String) subUriValue.get("status"),
                    (Boolean) subUriValue.get("isJsFindUrl"),
                    (String) subUriValue.get("method"));
            subApiData.add(currentData);
        }
        // 子项
        apiDocumentListTree.setSubApiData(subApiData);
        return apiDocumentListTree;
    }

}
