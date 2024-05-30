package burp;

import burp.ui.ConfigPanel;
import burp.dataModel.ApiDataModel;
import burp.ui.MailPanel;
import burp.util.*;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/**
 * @author： shaun
 * @create： 2024/4/5 09:07
 * @description：TODO
 */
public class IProxyScanner implements IProxyListener {
    private static UrlScanCount haveScanUrl = new UrlScanCount();
    public static int totalScanCount = 0;
    final ThreadPoolExecutor executorService;  // 修改这行
    private static IExtensionHelpers helpers;
    static ScheduledExecutorService monitorExecutor;
    private static int monitorExecutorServiceNumberOfIntervals = 2;
    private static int MaxResponseContentLength = 200000;


    public IProxyScanner() {
        helpers = BurpExtender.getHelpers();

        int coreCount = Math.min(Runtime.getRuntime().availableProcessors(), 16);

        int maxPoolSize = coreCount * 2;

        // 高性能模式
        monitorExecutorServiceNumberOfIntervals = (Runtime.getRuntime().availableProcessors() > 6) ? 1 : monitorExecutorServiceNumberOfIntervals;
        long keepAliveTime = 60L;

        // 创建一个足够大的队列来处理您的任务
        BlockingQueue<Runnable> workQueue = new LinkedBlockingQueue<>(10000);

        executorService = new ThreadPoolExecutor(
                coreCount,
                maxPoolSize,
                keepAliveTime,
                TimeUnit.SECONDS,
                workQueue,
                Executors.defaultThreadFactory(),
                new ThreadPoolExecutor.AbortPolicy() // 当任务太多时抛出异常，可以根据需要调整策略
        );
        BurpExtender.getStdout().println("[+] run executorService maxPoolSize: " + coreCount + " ~ " + maxPoolSize + ", monitorExecutorServiceNumberOfIntervals: " + monitorExecutorServiceNumberOfIntervals);

        monitorExecutor = Executors.newSingleThreadScheduledExecutor();
        startDatabaseMonitor();
    }

    private void startDatabaseMonitor() {
        monitorExecutor.scheduleAtFixedRate(() -> {
            executorService.submit(() -> {
                try {

                    if (executorService.getActiveCount() >= 6){
                        return;
                    }

                    Random random = new Random();
                    if (random.nextInt(5) == 2){
                        int totalJsCrawledNumber = BurpExtender.getDataBaseService().getJSCrawledTotalCountPathDataWithIsJsFindUrl();
                        int haveJsCrawledNumber = BurpExtender.getDataBaseService().getJSCrawledCountPathDataWithStatus();
                        int totalUrlCrawledNumber = BurpExtender.getDataBaseService().getJSCrawledTotalCountOriginalData();
                        int haveUrlCrawledNumber = BurpExtender.getDataBaseService().getUrlCrawledCountOriginalDataWithStatus();
                        ConfigPanel.jsCrawledCount.setText(haveJsCrawledNumber + "/" + totalJsCrawledNumber);
                        ConfigPanel.urlCrawledCount.setText(haveUrlCrawledNumber + "/" + totalUrlCrawledNumber);
                        ConfigPanel.lbSuccessCount.setText(String.valueOf(BurpExtender.getDataBaseService().getApiDataCount()));
                    }
                    // 步骤一：判断是否有需要解析
                    Map<String, Object> oneOriginalData = BurpExtender.getDataBaseService().fetchAndMarkOriginalDataAsCrawling();
                    Map<String, Object> onePathData =  new HashMap<>();
                    String url = "";
                    if (!oneOriginalData.isEmpty()){
                        BurpExtender.getStdout().println("[+] 正在解析: " + oneOriginalData.get("url"));
                        runAPIFinder(oneOriginalData);
                    }else if (ConfigPanel.toggleButton.isSelected()) {
                        return;
                    }else if(!(onePathData =  BurpExtender.getDataBaseService().fetchAndMarkSinglePathAsCrawling()).isEmpty()){
                        // 步骤二：判断是否有需要爬取URL
                        BurpExtender.getStdout().println("[+] 正在爬取： " + onePathData.get("url") + onePathData.get("path"));
                        ApiDataModel mergeApiData = FingerUtils.FingerFilter(HTTPUtils.makeGetRequest(onePathData));
                        mergeApiData.setHavingImportant(BurpExtender.getDataBaseService().hasImportantPathDataByUrl(Utils.getUriFromUrl(mergeApiData.getUrl())));
                        BurpExtender.getDataBaseService().updateApiDataModelByUrl(mergeApiData);
                    } else if(!(onePathData = BurpExtender.getDataBaseService().fetchAndMarkSinglePathAsCrawlingByNewParentPath()).isEmpty()){
                        BurpExtender.getStdout().println("[+] 正在爬去Js提取Parent合并后的url： " + onePathData.get("url") + onePathData.get("path"));
                        Map<String, Object> pathData = HTTPUtils.makeGetRequest(onePathData);
                        pathData.put("isJsFindUrl", "YY");
                        ApiDataModel mergeApiData = FingerUtils.FingerFilter(pathData);
                        mergeApiData.setHavingImportant(BurpExtender.getDataBaseService().hasImportantPathDataByUrl(Utils.getUriFromUrl(mergeApiData.getUrl())));
                        BurpExtender.getDataBaseService().updateApiDataModelByUrl(mergeApiData);
                    }else if (!(url = BurpExtender.getDataBaseService().fetchAndMarkApiData()).equals("")){
                        BurpExtender.getStdout().println("[+] 进入Js提取Parent的逻辑：" + url);
                        // 步骤一：读取该url对应的非爬取的url
                        Map<String, Object> notJsFindUrlAndNot404 = BurpExtender.getDataBaseService().selectPathDataByUrlAndStatusNot404(url);
                        // 步骤二：读取该url对应的爬取的url
                        Map<String, Object> isFindUrl = BurpExtender.getDataBaseService().selectPathDataByUrlAndIsJsFindUrl(url);
                        // 步骤三：进行匹配，看是否有匹配成功
                        // 遍历filteredPathData2的键，并检查它们是否部分包含在filteredPathData的键中
                        Map<String, Set<String>> uniqueElementsParent =new HashMap<>();
                        for (String keyToCheck : isFindUrl.keySet()) {

                            // 在filteredPathData的键中寻找任何包含keyToCheck的键
                            for (String key : notJsFindUrlAndNot404.keySet()) {
                                if (key.contains(keyToCheck)) {
                                    // 提取出parent
                                    String parentPath = key.replace(keyToCheck, "");
                                    if (parentPath.length() < 3){
                                        continue;
                                    }
                                    // BurpExtender.getStdout().println("[+] jsFindUrl: " + isFindUrl.get(keyToCheck) + ", parentPath: " + parentPath + ", Key: " + key);
                                    uniqueElementsParent.computeIfAbsent((String) isFindUrl.get(keyToCheck), k -> new HashSet<>()).add(parentPath);
                                    break;
                                }
                            }
                        }
                        for (Map.Entry<String, Set<String>> entry : uniqueElementsParent.entrySet()) {
                            String jsFindUrl = entry.getKey();
                            Set<String> valueSet = entry.getValue();

                            // 将Set转换为以逗号分隔的字符串
                            String mayNewParentPath = String.join(", ", valueSet);

                            // 输出到BurpExtender的标准输出
                            BurpExtender.getStdout().println("jsFindUrl: " + jsFindUrl + ", mayNewParentPath: " + mayNewParentPath);
                            // 步骤四：对匹配的数据库进行写入
                            BurpExtender.getDataBaseService().updatePathDataMayNewParentPath(mayNewParentPath, jsFindUrl);
                        }
                    }
                    //


                } catch (Exception e) {
                    BurpExtender.getStderr().println("[!] scheduleAtFixedRate error: ");
                    e.printStackTrace(BurpExtender.getStderr());
                }
            });
        }, 0, monitorExecutorServiceNumberOfIntervals, TimeUnit.SECONDS);
    }


    public static void shutdownMonitorExecutor() {
        // 关闭监控线程池
        if (monitorExecutor != null && !monitorExecutor.isShutdown()) {
            monitorExecutor.shutdown();
            try {
                // 等待线程池终止，设置一个合理的超时时间
                if (!monitorExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    // 如果线程池没有在规定时间内终止，则强制关闭
                    monitorExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                // 如果等待期间线程被中断，恢复中断状态
                Thread.currentThread().interrupt();
                // 强制关闭
                monitorExecutor.shutdownNow();
            }
        }
    }

    public static void setHaveScanUrlNew(){
        haveScanUrl = new UrlScanCount();
        ConfigPanel.lbSuccessCount.setText("0");
        ConfigPanel.lbRequestCount.setText("0");
        ConfigPanel.jsCrawledCount.setText("0/0");
        ConfigPanel.urlCrawledCount.setText("0/0");
        BurpExtender.getDataBaseService().clearApiDataTable();
        BurpExtender.getDataBaseService().clearPathDataTable();
        BurpExtender.getDataBaseService().clearRequestsResponseTable();
        BurpExtender.getDataBaseService().clearOriginalDataTable();
    }

    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            totalScanCount += 1;
            ConfigPanel.lbRequestCount.setText(Integer.toString(totalScanCount));

            IHttpRequestResponse requestResponse = iInterceptedProxyMessage.getMessageInfo();
            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();
            String method = helpers.analyzeRequest(resrsp).getMethod();
            // 提取url，过滤掉静态文件
            String url = String.valueOf(helpers.analyzeRequest(resrsp).getUrl());
            byte[] responseBytes = resrsp.getResponse().length > MaxResponseContentLength ? Arrays.copyOf(resrsp.getResponse(), MaxResponseContentLength) : resrsp.getResponse();


            // 返回结果为空则退出
            if (responseBytes == null || responseBytes.length == 0) {
                BurpExtender.getStdout().println("返回结果为空: " + url);
                return;
            }

            // 匹配白名单路径
            if (Utils.isWhiteDomain(Utils.getUriFromUrl(url))){
                BurpExtender.getStdout().println("[-] 命中白名单， 不进行url识别： " + url);
                return;
            }

            // 匹配静态文件
            if (Utils.isStaticFile(url) || url.contains("favicon.")){
                BurpExtender.getStdout().println("[-] 命中静态文件，不进行url识别：" + url);
                return;
            }
            // 看URL识别是否报错
            String extractBaseUrl = Utils.extractBaseUrl(url);
            if (extractBaseUrl.equals("-")){
                BurpExtender.getStdout().println("[-] URL转化失败， 不进行url识别： " + url);
                return;
            }
            String statusCode = String.valueOf(BurpExtender.getCallbacks().getHelpers().analyzeResponse(responseBytes).getStatusCode());
            // 看status是否为30开头
            if (statusCode.startsWith("3") || statusCode.equals("404")){
                BurpExtender.getStdout().println("[-] URL的响应包状态码3开头， 不进行url识别： " + url);
                return;
            }

            if (haveScanUrl.get((Utils.extractBaseUrl(url).hashCode() + statusCode + method)) <= 0) {
                haveScanUrl.add(Utils.extractBaseUrl(url).hashCode() + statusCode + method);
            } else {
                BurpExtender.getStdout().println("[-] 已识别过URL，不进行重复识别： " + url);
                return;
            }


            // 网页提取URL并进行指纹识别
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    int requestResponseIndex =  BurpExtender.getDataBaseService().insertOrUpdateRequestResponse(url, resrsp.getRequest(), responseBytes);
                    if (requestResponseIndex == -1){
                        BurpExtender.getStderr().println("[!] error in insertOrUpdateRequestResponse: " + url);
                        return;
                    }
                    int insertOrUpdateOriginalDataIndex = BurpExtender.getDataBaseService().insertOrUpdateOriginalData(url, iInterceptedProxyMessage.getMessageReference(), statusCode, method, requestResponseIndex, resrsp.getHttpService());
                    if (insertOrUpdateOriginalDataIndex == -1){
                        BurpExtender.getStderr().println("[!] error in insertOrUpdateOriginalData: " + url);
                    }
                }
            });
        }

    }

    public static void runAPIFinder(Map<String, Object> oneOriginalData){
        Map<String, Object> pathData = new HashMap<>();
        String url = (String)oneOriginalData.get("url");
        String host = (String) oneOriginalData.get("host");
        int port =  (Integer) oneOriginalData.get("port");
        String protocol = (String)oneOriginalData.get("protocol");
        // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
        ApiDataModel originalApiData = new ApiDataModel(
                Constants.TREE_STATUS_COLLAPSE,
                (String) oneOriginalData.get("pid"),
                Utils.getUriFromUrl(url),
                "0",
                false,
                "-",
                (Integer) oneOriginalData.get("request_response_index"),
                Utils.iHttpService(host, port, protocol),
                new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()),
                "-",
                "-",
                "-",
                "-",
                "\r\n");
        try {
            Map<String, byte[]> requestResponseMap =  BurpExtender.getDataBaseService().selectRequestResponseById((Integer) oneOriginalData.get("request_response_index"));
            byte[] responseBytes = requestResponseMap.get("response");
            byte[] requestBytes  = requestResponseMap.get("request");
            String mime = helpers.analyzeResponse(responseBytes).getInferredMimeType();

            if (!pathData.containsKey(Utils.getPathFromUrl(url)) && !Utils.isStaticFile(url) && !Utils.isStaticPathByPath(Utils.getPathFromUrl(url))) {
                Map<String, Object> getUriData = new HashMap<String, Object>();
                getUriData.put("requests", Base64.getEncoder().encodeToString(requestBytes));
                getUriData.put("response", Base64.getEncoder().encodeToString(responseBytes));
                getUriData.put("host", host);
                getUriData.put("port", port);
                getUriData.put("protocol", protocol);
                getUriData.put("isJsFindUrl", "N");
                getUriData.put("method", oneOriginalData.get("method"));
                getUriData.put("status", oneOriginalData.get("status"));
                getUriData.put("isImportant", false);
                getUriData.put("result", "-");
                getUriData.put("result info", "-");
                getUriData.put("describe", "-");
                getUriData.put("time", new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                getUriData.put("url", Utils.getUriFromUrl(url));
                getUriData.put("path", Utils.getPathFromUrl(url));
                getUriData.put("jsFindUrl", "-");
                pathData.put(Utils.getPathFromUrl(url), getUriData);
            }

            // 针对html页面提取
            Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtml(url, new String(responseBytes)));
            // 针对JS页面提取
            if (mime.equals("script") || mime.equals("HTML") || url.contains(".htm") || Utils.isGetUrlExt(url)) {
                urlSet.addAll(Utils.findUrl(url, port, host, protocol, new String(responseBytes)));
            }
            // 依次遍历urlSet获取其返回的response值
            for (String getUrl : urlSet) {
                if (Utils.isStaticFile(getUrl) || Utils.getPathFromUrl(getUrl).length() < 4) {
                    BurpExtender.getStdout().println("白Ext或者太短path，过滤掉： " + getUrl);
                    continue;
                }
                // 当前请求的URL，requests，Response，以及findUrl来区别是否为提取出来的URL
                Map<String, Object> originalData = new HashMap<String, Object>();
                originalData.put("requests", null);
                originalData.put("response", null);
                originalData.put("host", host);
                originalData.put("port", port);
                originalData.put("protocol", protocol);
                originalData.put("isJsFindUrl", "Y");
                originalData.put("method", "GET");
                originalData.put("status", "等待爬取");
                originalData.put("isImportant", false);
                originalData.put("result", "-");
                originalData.put("result info", "-");
                originalData.put("describe", "-");
                originalData.put("time", '-');
                originalData.put("url", Utils.getUriFromUrl(url));
                originalData.put("path", Utils.getPathFromUrl(getUrl));
                originalData.put("jsFindUrl", url);
                pathData.put(Utils.getPathFromUrl(getUrl), originalData);
            }

            if (pathData.isEmpty()) {
                return;
            }

        }catch (Exception e) {
            BurpExtender.getStderr().println("数据提取uri的时候报错：" + url);
            e.printStackTrace(BurpExtender.getStderr());
        }

        try{
            ApiDataModel newOriginalApiData = FingerUtils.FingerFilter(url, originalApiData, pathData, BurpExtender.getHelpers());
            if (!BurpExtender.getDataBaseService().isExistApiDataModelByUri(Utils.getUriFromUrl(url))) {
                newOriginalApiData.setHavingImportant(BurpExtender.getDataBaseService().hasImportantPathDataByUrl(Utils.getUriFromUrl(url)));
                BurpExtender.getDataBaseService().insertApiDataModel(newOriginalApiData);
            } else {
                ApiDataModel existedApiData = BurpExtender.getDataBaseService().selectApiDataModelByUri(Utils.getUriFromUrl(url));
                ApiDataModel mergeApiData = mergeApiData(url, existedApiData, newOriginalApiData);
                mergeApiData.setHavingImportant(BurpExtender.getDataBaseService().hasImportantPathDataByUrl(Utils.getUriFromUrl(url)));
                BurpExtender.getDataBaseService().updateApiDataModelByUrl(mergeApiData);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("数据合并的时候报错： " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public static ApiDataModel mergeApiData(String url, ApiDataModel apiDataModel1, ApiDataModel apiDataModel2){

        // 合并status
        // 将字符串分割成数组
        String[] apiDataStatusList1 = apiDataModel1.getStatus().split(",");
        String[] apiDataStatusList2 = apiDataModel2.getStatus().split(",");
        // 创建一个 HashSet 并添加所有元素来去除重复项
        Set<String> statusSet = new HashSet<>();
        statusSet.addAll(Arrays.asList(apiDataStatusList1));
        statusSet.addAll(Arrays.asList(apiDataStatusList2));
        // 将 Set 转换回 String，元素之间用逗号分隔
        apiDataModel1.setStatus(String.join(",", statusSet).replace("-,", "").replace(",-", ""));

        // 合并result
        // 将字符串分割成数组
        String[] apiDataResultList1 = apiDataModel1.getResult().split(",");
        String[] apiDataResultList2 = apiDataModel2.getResult().split(",");
        // 创建一个 HashSet 并添加所有元素来去除重复项
        Set<String> resultSet = new HashSet<>();
        resultSet.addAll(Arrays.asList(apiDataResultList1));
        resultSet.addAll(Arrays.asList(apiDataResultList2));
        // 将 Set 转换回 String，元素之间用逗号分隔
        apiDataModel1.setResult(String.join(",", resultSet).replace("-,", "").replace(",-", "").replace(",误报", "").replace("误报,", ""));

        // 合并describe
        String[] apiDataDescribeList1 = apiDataModel1.getDescribe().split(",");
        String[] apiDataDescribeList2 = apiDataModel2.getDescribe().split(",");
        // 创建一个 HashSet 并添加所有元素来去除重复项
        Set<String> describeSet = new HashSet<>();
        describeSet.addAll(Arrays.asList(apiDataDescribeList1));
        describeSet.addAll(Arrays.asList(apiDataDescribeList2));
        // 将 Set 转换回 String，元素之间用逗号分隔
        apiDataModel1.setDescribe(String.join(",", describeSet).replace("-,", "").replace(",-", "").replace(",误报", "").replace("误报,", ""));

        // 合并PathData
        apiDataModel1.setTime(apiDataModel2.getTime());

        apiDataModel1.setPathNumber(BurpExtender.getDataBaseService().getPathDataCountByUrl(Utils.getUriFromUrl(url)));
        apiDataModel1.setResultInfo((apiDataModel1.getResultInfo() + "\r\n" + apiDataModel2.getResultInfo()).strip());
        return apiDataModel1;
    }


}
