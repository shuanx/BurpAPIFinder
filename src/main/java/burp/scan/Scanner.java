package burp.scan;

import burp.*;
import burp.ui.tabs.SettingUi;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：入口
 */
public class Scanner implements IScannerCheck {

    public BurpExtender burpExtender;
    private IExtensionHelpers helpers;

    // 存放每次同类uri的md5, 防止重复扫描
    private final Set<String> allScan = new HashSet<String>();

    // 定时任务
    private Timer timer;

    public Scanner(BurpExtender burpExtender) {
        // 获取父类的操作类
//        this.burpExtender = burpExtender;
//        this.helpers = this.burpExtender.helpers;
//        this.timer = new Timer();
    }

    /**
     * 只做被动扫描
     */
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse iHttpRequestResponse) {
        // 插件是否开启
        return this.doScan(iHttpRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse iHttpRequestResponse, IScannerInsertionPoint iScannerInsertionPoint) {
        return null;
    }

    public List<IScanIssue> doScan(IHttpRequestResponse iHttpRequestResponse) {
        // vul?
        boolean isVul = false;
        List<IScanIssue> issues = new ArrayList<IScanIssue>();
        IRequestInfo requestInfo = this.helpers.analyzeRequest(iHttpRequestResponse);
        IResponseInfo responseInfo = this.helpers.analyzeResponse(iHttpRequestResponse.getResponse());
        String url = String.valueOf(requestInfo.getUrl());

        return null;
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue iScanIssue, IScanIssue iScanIssue1) {
        return 0;
    }

}
