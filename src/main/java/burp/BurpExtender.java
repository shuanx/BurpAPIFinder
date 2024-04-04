package burp;

import burp.ui.LogEntry;
import burp.util.Utils;
import burp.ui.GUI;

import java.awt.Component;
import java.io.PrintWriter;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import javax.swing.*;

public class BurpExtender implements IBurpExtender,ITab,IProxyListener {
    public final static String extensionName = "Finger Print";
    public final static String version = "v2024-02-17";
    public final static String author = "Shaun";
    public static IBurpExtenderCallbacks callbacks;
    public static IExtensionHelpers helpers;
    public static PrintWriter stdout;
    public static PrintWriter stderr;
    public static BurpExtender burpExtender;
    private ExecutorService executorService;
    public static GUI gui;
    public static final List<LogEntry> log = new ArrayList<LogEntry>();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.burpExtender = this;
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(),true);
        this.stderr = new PrintWriter(callbacks.getStderr(),true);

        //  注册菜单拓展
        callbacks.setExtensionName(extensionName + " " + version);
        BurpExtender.this.gui = new GUI();
        SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                // 添加一个标签页
                BurpExtender.this.callbacks.addSuiteTab(BurpExtender.this);
                // 继承IProxyListener，必须进行注册，才能正常使用processProxyMessage模块
                BurpExtender.this.callbacks.registerProxyListener(BurpExtender.this);
                stdout.println(Utils.getBanner());
            }
        });
        // 先新建一个进程用于后续处理任务
        executorService = Executors.newSingleThreadExecutor();
    }

    @Override
    public Component getUiComponent() {
        return gui.getComponet();
    }

    @Override
    public String getTabCaption() {
        return extensionName;
    }

    //    IHttpRequestResponse 接口包含了每个请求和响应的细节，在 brupsuite 中的每个请求或者响应都是 IHttpRequestResponse 实例。通过 getRequest()可以获取请求和响应的细节信息。
    public void processProxyMessage(boolean messageIsRequest, final IInterceptedProxyMessage iInterceptedProxyMessage) {
        if (!messageIsRequest) {
            IHttpRequestResponse reprsp = iInterceptedProxyMessage.getMessageInfo();
            IHttpService httpService = reprsp.getHttpService();
            String host = reprsp.getHttpService().getHost();

            String  url = helpers.analyzeRequest(httpService,reprsp.getRequest()).getUrl().toString();
            url = url.indexOf("?") > 0 ? url.substring(0, url.indexOf("?")) : url;
            stdout.println(url);

            final IHttpRequestResponse resrsp = iInterceptedProxyMessage.getMessageInfo();

            // 使用新建出来的executorService单线程处理任务
            executorService.submit(new Runnable() {
                @Override
                public void run() {
                    synchronized(log) {
                        int row = log.size();
                        String method = helpers.analyzeRequest(resrsp).getMethod();
                        Map<String, String> mapResult =  new HashMap<String, String>();
                        mapResult.put("status", "status");
                        mapResult.put("header", "header");
                        mapResult.put("result", "result");
                        stdout.println(mapResult);
                        // 对log添加数据
                        log.add(new LogEntry(iInterceptedProxyMessage.getMessageReference(),
                                callbacks.saveBuffersToTempFiles(resrsp), helpers.analyzeRequest(resrsp).getUrl(),
                                method,
                                mapResult)
                        );
                        // 更新表格数据，表格数据对接log
                        GUI.logTable.getHttpLogTableModel().fireTableRowsInserted(row, row);
                    }
                }
            });
        }
    }


}