package burp.ui;

import burp.IHttpRequestResponsePersisted;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Map;

public class LogEntry {
    final int id;
    final IHttpRequestResponsePersisted requestResponse;
    final URL url;
    final String method;
    final String status;
    final String proxyResponse;
    public String requestTime;

    public LogEntry(int id, IHttpRequestResponsePersisted requestResponse, URL url, String method, Map<String, String> mapResult) {
        this.id = id;
        this.requestResponse = requestResponse;
        this.url = url;
        this.method = method;
        this.status = mapResult.get("status");
        this.proxyResponse = mapResult.get("header") + "\r\n" + mapResult.get("result");
        this.requestTime = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date());
    }
}
