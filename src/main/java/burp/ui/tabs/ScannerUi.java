package burp.ui.tabs;

import burp.*;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * @author : metaStor
 * @date : Created 2022/4/6 7:27 PM
 * @description:
 */
public class ScannerUi extends AbstractTableModel implements IMessageEditorController {

    private IBurpExtenderCallbacks callbacks;

    private IHttpRequestResponse currentHttp;
    private IMessageEditor messageRequest;
    private IMessageEditor messageResponse;
    private List<TableData> tasks = new ArrayList<TableData>();  // 适配jdk8语法

    // ui
    private JTabbedPane tabs;
    private JPanel ScannerUI;
    private JSplitPane mainSplitPane;  // 分割上下任务/数据包
    private JSplitPane httpSplitPane;  // 分割左右请求/响应包
    private JScrollPane tablePane;
    private JTabbedPane requestPane;
    private JTabbedPane responsePane;


    public ScannerUi(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        this.callbacks = callbacks;
        this.tabs = tabs;
        this.initUI();
        this.tabs.addTab("Scanner", this.ScannerUI);
    }

    private void initUI() {
        this.ScannerUI = new JPanel(new BorderLayout());

        this.mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        this.httpSplitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        this.httpSplitPane.setDividerLocation(.5d);  // 位置均分

        Table table = new Table(ScannerUi.this);
        this.tablePane = new JScrollPane(table);

        this.requestPane = new JTabbedPane();
        this.responsePane = new JTabbedPane();
        this.messageRequest = this.callbacks.createMessageEditor(this, false);  // 不可编辑
        this.messageResponse = this.callbacks.createMessageEditor(this, false);
        this.requestPane.addTab("Request", this.messageRequest.getComponent());
        this.responsePane.addTab("Response", this.messageResponse.getComponent());

        this.httpSplitPane.add(this.requestPane);
        this.httpSplitPane.add(this.responsePane);

        this.mainSplitPane.add(this.tablePane);
        this.mainSplitPane.add(this.httpSplitPane);
        this.ScannerUI.add(this.mainSplitPane);
    }

    // implements IMessageEditorController

    @Override
    public IHttpService getHttpService() {
        return this.currentHttp.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return this.currentHttp.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return this.currentHttp.getResponse();
    }

    // extends AbstractTableModel

    @Override
    public int getRowCount() {
        return this.tasks.size();
    }

    @Override
    public int getColumnCount() {
        return 8;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        TableData data = ScannerUi.this.tasks.get(rowIndex);
        switch (columnIndex) {
            case 0: return data.id;
            case 1: return data.checkMethod;
            case 2: return data.requestMethod;
            case 3: return data.url;
            case 4: return data.status_code;
            case 5: return data.issue;
            case 6: return data.startTime;
            case 7: return data.endTime;
        }
        return null;
    }

    @Override
    public String getColumnName(int column) {
        switch (column) {
            case 0: return "#";
            case 1: return "checkMethod";
            case 2: return "requestMethod";
            case 3: return "url";
            case 4: return "status_code";
            case 5: return "issue";
            case 6: return "startTime";
            case 7: return "endTime";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }


    /**
     * 新增任务至任务栏面板
     *
     * @param extensionMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return int id
     */
    public int add(String extensionMethod, String requestMethod, String url,
                   String statusCode, String issue, IHttpRequestResponse requestResponse) {
        synchronized (this.tasks) {
            Date date = new Date();
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
            String startTime = sdf.format(date);

            int id = this.tasks.size();
            this.tasks.add(
                    new TableData(
                            id,
                            url,
                            statusCode,
                            requestMethod,
                            extensionMethod,
                            issue,
                            startTime,
                            "",
                            requestResponse
                    )
            );
            fireTableRowsInserted(id, id);
            return id;
        }
    }

    /**
     * 更新任务状态至任务栏面板
     *
     * @param id
     * @param extensionMethod
     * @param requestMethod
     * @param url
     * @param statusCode
     * @param issue
     * @param requestResponse
     * @return int id
     */
    public int save(int id, String extensionMethod, String requestMethod,
                    String url, String statusCode, String issue,
                    IHttpRequestResponse requestResponse) {
        TableData dataEntry = ScannerUi.this.tasks.get(id);
        String startTime = dataEntry.startTime;

        Date d = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        String endTime = sdf.format(d);

        synchronized (this.tasks) {
            this.tasks.set(
                    id,
                    new TableData(
                            id,
                            url,
                            statusCode,
                            requestMethod,
                            extensionMethod,
                            issue,
                            startTime,
                            endTime,
                            requestResponse
                    )
            );
            fireTableRowsUpdated(id, id);
            return id;
        }
    }


    /**
     * 自定义 JTable 子类，完成响应点击cell显示请求/响应包
     */
    private class Table extends JTable {

        public Table(TableModel dm) {
            super(dm);
        }

        @Override
        public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
            // JTable的autoCreateRowSorter为true，则自动实现了排序功能，
            // https://blog.csdn.net/liangjiemin11/article/details/14209361
            TableData data = ScannerUi.this.tasks.get(convertRowIndexToModel(rowIndex));
            ScannerUi.this.messageRequest.setMessage(data.iHttpRequestResponse.getRequest(), true);
            ScannerUi.this.messageResponse.setMessage(data.iHttpRequestResponse.getResponse(), false);
            ScannerUi.this.currentHttp = data.iHttpRequestResponse;
            super.changeSelection(rowIndex, columnIndex, toggle, extend);
        }
    }

    /**
     * 数据包展示类
     */
    private static class TableData {
        final int id;
        final String url;
        final String status_code;
        final String requestMethod;
        final String checkMethod;
        final String issue;
        final String startTime;
        final String endTime;
        final IHttpRequestResponse iHttpRequestResponse;

        public TableData(int id, String url, String status_code, String method, String checkMethod, String issue, String startTime, String endTime, IHttpRequestResponse iHttpRequestResponse) {
            this.id = id;
            this.url = url;
            this.status_code = status_code;
            this.requestMethod = method;
            this.checkMethod = checkMethod;
            this.issue = issue;
            this.startTime = startTime;
            this.endTime = endTime;
            this.iHttpRequestResponse = iHttpRequestResponse;
        }
    }

}
