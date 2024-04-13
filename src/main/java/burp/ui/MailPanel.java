package burp.ui;

import burp.*;
import burp.ui.datmodel.ApiDataModel;
import burp.ui.renderer.HavingImportantRenderer;
import burp.ui.renderer.IsJsFindUrlRenderer;
import burp.util.Constants;
import burp.util.Utils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.*;
import java.util.List;

public class MailPanel extends JPanel implements IMessageEditorController {
    private String tagName;
    private JSplitPane mainSplitPane;
    private static IMessageEditor requestTextEditor;
    private static IMessageEditor responseTextEditor;
    private static IHttpRequestResponse currentlyDisplayedItem;
    private JScrollPane upScrollPane;
    private ConfigPanel configPanel;
    public static ITextEditor resultDeViewer;
    private static DefaultTableModel model;
    public static JTable table;
    public static int selectRow = 0;

    public static String historySearchText = "";
    public static String historySearchType = null;

    public MailPanel(IBurpExtenderCallbacks callbacks, String name) {
        // 主分隔面板
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
        setLayout(new BorderLayout());
        tagName = name;

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BorderLayout());

        // 首行配置面板
        configPanel = new ConfigPanel();

        // 数据展示面板
        model = new DefaultTableModel(new Object[]{"#", "ID", "URl", "PATH Number", "Method", "status", "isJsFindUrl", "HavingImportant", "Result", "Time"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // This will make all cells of the table non-editable
                return false;
            }
        };
        table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        upScrollPane = new JScrollPane(table);
        // 将upScrollPane作为mainSplitPane的上半部分
        mainSplitPane.setTopComponent(upScrollPane);

        // 前两列设置宽度 30px、60px
        table.getColumnModel().getColumn(0).setMaxWidth(30);
        table.getColumnModel().getColumn(1).setMaxWidth(60);
        table.getColumnModel().getColumn(2).setMinWidth(400);
        table.getColumnModel().getColumn(7).setMinWidth(60);
        table.getColumnModel().getColumn(8).setMinWidth(150);
        table.getColumnModel().getColumn(9).setMinWidth(100);

        // 创建一个居中对齐的单元格渲染器
        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
        centerRenderer.setHorizontalAlignment(JLabel.CENTER);

        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
        leftRenderer.setHorizontalAlignment(JLabel.LEFT);

        table.getColumnModel().getColumn(0).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(1).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(2).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(7).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(8).setCellRenderer(leftRenderer);

        IsJsFindUrlRenderer isJsFindUrlRenderer = new IsJsFindUrlRenderer();
        table.getColumnModel().getColumn(6).setCellRenderer(isJsFindUrlRenderer);
        HavingImportantRenderer havingImportantRenderer = new HavingImportantRenderer();
        table.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        synchronized (getModel()){
                            int row = table.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                selectRow = row;
                                String listStatus = (String)table.getModel().getValueAt(row, 0);
                                String url;
                                if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)){
                                    url = (String)table.getModel().getValueAt(row, 2);
                                    ApiDataModel apiDataModel = IProxyScanner.apiDataModelMap.get(url);
                                    requestTextEditor.setMessage(apiDataModel.getRequestResponse().getRequest(), true);
                                    responseTextEditor.setMessage(apiDataModel.getRequestResponse().getResponse(), false);
                                    currentlyDisplayedItem = apiDataModel.getRequestResponse();
                                    if (apiDataModel.getListStatus().equals(Constants.TREE_STATUS_COLLAPSE)){
                                        apiDataModel.setListStatus(Constants.TREE_STATUS_EXPAND);
                                        modelExpand(apiDataModel, row);
                                    } else if (apiDataModel.getListStatus().equals(Constants.TREE_STATUS_EXPAND)) {
                                        apiDataModel.setListStatus(Constants.TREE_STATUS_COLLAPSE);
                                        modeCollapse(apiDataModel, row);
                                    }
                                }else{
                                    String path = (String)table.getModel().getValueAt(row, 2);
                                    url = findUrlFromPath(row);
                                    ApiDataModel apiDataModel = IProxyScanner.apiDataModelMap.get(url);
                                    Map<String, Object> pathData = apiDataModel.getPathData();
                                    Map<String, Object> matchPathData = (Map<String, Object>)pathData.get(path);
                                    requestTextEditor.setMessage(((IHttpRequestResponse)matchPathData.get("responseRequest")).getRequest(), true);
                                    responseTextEditor.setMessage(((IHttpRequestResponse)matchPathData.get("responseRequest")).getResponse(), false);
                                    currentlyDisplayedItem = ((IHttpRequestResponse)matchPathData.get("responseRequest"));
                                }

                            }
                        }
                    }
                });

            }
        });

        // 请求的面板
        requestTextEditor = callbacks.createMessageEditor(this, false);

        // 响应的面板
        responseTextEditor = callbacks.createMessageEditor(this, false);

        // 详细结果面板
        resultDeViewer = BurpExtender.getCallbacks().createTextEditor();

        toolbar.add(configPanel, BorderLayout.NORTH);
        toolbar.add(mainSplitPane, BorderLayout.CENTER);
        add(toolbar, BorderLayout.NORTH);
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Original Response", responseTextEditor.getComponent());
        tabs.addTab("Result Info", resultDeViewer.getComponent());
        tabs.addTab("Request", requestTextEditor.getComponent());
        mainSplitPane.setBottomComponent(tabs);

    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem.getResponse();
    }

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem.getHttpService();
    }

    public void addApiData(ApiDataModel apiDataModel) {
        if (!historySearchText.isEmpty() && apiDataModel.getUrl().toLowerCase().contains(historySearchText.toLowerCase())) {
            model.insertRow(0, new Object[]{
                    Constants.TREE_STATUS_COLLAPSE,
                    apiDataModel.getId(),
                    apiDataModel.getUrl(),
                    apiDataModel.getPATHNumber(),
                    apiDataModel.getMethod(),
                    apiDataModel.getStatus(),
                    apiDataModel.getIsJsFindUrl(),
                    apiDataModel.getHavingImportant(),
                    apiDataModel.getResult(),
                    apiDataModel.getTime()
            });
        } else if (historySearchText.isEmpty()) {
            model.insertRow(0, new Object[]{
                    Constants.TREE_STATUS_COLLAPSE,
                    apiDataModel.getId(),
                    apiDataModel.getUrl(),
                    apiDataModel.getPATHNumber(),
                    apiDataModel.getMethod(),
                    apiDataModel.getStatus(),
                    apiDataModel.getIsJsFindUrl(),
                    apiDataModel.getHavingImportant(),
                    apiDataModel.getResult(),
                    apiDataModel.getTime()
            });

        }
        if (selectRow == 0) {
            table.setRowSelectionInterval(0, 0);
            requestTextEditor.setMessage(apiDataModel.getRequestResponse().getRequest(), true);
            responseTextEditor.setMessage(apiDataModel.getRequestResponse().getResponse(), false);
            currentlyDisplayedItem = apiDataModel.getRequestResponse();
        }
    }


    public void editApiData(ApiDataModel apiDataModel) {

        ApiDataModel originalApiData = IProxyScanner.apiDataModelMap.get(Utils.getUriFromUrl(apiDataModel.getUrl()));
        if (!historySearchText.isEmpty() && apiDataModel.getUrl().toLowerCase().contains(historySearchText.toLowerCase())) {
            int index = findRowIndexByURL(originalApiData.getUrl());
            if (model.getValueAt(index, 0).equals(Constants.TREE_STATUS_EXPAND)) {
                modeCollapse(apiDataModel, index);
            }
            model.removeRow(index);
            model.insertRow(0, new Object[]{
                    Constants.TREE_STATUS_COLLAPSE,
                    apiDataModel.getId(),
                    apiDataModel.getUrl(),
                    apiDataModel.getPATHNumber(),
                    apiDataModel.getMethod(),
                    apiDataModel.getStatus(),
                    apiDataModel.getIsJsFindUrl(),
                    apiDataModel.getHavingImportant(),
                    apiDataModel.getResult(),
                    apiDataModel.getTime()
            });
        } else if (historySearchText.isEmpty()) {
            int index = findRowIndexByURL(originalApiData.getUrl());
            if (model.getValueAt(index, 0).equals(Constants.TREE_STATUS_EXPAND)) {
                modeCollapse(apiDataModel, index);
            }
            model.removeRow(index);
            model.insertRow(0, new Object[]{
                    Constants.TREE_STATUS_COLLAPSE,
                    apiDataModel.getId(),
                    apiDataModel.getUrl(),
                    apiDataModel.getPATHNumber(),
                    apiDataModel.getMethod(),
                    apiDataModel.getStatus(),
                    apiDataModel.getIsJsFindUrl(),
                    apiDataModel.getHavingImportant(),
                    apiDataModel.getResult(),
                    apiDataModel.getTime()
            });
        }
    }


    public static void searchAndSelectRowByURL(String searchText){
        // 清空model后，根据URL来做匹配
        model.setRowCount(0);

        // 记录当前检索内容
        historySearchText = searchText;

        // 遍历apiDataModelMap
        for (Map.Entry<String, ApiDataModel> entry : IProxyScanner.apiDataModelMap.entrySet()) {
            String url = entry.getKey();
            ApiDataModel apiDataModel = entry.getValue();
            if (url.toLowerCase().contains(searchText.toLowerCase())) {
                model.insertRow(0, new Object[]{
                        Constants.TREE_STATUS_COLLAPSE,
                        apiDataModel.getId(),
                        apiDataModel.getUrl(),
                        apiDataModel.getPATHNumber(),
                        apiDataModel.getMethod(),
                        apiDataModel.getStatus(),
                        apiDataModel.getIsJsFindUrl(),
                        apiDataModel.getHavingImportant(),
                        apiDataModel.getResult(),
                        apiDataModel.getTime()
                });
            }
        }
    }

    public static void showFilter(String selectOption){
        synchronized (model) {
            // 清空model后，根据URL来做匹配
            model.setRowCount(0);

            // 遍历apiDataModelMap
            for (Map.Entry<String, ApiDataModel> entry : IProxyScanner.apiDataModelMap.entrySet()) {
                ApiDataModel apiDataModel = entry.getValue();
                boolean notMatch = false;
                switch (selectOption) {
                    case "只看status为200":
                        if (!apiDataModel.getStatus().contains("200")){
                            notMatch = true;
                            break;
                        };
                    case "只看重点":
                        if (!apiDataModel.getHavingImportant()) {
                            notMatch = true;
                            break;
                        }
                    case "只看铭感内容":
                        if (!apiDataModel.getResult().contains("铭感内容")) {
                            notMatch = true;
                            break;
                        }
                    case "只看铭感路径":
                        if (!apiDataModel.getResult().contains("铭感路径")) {
                            notMatch = true;
                            break;
                        }
                }
                if (notMatch){
                    break;
                }
                model.insertRow(0, new Object[]{
                        Constants.TREE_STATUS_COLLAPSE,
                        apiDataModel.getId(),
                        apiDataModel.getUrl(),
                        apiDataModel.getPATHNumber(),
                        apiDataModel.getMethod(),
                        apiDataModel.getStatus(),
                        apiDataModel.getIsJsFindUrl(),
                        apiDataModel.getHavingImportant(),
                        apiDataModel.getResult(),
                        apiDataModel.getTime()
                });
            }
        }
    }

    public static void showAllRows(){
        synchronized (model) {
            // 清空model后，根据URL来做匹配
            model.setRowCount(0);

            // 清空检索内容
            historySearchText = "";

            // 遍历apiDataModelMap
            for (Map.Entry<String, ApiDataModel> entry : IProxyScanner.apiDataModelMap.entrySet()) {
                ApiDataModel apiDataModel = entry.getValue();
                model.insertRow(0, new Object[]{
                        Constants.TREE_STATUS_COLLAPSE,
                        apiDataModel.getId(),
                        apiDataModel.getUrl(),
                        apiDataModel.getPATHNumber(),
                        apiDataModel.getMethod(),
                        apiDataModel.getStatus(),
                        apiDataModel.getIsJsFindUrl(),
                        apiDataModel.getHavingImportant(),
                        apiDataModel.getResult(),
                        apiDataModel.getTime()
                });
            }
        }
    }

    public static void clearAllData(){
        synchronized (model) {
            // 清空model
            model.setRowCount(0);
            // 清空表格
            IProxyScanner.apiDataModelMap = new HashMap<String, ApiDataModel>();
            // 清空检索
            historySearchText = "";
            SwingUtilities.invokeLater(new Runnable() {
                public void run() {
                    ConfigPanel.searchField.setText("");
                }
            });

            // 还可以清空编辑器中的数据
            MailPanel.requestTextEditor.setMessage(new byte[0], true); // 清空请求编辑器
            MailPanel.responseTextEditor.setMessage(new byte[0], false); // 清空响应编辑器
            MailPanel.currentlyDisplayedItem = null; // 清空当前显示的项
        }
    }

    public void modelExpand(ApiDataModel apiDataModel, int index) {
        // 看当前是否有过滤场景
        String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();


        model.setValueAt(Constants.TREE_STATUS_EXPAND, index, 0);

        Map<String, Object> pathData = apiDataModel.getPathData();

        int tmpIndex = 0;
        for (Map.Entry<String, Object> pathEntry : pathData.entrySet()) {
            Map<String, Object> subPathValue = (Map<String, Object>)pathEntry.getValue();
            boolean notMatch = false;
            switch (selectedOption) {
                case "只看status为200":
                    if (!((String)subPathValue.get("status")).contains("200")){
                        notMatch = true;
                        break;
                    };
                case "只看重点":
                    if (!(Boolean) subPathValue.get("havingImportant")) {
                        notMatch = true;
                        break;
                    }
                case "只看铭感内容":
                    if (!((String)subPathValue.get("result")).contains("铭感内容")) {
                        notMatch = true;
                        break;
                    }
                case "只看铭感路径":
                    if (!((String)subPathValue.get("result")).contains("铭感路径")) {
                        notMatch = true;
                        break;
                    }
            }
            if (notMatch){
                break;
            }
            tmpIndex += 1;
            String listStatus;

            if (tmpIndex != pathData.size() && pathData.size() != 1) {
                listStatus = "┠";
            } else if (pathData.size() == 1) {
                listStatus = "┗";
            } else {
                listStatus = "┗";
            }
            model.insertRow(index+tmpIndex, new Object[]{
                    listStatus,
                    "-",
                    pathEntry.getKey(),
                    "-",
                    subPathValue.get("method"),
                    subPathValue.get("status"),
                    subPathValue.get("isJsFindUrl"),
                    subPathValue.get("isImportant"),
                    subPathValue.get("result"),
                    subPathValue.get("time")
            });
            model.fireTableRowsInserted(index+tmpIndex, index+tmpIndex);
        }
        // 通知监听器，从selfIndex + 1 到 selfIndex + subApiData.size()的行已经被插入
        model.fireTableRowsInserted(index + 1, index + pathData.size());

    }

    public void modeCollapse(ApiDataModel apiDataModel, int index) {
        // 看当前是否有过滤场景
        String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
        model.setValueAt(Constants.TREE_STATUS_COLLAPSE, index, 0);

        Map<String, Object> pathData = apiDataModel.getPathData();
        // 计算即将删除的行区间
        int startDeleteIndex = index + 1;
        int deleteNumber = 0;

        // 从后向前删除子项，这样索引就不会因为列表的变动而改变
        int numberOfRows = model.getRowCount();
        for (int i = 0; i < numberOfRows; i++) {
            try {
                if (!model.getValueAt(startDeleteIndex, 0).equals(Constants.TREE_STATUS_EXPAND) && !model.getValueAt(startDeleteIndex, 0).equals(Constants.TREE_STATUS_COLLAPSE)) {
                    model.removeRow(startDeleteIndex);
                    deleteNumber += 1;
                } else {
                    break;
                }} catch (Exception e) {
                    // 捕获其他所有类型的异常
                    BurpExtender.getStdout().println("Exception caught: " + e.getMessage());
                }
        }

        // 现在所有的子项都被删除了，通知表格模型更新
        // 注意这里的索引是根据删除前的状态传递的
        model.fireTableRowsDeleted(startDeleteIndex, index+deleteNumber);
    }

    public int findRowIndexByURL(String url) {
        for (int i = 0; i < model.getRowCount(); i++) {
            // 获取每一行第二列的值
            Object value = model.getValueAt(i, 2);
            // 检查这个值是否与要查找的URL匹配
            if (value != null && value.equals(url)) {
                // 如果匹配，返回当前行的索引
                return i;
            }
        }
        // 如果没有找到，返回-1表示未找到
        return -1;
    }

    public String findUrlFromPath(int row){
        for (int index = row; index >= 0; index--) {
            // 获取每一行第二列的值
            String value = (String)model.getValueAt(index, 0);
            if (value.equals(Constants.TREE_STATUS_EXPAND) || value.equals((Constants.TREE_STATUS_COLLAPSE))){
                return (String)model.getValueAt(index, 2);
            }
        }
        return null;
    }

    public DefaultTableModel getModel(){
        return model;
    }

}
