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
import java.util.ArrayList;
import java.util.List;
import java.util.Iterator;
import java.util.Map;

public class MailPanel extends JPanel implements IMessageEditorController {
    private String tagName;
    private JSplitPane mainSplitPane;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private JScrollPane upScrollPane;
    private ConfigPanel configPanel;
    public static ITextEditor resultDeViewer;
    public static DefaultTableModel model;
    public static JTable table;
    public static int selectRow = 0;

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
                synchronized (table){
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
        if (selectRow == 0){
            table.setRowSelectionInterval(0, 0);
            requestTextEditor.setMessage(apiDataModel.getRequestResponse().getRequest(), true);
            responseTextEditor.setMessage(apiDataModel.getRequestResponse().getResponse(), false);
            currentlyDisplayedItem = apiDataModel.getRequestResponse();
        }
    }


    public void editApiData(ApiDataModel apiDataModel) {
        ApiDataModel originalApiData = IProxyScanner.apiDataModelMap.get(Utils.getUriFromUrl(apiDataModel.getUrl()));
        int index = findRowIndexByURL(originalApiData.getUrl());
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

    public void modelExpand(ApiDataModel apiDataModel, int index) {
        model.setValueAt(Constants.TREE_STATUS_EXPAND, index, 0);

        Map<String, Object> pathData = apiDataModel.getPathData();

        int tmpIndex = 0;
        for (Map.Entry<String, Object> pathEntry : pathData.entrySet()) {
            Map<String, Object> subPathValue = (Map<String, Object>)pathEntry.getValue();
            tmpIndex += 1;
            String listStatus;

            if (tmpIndex != pathData.size() - 1 && pathData.size() != 1) {
                listStatus = "┠";
            } else if (pathData.size() == 1) {
                listStatus = "┗";
            } else {
                listStatus = "┗";
            }
            model.insertRow(index+tmpIndex, new Object[]{
                    listStatus,
                    String.valueOf(tmpIndex),
                    pathEntry.getKey(),
                    "-",
                    subPathValue.get("method"),
                    subPathValue.get("status"),
                    subPathValue.get("isJsFindUrl"),
                    "-",
                    "-",
                    subPathValue.get("time")
            });
            model.fireTableRowsInserted(index+tmpIndex, index+tmpIndex);
        }
        // 通知监听器，从selfIndex + 1 到 selfIndex + subApiData.size()的行已经被插入
        model.fireTableRowsInserted(index + 1, index + pathData.size());
    }

    public void modeCollapse(ApiDataModel apiDataModel, int index) {
        model.setValueAt(Constants.TREE_STATUS_COLLAPSE, index, 0);

        Map<String, Object> pathData = apiDataModel.getPathData();
        // 计算即将删除的行区间
        int startDeleteIndex = index + 1;
        int endDeleteIndex = index + pathData.size();

        // 从后向前删除子项，这样索引就不会因为列表的变动而改变
        for (int i = pathData.size() - 1; i >= 0; i--) {
            model.removeRow(startDeleteIndex);
        }

        // 现在所有的子项都被删除了，通知表格模型更新
        // 注意这里的索引是根据删除前的状态传递的
        model.fireTableRowsDeleted(startDeleteIndex, endDeleteIndex - 1);
    }

    public int findRowIndexByURL(String url) {
        for (int i = 0; i < model.getRowCount(); i++) {
            // 获取每一行第二列的值
            Object value = model.getValueAt(i, 1);
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
}
