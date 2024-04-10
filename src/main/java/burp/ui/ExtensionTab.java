//package burp.ui;
//
//import burp.*;
//import burp.ui.renderer.HavingImportantRenderer;
//import burp.ui.renderer.IsJsFindUrlRenderer;
//import burp.util.Constants;
//
//import javax.swing.*;
//import javax.swing.border.EmptyBorder;
//import javax.swing.table.AbstractTableModel;
//import javax.swing.table.DefaultTableCellRenderer;
//import javax.swing.table.DefaultTableModel;
//import javax.swing.table.TableModel;
//import java.awt.*;
//import java.util.ArrayList;
//import java.util.List;
//import java.util.Iterator;
//
//public class ExtensionTab extends JPanel implements IMessageEditorController {
//    private String tagName;
//    private JSplitPane mainSplitPane;
//    private IMessageEditor requestTextEditor;
//    private IMessageEditor responseTextEditor;
//    private IHttpRequestResponse currentlyDisplayedItem;
//    private JScrollPane upScrollPane;
//    private ConfigPanel configPanel;
//    public static ITextEditor resultDeViewer;
//    public static DefaultTableModel model;
//    public static JTable table;
//
//    public ExtensionTab(IBurpExtenderCallbacks callbacks, String name) {
//        // 主分隔面板
//        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
//        setLayout(new BorderLayout());
//        tagName = name;
//
//        JPanel toolbar = new JPanel();
//        toolbar.setLayout(new BorderLayout());
//
//        // 首行配置面板
//        configPanel = new ConfigPanel();
//
//        // 数据展示面板
//        model = new DefaultTableModel(new Object[]{"#", "ID", "URl", "PATH Number", "Method", "status", "isJsFindUrl", "HavingImportant", "Result", "Time"}, 0) {
//
//        };
//        table = new JTable(model);
//        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
//        upScrollPane = new JScrollPane(table);
//        // 将upScrollPane作为mainSplitPane的上半部分
//        mainSplitPane.setTopComponent(upScrollPane);
//
//        // 前两列设置宽度 30px、60px
//        table.getColumnModel().getColumn(0).setMaxWidth(30);
//        table.getColumnModel().getColumn(1).setMaxWidth(60);
//        table.getColumnModel().getColumn(2).setMinWidth(400);
//
//        // 创建一个居中对齐的单元格渲染器
//        DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
//        centerRenderer.setHorizontalAlignment(JLabel.CENTER);
//
//        DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
//        leftRenderer.setHorizontalAlignment(JLabel.LEFT);
//
//        table.getColumnModel().getColumn(0).setCellRenderer(leftRenderer);
//        table.getColumnModel().getColumn(1).setCellRenderer(leftRenderer);
//        table.getColumnModel().getColumn(2).setCellRenderer(leftRenderer);
//        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
//        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
//        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
//        table.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
//        table.getColumnModel().getColumn(7).setCellRenderer(leftRenderer);
//        table.getColumnModel().getColumn(8).setCellRenderer(leftRenderer);
//
//        IsJsFindUrlRenderer isJsFindUrlRenderer = new IsJsFindUrlRenderer();
//        table.getColumnModel().getColumn(6).setCellRenderer(isJsFindUrlRenderer);
//        HavingImportantRenderer havingImportantRenderer = new HavingImportantRenderer();
//        table.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);
//
////        table.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
////            @Override
////            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
////                final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
////                if (isSelected) {
////                    c.setBackground(Color.decode(Constants.TAB_COLOR_SELECTED));
////                } else {
////                    ExtensionTab apiTable = (ExtensionTab) table.getModel();
////                    ApiTableData apiTableData = apiTable.getApiTable().getTableData().get(row);
////                    if (apiTableData.isSubData) {
////                        c.setBackground(Color.decode(Constants.TAB_COLOR_SUB_DATA));
////                    } else {
////                        c.setBackground(Color.decode(Constants.TAB_COLOR_MAIN_DATA));
////                    }
////                }
////                return c;
////            }
////        });
//
//        BurpExtender.getStdout().println("2");
//        // 请求的面板
//        requestTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);
//
//        // 响应的面板
//        responseTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);
//
//        // 详细结果面板
//        resultDeViewer = BurpExtender.getCallbacks().createTextEditor();
//
//        toolbar.add(configPanel, BorderLayout.NORTH);
//        toolbar.add(mainSplitPane, BorderLayout.CENTER);
//        add(toolbar, BorderLayout.NORTH);
//        JTabbedPane tabs = new JTabbedPane();
//        tabs.addTab("Original Response", responseTextEditor.getComponent());
//        tabs.addTab("Result Info", resultDeViewer.getComponent());
//        tabs.addTab("Request", requestTextEditor.getComponent());
//        mainSplitPane.setBottomComponent(tabs);
//
//    }
//
//    @Override
//    public byte[] getRequest() {
//        return currentlyDisplayedItem.getRequest();
//    }
//
//    @Override
//    public byte[] getResponse() {
//        return currentlyDisplayedItem.getResponse();
//    }
//
//    @Override
//    public IHttpService getHttpService() {
//        return currentlyDisplayedItem.getHttpService();
//    }
//
//    /**
//     * 新增数据到table中
//     */
//    public void add(ApiDocumentListTree apiDocumentListTree) {
//
//    }
//
//
//
//    /**
//     * 界面显示数据存储模块
//     */
//    public static class ApiTableData {
//        final String id;
//        final String url;
//        final String uriNumber;
//        final Boolean havingImportant;
//        final String result ;
//        final IHttpRequestResponse requestResponse;
//        final String time;
//        final Boolean isSubData;
//        final ApiDocumentListTree parentListTree;
//        private String treeStatus = "";
//        final String status;
//        final String isJsFindUrl;
//        final String method;
//
//        public ApiTableData(Boolean isSubData, ApiDocumentListTree parentListTree, String id, String url, String uriNumber, Boolean havingImportant, String result, IHttpRequestResponse requestResponse, String time, String status, String isJsFindUrl, String method) {
//            this.isSubData = isSubData;
//            this.parentListTree = parentListTree;
//            this.id = id;
//            this.url = url;
//            this.uriNumber = uriNumber;
//            this.havingImportant = havingImportant;
//            this.result = result;
//            this.requestResponse = requestResponse;
//            this.time = time;
//            this.status = status;
//            this.isJsFindUrl = isJsFindUrl;
//            this.method = method;
//        }
//
//        public void setTreeStatus(String treeStatus) {
//            this.treeStatus = treeStatus;
//        }
//    }
//
//    /**
//     * 自定义Table
//     */
//    public class ApiTable extends JTable {
//        private final List<ApiTableData> tableData = new ArrayList<ApiTableData>();
//
//        public ApiTable(TableModel tableModel) {
//            super(tableModel);
//        }
//
//        public List<ApiTableData> getTableData() {
//            return this.tableData;
//        }
//
//
//        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
//            ApiTableData dataEntry = this.tableData.get(convertRowIndexToModel(row));
//
//            if (!dataEntry.isSubData) { // 切换状态
//                if (dataEntry.parentListTree.getExpandStatus()) {
//                    dataEntry.parentListTree.collapse();
//                } else {
//                    dataEntry.parentListTree.expand();
//                }
//            }
//
//            requestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
//            responseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
//            currentlyDisplayedItem = dataEntry.requestResponse;
//            super.changeSelection(row, col, toggle, extend);
//        }
//    }
//}
