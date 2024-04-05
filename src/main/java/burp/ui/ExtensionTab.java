package burp.ui;

import burp.*;
import burp.util.Constants;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableModel;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;

public class ExtensionTab extends AbstractTableModel implements ITab, IMessageEditorController {
    private final String tagName;
    public static JPanel contentPane;
    private JSplitPane mainSplitPane;
    private IMessageEditor requestTextEditor;
    private IMessageEditor responseTextEditor;
    private IHttpRequestResponse currentlyDisplayedItem;
    private JScrollPane upScrollPane;
    private ConfigPanel configPanel;
    public static ITextEditor resultDeViewer;

    private ApiTable apiTable;

    public ExtensionTab(String name) {
        IBurpExtenderCallbacks callbacks = BurpExtender.getCallbacks();

        this.tagName = name;

        // 创建用户界面
        SwingUtilities.invokeLater(new Runnable() {
            @Override
            public void run() {
                // 主分隔面板
                mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

                // 配置面板
                configPanel = new ConfigPanel();

                // 任务栏面板
                apiTable = new ApiTable(ExtensionTab.this);
                upScrollPane = new JScrollPane(apiTable);

                // 将upScrollPane作为mainSplitPane的上半部分
                mainSplitPane.setTopComponent(upScrollPane);

                // 前两列设置宽度 30px、60px
                apiTable.getColumnModel().getColumn(0).setMaxWidth(30);
                apiTable.getColumnModel().getColumn(1).setMaxWidth(60);

                // 创建一个居中对齐的单元格渲染器
                DefaultTableCellRenderer centerRenderer = new DefaultTableCellRenderer();
                centerRenderer.setHorizontalAlignment(JLabel.CENTER);

                DefaultTableCellRenderer leftRenderer = new DefaultTableCellRenderer();
                leftRenderer.setHorizontalAlignment(JLabel.LEFT);

                apiTable.getColumnModel().getColumn(0).setCellRenderer(leftRenderer);
                apiTable.getColumnModel().getColumn(1).setCellRenderer(leftRenderer);
                apiTable.getColumnModel().getColumn(2).setCellRenderer(leftRenderer);
                apiTable.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
                apiTable.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
                apiTable.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
                apiTable.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
                apiTable.getColumnModel().getColumn(7).setCellRenderer(leftRenderer);
                apiTable.getColumnModel().getColumn(8).setCellRenderer(leftRenderer);


                apiTable.setDefaultRenderer(Object.class, new DefaultTableCellRenderer() {
                    @Override
                    public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                        final Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                        if (isSelected) {
                            c.setBackground(Color.decode(Constants.TAB_COLOR_SELECTED));
                        } else {
                            ExtensionTab apiTable = (ExtensionTab) table.getModel();
                            ApiTableData apiTableData = apiTable.getApiTable().getTableData().get(row);
                            if (apiTableData.isSubData) {
                                c.setBackground(Color.decode(Constants.TAB_COLOR_SUB_DATA));
                            } else {
                                c.setBackground(Color.decode(Constants.TAB_COLOR_MAIN_DATA));
                            }
                        }
                        return c;
                    }
                });


                // 请求的面板
                requestTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);

                // 响应的面板
                responseTextEditor = callbacks.createMessageEditor(ExtensionTab.this, false);

                // 详细结果面板
                resultDeViewer = BurpExtender.getCallbacks().createTextEditor();

                // 整体布局
                contentPane = new JPanel();
                contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
                contentPane.setLayout(new BorderLayout(0, 0));

                contentPane.add(configPanel, BorderLayout.NORTH);
                contentPane.add(mainSplitPane, BorderLayout.CENTER);

                JTabbedPane tabs = new JTabbedPane();
                tabs.addTab("Result Info", resultDeViewer.getComponent());
                tabs.addTab("Request", requestTextEditor.getComponent());
                tabs.addTab("Original Response", responseTextEditor.getComponent());
                mainSplitPane.setBottomComponent(tabs);

                callbacks.customizeUiComponent(contentPane);

                // 将自定义选项卡添加到Burp的UI
                callbacks.addSuiteTab(ExtensionTab.this);
            }
        });
    }

    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    @Override
    public Component getUiComponent() {
        return contentPane;
    }

    @Override
    public int getRowCount() {
        return this.getApiTable().getTableData().size();
    }

    @Override
    public int getColumnCount() {
        return 9;
    }

    @Override
    public String getColumnName(int columnIndex) {
        switch (columnIndex) {
            case 0:
                return " ";
            case 1:
                return "ID";
            case 2:
                return "URL";
            case 3:
                return "method";
            case 4:
                return "URI Number";
            case 5:
                return "isJsFindUrl";
            case 6:
                return "HavingImportant";
            case 7:
                return "Result";
            case 8:
                return "Time";
        }
        return null;
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return String.class;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        if (this.getApiTable().getTableData().isEmpty()){
            return null;
        }
        ApiTableData data = this.getApiTable().getTableData().get(rowIndex);
        switch (columnIndex) {
            case 0:
                return data.treeStatus;
            case 1:
                return data.id;
            case 2:
                return data.url;
            case 3:
                return data.method;
            case 4:
                return data.uriNumber;
            case 5:
                return data.isJsFindUrl;
            case 6:
                return data.havingImportant;
            case 7:
                return data.result;
            case 8:
                return data.time;
        }
        return null;
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

    /**
     * 新增任务至任务栏面板
     */
    public void add(ApiDocumentListTree apiDocumentListTree) {

            this.apiTable.getTableData().add(apiDocumentListTree.getMainApiData());
            int _id = this.apiTable.getTableData().size();
            fireTableRowsInserted(_id, _id);
    }

    // 清空列表中的数据
    public void clearTableData() {
            int size = this.apiTable.getTableData().size();
            this.apiTable.getTableData().clear();
            if (size > 0) {
                fireTableRowsDeleted(0, size - 1);

        }
    }

    public ApiTable getApiTable() {
        return this.apiTable;
    }

    /**
     * 界面显示数据存储模块
     */
    public static class ApiTableData {
        final String id;
        final String url;
        final String uriNumber;
        final Boolean havingImportant;
        final String result ;
        final IHttpRequestResponse requestResponse;
        final String time;
        final Boolean isSubData;
        final ApiDocumentListTree parentListTree;
        private String treeStatus = "";
        final String status;
        final Boolean isJsFindUrl;
        final String method;

        public ApiTableData(Boolean isSubData, ApiDocumentListTree parentListTree, String id, String url, String uriNumber, Boolean havingImportant, String result, IHttpRequestResponse requestResponse, String time, String status, Boolean isJsFindUrl, String method) {
            this.isSubData = isSubData;
            this.parentListTree = parentListTree;
            this.id = id;
            this.url = url;
            this.uriNumber = uriNumber;
            this.havingImportant = havingImportant;
            this.result = result;
            this.requestResponse = requestResponse;
            this.time = time;
            this.status = status;
            this.isJsFindUrl = isJsFindUrl;
            this.method = method;
        }

        public void setTreeStatus(String treeStatus) {
            this.treeStatus = treeStatus;
        }
    }

    /**
     * 自定义Table
     */
    public class ApiTable extends JTable {
        private final List<ApiTableData> tableData = new ArrayList<ApiTableData>();

        public ApiTable(TableModel tableModel) {
            super(tableModel);
        }

        public List<ApiTableData> getTableData() {
            return this.tableData;
        }


        public void changeSelection(int row, int col, boolean toggle, boolean extend) {
            ApiTableData dataEntry = ApiTable.this.tableData.get(convertRowIndexToModel(row));

            if (!dataEntry.isSubData) { // 切换状态
                if (dataEntry.parentListTree.getExpandStatus()) {
                    dataEntry.parentListTree.collapse();
                } else {
                    dataEntry.parentListTree.expand();
                }
            }

            requestTextEditor.setMessage(dataEntry.requestResponse.getRequest(), true);
            responseTextEditor.setMessage(dataEntry.requestResponse.getResponse(), false);
            currentlyDisplayedItem = dataEntry.requestResponse;
            super.changeSelection(row, col, toggle, extend);
        }
    }
}
