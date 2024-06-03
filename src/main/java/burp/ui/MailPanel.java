package burp.ui;

import burp.*;
import burp.dataModel.ApiDataModel;
import burp.ui.renderer.IconTableCellRenderer;
import burp.ui.renderer.IsJsFindUrlRenderer;
import burp.util.Constants;
import burp.util.UiUtils;
import burp.util.Utils;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.event.*;
import java.net.URL;
import java.util.*;
import javax.swing.Timer;
import java.util.ArrayList;
import java.util.List;
import java.time.Duration;
import java.time.LocalDateTime;
import javax.swing.SwingWorker;
import java.util.Map;
import java.util.concurrent.ExecutionException;

public class MailPanel implements IMessageEditorController {
    public static JPanel contentPane;
    private JSplitPane mainSplitPane;
    private static IMessageEditor requestTextEditor;
    private static IMessageEditor responseTextEditor;
    public static byte[] requestsData;
    public static byte[] responseData;
    public static IHttpService iHttpService;
    private JScrollPane upScrollPane;
    private ConfigPanel configPanel;
    public static JEditorPane resultTextPane = new JEditorPane("text/html", "");
    public static ITextEditor findUrlTEditor;
    public static JScrollPane scrollPane = new JScrollPane(resultTextPane);
    private static DefaultTableModel model;
    public static JTable table;
    public static int selectRow = 0;
    public static Timer timer;
    public static String historySearchText = "";
    public static String historySearchType = null;
    public static LocalDateTime operationStartTime = LocalDateTime.now();
    private final Icon deleteItemIcon = UiUtils.getImageIcon("/icon/deleteButton.png", 15, 15);
    private final Icon setUnImportantItemIcon = UiUtils.getImageIcon("/icon/setUnImportantItemIcon.png", 15, 15);
    private final Icon copyIcon = UiUtils.getImageIcon("/icon/copyIcon.png", 15, 15);
    private final Icon customizeIcon = UiUtils.getImageIcon("/icon/customizeIcon.png", 15, 15);
    private final Icon cookieIcon = UiUtils.getImageIcon("/icon/cookieIcon.png", 15, 15);
    private final Icon urlIcon = UiUtils.getImageIcon("/icon/urlIcon.png", 15, 15);
    public static JPanel getContentPane(){
        return contentPane;
    }

    public MailPanel(IBurpExtenderCallbacks callbacks, String name) {
        contentPane = new JPanel();
        contentPane.setBorder(new EmptyBorder(5, 5, 5, 5));
        contentPane.setLayout(new BorderLayout(0, 0));
        // 主分隔面板
        mainSplitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        // 首行配置面板
        configPanel = new ConfigPanel();

        // 数据展示面板
        model = new DefaultTableModel(new Object[]{"#", "ID", "URl", "PATH Number", "Method", "status", "isJsFindUrl", "HavingImportant", "Result", "describe", "Time"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                // This will make all cells of the table non-editable
                return false;
            }
        };
        table = new JTable(model){
            public String getToolTipText(MouseEvent e) {
                int row = rowAtPoint(e.getPoint());
                int col = columnAtPoint(e.getPoint());
                if (row > -1 && col > -1) {
                    Object value = getValueAt(row, col);
                    return value == null ? null : value.toString();
                }
                return super.getToolTipText(e);
            }
        };
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

        // 创建右键菜单
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem cookieItem = new JMenuItem("自定义凭证", cookieIcon);
        JMenuItem customizeItem = new JMenuItem("自定义父路径", customizeIcon);
        JMenuItem urlItem = new JMenuItem("提取url", urlIcon);
        JMenuItem copyItem = new JMenuItem("复制路径", copyIcon);
        JMenuItem setUnImportantItem = new JMenuItem("误报", setUnImportantItemIcon);
        JMenuItem deleteItem = new JMenuItem("删除", deleteItemIcon);
        popupMenu.add(cookieItem);
        popupMenu.add(customizeItem);
        popupMenu.add(urlItem);
        popupMenu.add(copyItem);
        popupMenu.add(deleteItem);
        popupMenu.add(setUnImportantItem);
        // 将右键菜单添加到表格
        table.setComponentPopupMenu(popupMenu);

        // 添加事件监听器到"自定义凭证"菜单项
        urlItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String listStatus = (String) table.getModel().getValueAt(selectedRow, 0);
                    String path = (String) table.getModel().getValueAt(selectedRow, 2);
                    try {
                        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
                            JOptionPane.showMessageDialog(table, "当前只支持对某一个具体路径进行url提取" , "提取url失败",  JOptionPane.INFORMATION_MESSAGE);
                        }else {
                            String url = findUrlFromPath(selectedRow);
                            Map<String, Object> matchPathData = BurpExtender.getDataBaseService().selectPathDataByUrlAndPath(url, path);
                            responseData = Base64.getDecoder().decode((String) matchPathData.get("response"));
                            // 针对html页面提取
                            Set<String> urlSet = new HashSet<>(Utils.extractUrlsFromHtmlNotFilter(url, new String(responseData, "UTF-8")));
                            URL urlUrl = new URL(url);
                            int port = 80;
                            if (urlUrl.getPort() != -1){
                                port = urlUrl.getPort();
                            } else if (url.contains("http://")) {
                                port = 80;
                            }else {
                                port = 443;
                            }
                            // 针对JS页面提取
                            urlSet.addAll(Utils.findUrlNotFilter(url, port, urlUrl.getHost(), urlUrl.getProtocol(), new String(responseData, "UTF-8")));
                            if (urlSet.isEmpty()){
                                urlSet.add("[-] 未能提取出任何URL");
                            }
                            // 创建一个JTextArea
                            JTextArea textArea = new JTextArea(String.join("\r\n", urlSet));
                            textArea.setLineWrap(true); // 自动换行
                            textArea.setWrapStyleWord(true); // 断行不断字
                            textArea.setEditable(true); // 设置为不可编辑
                            textArea.setCaretPosition(0); // 将插入符号位置设置在文档开头，这样滚动条会滚动到顶部

                            // 使JTextArea能够被复制
                            textArea.setSelectionStart(0);
                            textArea.setSelectionEnd(textArea.getText().length());

                            // 将JTextArea放入JScrollPane
                            JScrollPane scrollPane = new JScrollPane(textArea);
                            scrollPane.setPreferredSize(new Dimension(350, 150)); // 设定尺寸

                            // 弹出一个包含滚动条的消息窗口
                            JOptionPane.showMessageDialog(
                                    null,
                                    scrollPane,
                                    "提取url成功",
                                    JOptionPane.INFORMATION_MESSAGE
                            );
                        }
                    }catch (Exception ek) {
                        BurpExtender.getStderr().println("[-] chick 提取url error : " + path);
                        ek.printStackTrace(BurpExtender.getStderr());
                    }

                }

            }
        });

        // 添加事件监听器到"自定义凭证"菜单项
        cookieItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String listStatus = (String) table.getModel().getValueAt(selectedRow, 0);
                    String path = (String) table.getModel().getValueAt(selectedRow, 2);
                    try {
                        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
                            // Update the database
                            String url = (String) model.getValueAt(selectedRow, 2); // Assuming URL is in column 2
                            // 创建对话框的容器
                            JDialog dialog = new JDialog();
                            dialog.setTitle("自定义凭证");
                            dialog.setLayout(new GridBagLayout()); // 使用GridBagLayout布局管理器
                            GridBagConstraints constraints = new GridBagConstraints();
                            constraints.fill = GridBagConstraints.HORIZONTAL;
                            constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距

                            // 添加URL展示
                            JLabel urlJLabel = new JLabel("功能：针对该URL下返回状态码3xx且重要无敏感指纹场景的补充上下面Header后进行识别");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 0; // 第一行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(urlJLabel, constraints);

                            // 添加PATH展示
                            JLabel pathJLabel = new JLabel("URL： " + url);
                            constraints.gridy = 1; // 第二行
                            dialog.add(pathJLabel, constraints);

                            // 添加"自定义父路径"标签和输入框
                            JLabel customParentPathLabel = new JLabel("自定义凭证(头部信息)：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 2; // 第三行
                            constraints.gridwidth = 1; // 重置为占据一列的空间
                            dialog.add(customParentPathLabel, constraints);

                            JTextArea customParentPathArea = new JTextArea(5, 20);
                            customParentPathArea.setText("Cookie: xxx\r\nAuthorization:xxx");
                            customParentPathArea.setLineWrap(true); // 自动换行
                            customParentPathArea.setWrapStyleWord(true); // 断行不断字
                            constraints.gridx = 1; // 第二列
                            dialog.add(new JScrollPane(customParentPathArea), constraints); // 添加滚动条

                            // 添加按钮面板
                            JPanel buttonPanel = new JPanel();
                            JButton confirmButton = new JButton("确认");
                            JButton cancelButton = new JButton("取消");

                            // 确认按钮事件
                            confirmButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    // 处理自定义父路径逻辑
                                    // 获取用户输入的自定义父路径
                                    String cookie = customParentPathArea.getText();
                                    if (cookie.equals("Cookie: xxx\r\nAuthorization:xxx")){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + ", 插入自定义凭证失败：凭证为空，请重新插入", "插入自定义凭证失败",  JOptionPane.INFORMATION_MESSAGE);
                                        return;
                                    }
                                    if (BurpExtender.getDataBaseService().updatePathDataByUrlInsertCookie(url, cookie)){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + ", 插入自定义凭证成功：" + cookie , "插入自定义凭证成功",  JOptionPane.INFORMATION_MESSAGE);
                                        dialog.dispose(); // 关闭对话框
                                    } else{
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + ", 插入自定义凭证失败：" + cookie , "插入自定义凭证失败",  JOptionPane.INFORMATION_MESSAGE);
                                        dialog.dispose(); // 关闭对话框
                                    }
                                }
                            });

                            // 取消按钮事件
                            cancelButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            buttonPanel.add(confirmButton);
                            buttonPanel.add(cancelButton);
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 3; // 第四行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(buttonPanel, constraints);

                            dialog.pack(); // 调整对话框大小以适应其子组件
                            dialog.setLocationRelativeTo(null); // 居中显示
                            dialog.setVisible(true); // 显示对话框
                        } else {
                            // Update the database
                            String url = findUrlFromPath(selectedRow);
                            // 创建对话框的容器
                            JDialog dialog = new JDialog();
                            dialog.setTitle("自定义凭证");
                            dialog.setLayout(new GridBagLayout()); // 使用GridBagLayout布局管理器
                            GridBagConstraints constraints = new GridBagConstraints();
                            constraints.fill = GridBagConstraints.HORIZONTAL;
                            constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距

                            // 添加URL展示
                            JLabel urlJLabel = new JLabel("功能：针对该URL添加下面Header后进行识别");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 0; // 第一行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(urlJLabel, constraints);

                            // 添加PATH展示
                            JLabel pathJLabel = new JLabel("URL： " + url + path);
                            constraints.gridy = 1; // 第二行
                            dialog.add(pathJLabel, constraints);

                            // 添加"自定义父路径"标签和输入框
                            JLabel customParentPathLabel = new JLabel("自定义凭证(头部信息)：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 2; // 第三行
                            constraints.gridwidth = 1; // 重置为占据一列的空间
                            dialog.add(customParentPathLabel, constraints);

                            JTextArea customParentPathArea = new JTextArea(5, 20);
                            customParentPathArea.setText("Cookie: xxx\r\nAuthorization:xxx");
                            customParentPathArea.setLineWrap(true); // 自动换行
                            customParentPathArea.setWrapStyleWord(true); // 断行不断字
                            constraints.gridx = 1; // 第二列
                            dialog.add(new JScrollPane(customParentPathArea), constraints); // 添加滚动条

                            // 添加按钮面板
                            JPanel buttonPanel = new JPanel();
                            JButton confirmButton = new JButton("确认");
                            JButton cancelButton = new JButton("取消");

                            // 确认按钮事件
                            confirmButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    // 处理自定义父路径逻辑
                                    // 获取用户输入的自定义父路径
                                    String cookie = customParentPathArea.getText();
                                    if (cookie.equals("Cookie: xxx\r\nAuthorization:xxx")){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + path + ", 插入自定义凭证失败：凭证为空，请重新插入", "插入自定义凭证失败",  JOptionPane.INFORMATION_MESSAGE);
                                        return;
                                    }
                                    if (BurpExtender.getDataBaseService().updatePathDataByUrlAndPathInsertCookie(url, path,  cookie)){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + path + ", 插入自定义凭证成功：" + cookie , "插入自定义凭证成功",  JOptionPane.INFORMATION_MESSAGE);
                                        dialog.dispose(); // 关闭对话框
                                    } else{
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + path+  ", 插入自定义凭证失败：" + cookie , "插入自定义凭证失败",  JOptionPane.INFORMATION_MESSAGE);
                                        dialog.dispose(); // 关闭对话框
                                    }
                                }
                            });

                            // 取消按钮事件
                            cancelButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            buttonPanel.add(confirmButton);
                            buttonPanel.add(cancelButton);
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 3; // 第四行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(buttonPanel, constraints);

                            dialog.pack(); // 调整对话框大小以适应其子组件
                            dialog.setLocationRelativeTo(null); // 居中显示
                            dialog.setVisible(true); // 显示对话框
                        }

                    }catch (Exception ek) {
                        BurpExtender.getStderr().println("[-] chick 自定义cookie error : " + path);
                        ek.printStackTrace(BurpExtender.getStderr());
                    }

                }

            }
        });

        // 添加事件监听器到"自定义父路径"菜单项
        // 添加事件监听器到"自定义父路径"菜单项
        customizeItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String listStatus = (String) table.getModel().getValueAt(selectedRow, 0);
                    String path = (String) table.getModel().getValueAt(selectedRow, 2);
                    try {
                        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
                            // Update the database
                            String url = (String) model.getValueAt(selectedRow, 2); // Assuming URL is in column 2
                            // 创建对话框的容器
                            JDialog dialog = new JDialog();
                            dialog.setTitle("自定义父路径");
                            dialog.setLayout(new GridBagLayout()); // 使用GridBagLayout布局管理器
                            GridBagConstraints constraints = new GridBagConstraints();
                            constraints.fill = GridBagConstraints.HORIZONTAL;
                            constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距

                            // 添加URL展示
                            JLabel urlJLabel = new JLabel("功能：针对该URL下返回状态码3xx或4xx且无敏感指纹场景的补充上下面父路径后进行识别：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 0; // 第一行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(urlJLabel, constraints);

                            // 添加PATH展示
                            JLabel pathJLabel = new JLabel("URL： " + url);
                            constraints.gridy = 1; // 第二行
                            dialog.add(pathJLabel, constraints);

                            // 添加"自定义父路径"标签和输入框
                            JLabel customParentPathLabel = new JLabel("自定义父路径(多个用逗号拼接)：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 2; // 第三行
                            constraints.gridwidth = 1; // 重置为占据一列的空间
                            dialog.add(customParentPathLabel, constraints);

                            JTextField customParentPathField = new JTextField();
                            constraints.gridx = 1; // 第二列
                            dialog.add(customParentPathField, constraints);

                            // 添加按钮面板
                            JPanel buttonPanel = new JPanel();
                            JButton confirmButton = new JButton("确认");
                            JButton cancelButton = new JButton("取消");

                            // 确认按钮事件
                            confirmButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    // 处理自定义父路径逻辑
                                    // 获取用户输入的自定义父路径
                                    String customPath = customParentPathField.getText();
                                    if (BurpExtender.getDataBaseService().updatePathDataBy4xxAnd3XXAndUrl(url, customPath)){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + ", 插入自定义父路径成功：" + customPath , "插入自定义路径成功",  JOptionPane.INFORMATION_MESSAGE);
                                    } else{
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + ", 插入自定义父路径失败：" + customPath , "插入自定义路径失败",  JOptionPane.INFORMATION_MESSAGE);
                                    }
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            // 取消按钮事件
                            cancelButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            buttonPanel.add(confirmButton);
                            buttonPanel.add(cancelButton);
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 3; // 第四行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(buttonPanel, constraints);

                            dialog.pack(); // 调整对话框大小以适应其子组件
                            dialog.setLocationRelativeTo(null); // 居中显示
                            dialog.setVisible(true); // 显示对话框
                        } else {
                            String url = findUrlFromPath(selectedRow);
                            // 创建对话框的容器
                            JDialog dialog = new JDialog();
                            dialog.setTitle("自定义父路径");
                            dialog.setLayout(new GridBagLayout()); // 使用GridBagLayout布局管理器
                            GridBagConstraints constraints = new GridBagConstraints();
                            constraints.fill = GridBagConstraints.HORIZONTAL;
                            constraints.insets = new Insets(10, 10, 10, 10); // 设置组件之间的间距

                            // 添加URL展示
                            JLabel urlJLabel = new JLabel("功能：针对该PATH补充下面父路径后进行识别：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 0; // 第一行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(urlJLabel, constraints);

                            // 添加PATH展示
                            JLabel pathJLabel = new JLabel("PATH： " + path);
                            constraints.gridy = 1; // 第二行
                            dialog.add(pathJLabel, constraints);

                            // 添加"自定义父路径"标签和输入框
                            JLabel customParentPathLabel = new JLabel("自定义父路径(多个用逗号拼接)：");
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 2; // 第三行
                            constraints.gridwidth = 1; // 重置为占据一列的空间
                            dialog.add(customParentPathLabel, constraints);

                            JTextField customParentPathField = new JTextField();
                            constraints.gridx = 1; // 第二列
                            dialog.add(customParentPathField, constraints);

                            // 添加按钮面板
                            JPanel buttonPanel = new JPanel();
                            JButton confirmButton = new JButton("确认");
                            JButton cancelButton = new JButton("取消");

                            // 确认按钮事件
                            confirmButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    // 处理自定义父路径逻辑
                                    String customPath = customParentPathField.getText();
                                    if (BurpExtender.getDataBaseService().updatePathDataByUrlAndPath(url, path, customPath)){
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + path +  ", 插入自定义父路径成功：" + customPath , "插入自定义路径成功",  JOptionPane.INFORMATION_MESSAGE);
                                    } else{
                                        JOptionPane.showMessageDialog(table, "对URL：" + url + path + ", 插入自定义父路径失败：" + customPath , "插入自定义路径失败",  JOptionPane.INFORMATION_MESSAGE);
                                    }
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            // 取消按钮事件
                            cancelButton.addActionListener(new ActionListener() {
                                @Override
                                public void actionPerformed(ActionEvent e) {
                                    dialog.dispose(); // 关闭对话框
                                }
                            });

                            buttonPanel.add(confirmButton);
                            buttonPanel.add(cancelButton);
                            constraints.gridx = 0; // 第一列
                            constraints.gridy = 3; // 第四行
                            constraints.gridwidth = 2; // 占据两列的空间
                            dialog.add(buttonPanel, constraints);

                            dialog.pack(); // 调整对话框大小以适应其子组件
                            dialog.setLocationRelativeTo(null); // 居中显示
                            dialog.setVisible(true); // 显示对话框

                        }

                    }catch (Exception ek) {
                        BurpExtender.getStderr().println("[-] chick 自定义父路径 error : " + path);
                        ek.printStackTrace(BurpExtender.getStderr());
                    }

                }

            }
        });

        copyItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the selected row from the table

                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    // 假设URL在表格的第三列
                    String url = (String) table.getValueAt(selectedRow, 2);
                    // 复制URL到剪贴板
                    StringSelection stringSelection = new StringSelection(url);
                    Clipboard clipboard = Toolkit.getDefaultToolkit().getSystemClipboard();
                    clipboard.setContents(stringSelection, null);
                }
            }
        });

        setUnImportantItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the selected row from the table

                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String listStatus = (String) table.getModel().getValueAt(selectedRow, 0);
                    String path = (String) table.getModel().getValueAt(selectedRow, 2);
                    try {
                        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
                            // Update the database
                            String url = (String) model.getValueAt(selectedRow, 2); // Assuming URL is in column 2
                            ApiDataModel apiDataModel = BurpExtender.getDataBaseService().selectApiDataModelByUri(url);
                            if (apiDataModel != null) {
                                apiDataModel.setHavingImportant(false);
                                apiDataModel.setResult("误报");
                                apiDataModel.setDescribe("误报");
                                BurpExtender.getDataBaseService().updateApiDataModelByUrl(apiDataModel);
                                BurpExtender.getDataBaseService().updateIsImportantToFalse(apiDataModel.getUrl());
                            }
                        } else {
                            String url = findUrlFromPath(selectedRow);
                            ApiDataModel apiDataModel = BurpExtender.getDataBaseService().selectApiDataModelByUri(url);
                            Map<String, Object> matchPathData = BurpExtender.getDataBaseService().selectPathDataByUrlAndPath(url, path);
                            matchPathData.put("result", "误报");
                            matchPathData.put("describe", "误报");
                            matchPathData.put("isImportant", false);
                            BurpExtender.getDataBaseService().insertOrUpdatePathData(url, path, false, (String) matchPathData.get("status"), "误报", "误报", matchPathData);
                            if (!BurpExtender.getDataBaseService().hasImportantPathDataByUrl(url)){
                                apiDataModel.setHavingImportant(false);
                                apiDataModel.setResult("误报");
                                apiDataModel.setDescribe("误报");
                                BurpExtender.getDataBaseService().updateApiDataModelByUrl(apiDataModel);
                            }

                        }
                        // 触发显示所有行事件
                        String searchText = "";
                        if (!ConfigPanel.searchField.getText().isEmpty()){
                            searchText = ConfigPanel.searchField.getText();
                        }
                        // 设置所有状态码为关闭
                        String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                        MailPanel.showFilter(selectedOption, searchText);

                    }catch (Exception ek) {
                        BurpExtender.getStderr().println("[-] chick setUnImportantItem error : " + path);
                        ek.printStackTrace(BurpExtender.getStderr());
                    }

                }
            }
        });


        deleteItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // Get the selected row from the table

                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) {
                    String listStatus = (String) table.getModel().getValueAt(selectedRow, 0);
                    String path = (String) table.getModel().getValueAt(selectedRow, 2);
                    try {
                        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
                            // Update the database
                            String url = (String) model.getValueAt(selectedRow, 2); // Assuming URL is in column 2
                            Boolean deleteApiDataModelByUriBoolean = BurpExtender.getDataBaseService().deleteApiDataModelByUri(url);
                            if (deleteApiDataModelByUriBoolean){
                                if (BurpExtender.getDataBaseService().deletePathDataByUrl(url)){
                                    JOptionPane.showMessageDialog(table, "成功将URL从ApiData表和PathData中删除：" + url, "删除成功",  JOptionPane.INFORMATION_MESSAGE);
                                }
                                else{
                                    JOptionPane.showMessageDialog(table, "无法将URL从PathData表中删除：" + url, "删除失败",  JOptionPane.INFORMATION_MESSAGE);
                                }
                            }else{
                                JOptionPane.showMessageDialog(table, "无法将URL从ApiData表中删除：" + url, "删除失败",  JOptionPane.INFORMATION_MESSAGE);
                            }

                        } else {
                            String url = findUrlFromPath(selectedRow);
                            if(BurpExtender.getDataBaseService().deletePathDataByUrlAndPath(url, path)){
                                JOptionPane.showMessageDialog(table, "成功将PATH从PathData表中删除：" + url + path, "删除成功",  JOptionPane.INFORMATION_MESSAGE);
                            }else{
                                JOptionPane.showMessageDialog(table, "无法将PATH从PathData表中删除：" + url + path, "删除失败",  JOptionPane.INFORMATION_MESSAGE);
                            }
                        }
                        // 触发显示所有行事件
                        String searchText = "";
                        if (!ConfigPanel.searchField.getText().isEmpty()){
                            searchText = ConfigPanel.searchField.getText();
                        }
                        // 设置所有状态码为关闭
                        String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();
                        MailPanel.showFilter(selectedOption, searchText);

                    }catch (Exception ek) {
                        BurpExtender.getStderr().println("[-] chick setUnImportantItem error : " + path);
                        ek.printStackTrace(BurpExtender.getStderr());
                    }

                }
            }
        });

        upScrollPane = new JScrollPane(table);
        // 将upScrollPane作为mainSplitPane的上半部分
        mainSplitPane.setTopComponent(upScrollPane);

        // 前两列设置宽度 30px、60px
        table.getColumnModel().getColumn(0).setMaxWidth(30);
        table.getColumnModel().getColumn(1).setMaxWidth(60);
        table.getColumnModel().getColumn(2).setMinWidth(300);
        table.getColumnModel().getColumn(7).setMinWidth(60);
        table.getColumnModel().getColumn(8).setMinWidth(150);
        table.getColumnModel().getColumn(9).setMinWidth(200);
        table.getColumnModel().getColumn(10).setMinWidth(140);

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
        table.getColumnModel().getColumn(9).setCellRenderer(leftRenderer);
        table.getColumnModel().getColumn(10).setCellRenderer(leftRenderer);

        IsJsFindUrlRenderer isJsFindUrlRenderer = new IsJsFindUrlRenderer();
        table.getColumnModel().getColumn(6).setCellRenderer(isJsFindUrlRenderer);
        IconTableCellRenderer havingImportantRenderer = new IconTableCellRenderer();
        table.getColumnModel().getColumn(7).setCellRenderer(havingImportantRenderer);

        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        try {
                            int row = table.rowAtPoint(e.getPoint());
                            if (row >= 0) {
                                updateComponentsBasedOnSelectedRow(row);
                            }
                        }catch (Exception ef) {
                            BurpExtender.getStderr().println("[-] Error click table: " + table.rowAtPoint(e.getPoint()));
                            ef.printStackTrace(BurpExtender.getStderr());
                        }
                    }
                });

            }
        });

        table.addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_UP || e.getKeyCode() == KeyEvent.VK_DOWN) {
                    SwingUtilities.invokeLater(new Runnable() {
                        public void run() {
                            try {
                                int row = table.getSelectedRow();
                                if (row >= 0) {
                                    updateComponentsBasedOnSelectedRow(row);
                                }
                            }catch (Exception ef) {
                                BurpExtender.getStderr().println("[-] Error KeyEvent.VK_UP OR  KeyEvent.VK_DOWN: ");
                                ef.printStackTrace(BurpExtender.getStderr());
                            }
                        }
                    });
                }
            }
        });


        // 请求的面板
        requestTextEditor = callbacks.createMessageEditor(this, false);

        // 响应的面板
        responseTextEditor = callbacks.createMessageEditor(this, false);

        // 提取到URL的面板
        findUrlTEditor = BurpExtender.getCallbacks().createTextEditor();


        // 将 verticalSplitPane 添加到窗口的中心区域
        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Result Info", scrollPane);
        tabs.addTab("Original Response", responseTextEditor.getComponent());
        tabs.addTab("Request", requestTextEditor.getComponent());
        tabs.addTab("FindUrlByThisPath", findUrlTEditor.getComponent());
        mainSplitPane.setBottomComponent(tabs);

        contentPane.add(configPanel, BorderLayout.NORTH);
        contentPane.add(mainSplitPane, BorderLayout.CENTER);

        // 构建一个定时刷新页面函数
        // 创建一个每5秒触发一次的定时器
        int delay = 10000; // 延迟时间，单位为毫秒
        timer = new Timer(delay, new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 调用刷新表格的方法
                try{
                    refreshTableModel();
                } catch (Exception ep){
                    BurpExtender.getStderr().println("[!] 刷新表格报错， 报错如下：");
                    ep.printStackTrace(BurpExtender.getStderr());
                }
            }
        });

        // 启动定时器
        timer.start();
    }

    private void updateComponentsBasedOnSelectedRow(int row) {
        selectRow = row;
        String listStatus = (String) table.getModel().getValueAt(row, 0);
        String url;
        if (listStatus.equals(Constants.TREE_STATUS_COLLAPSE) || listStatus.equals(Constants.TREE_STATUS_EXPAND)) {
            url = (String) table.getModel().getValueAt(row, 2);
            ApiDataModel apiDataModel = BurpExtender.getDataBaseService().selectApiDataModelByUri(url);
            requestsData = BurpExtender.getDataBaseService().selectRequestResponseById(apiDataModel.getRequestsResponseIndex()).get("request");
            responseData = BurpExtender.getDataBaseService().selectRequestResponseById(apiDataModel.getRequestsResponseIndex()).get("response");
            iHttpService = apiDataModel.getiHttpService();
            requestTextEditor.setMessage(requestsData, true);
            responseTextEditor.setMessage(responseData, false);
            resultTextPane.setText((apiDataModel.getResultInfo()));
            findUrlTEditor.setText("-".getBytes());
            if (apiDataModel.getListStatus().equals(Constants.TREE_STATUS_COLLAPSE)) {
                BurpExtender.getDataBaseService().updateListStatusByUrl(url, Constants.TREE_STATUS_EXPAND);
                modelExpand(apiDataModel, row);
            } else if (apiDataModel.getListStatus().equals(Constants.TREE_STATUS_EXPAND)) {
                BurpExtender.getDataBaseService().updateListStatusByUrl(url, Constants.TREE_STATUS_COLLAPSE);
                modeCollapse(apiDataModel, row);
            }
        } else {
            try {
                String path = (String) table.getModel().getValueAt(row, 2);
                url = findUrlFromPath(row);
                ApiDataModel apiDataModel = BurpExtender.getDataBaseService().selectApiDataModelByUri(url);
                Map<String, Object> matchPathData = BurpExtender.getDataBaseService().selectPathDataByUrlAndPath(apiDataModel.getUrl(), path);
                if (((String)matchPathData.get("status")).equals("等待爬取")){
                    resultTextPane.setText(("IS Find From JS: " + matchPathData.get("isJsFindUrl") + "<br>" + "Find js From Url: " + Utils.encodeForHTML((String) matchPathData.get("jsFindUrl")) + "<br>等待爬取，爬取后再进行铭感信息探测..."));
                    requestTextEditor.setMessage("等待爬取，爬取后再进行铭感信息探测...".getBytes(), false);
                    responseTextEditor.setMessage("等待爬取，爬取后再进行铭感信息探测...".getBytes(), false);
                    findUrlTEditor.setText("-".getBytes());
                }else{

                    requestsData = Base64.getDecoder().decode((String) matchPathData.get("requests"));
                    responseData = Base64.getDecoder().decode((String) matchPathData.get("response"));
                    iHttpService = Utils.iHttpService((String) matchPathData.get("host"), ((Double) matchPathData.get("port")).intValue(), (String) matchPathData.get("protocol"));
                    requestTextEditor.setMessage(requestsData, true);
                    responseTextEditor.setMessage(responseData, false);
                    if (matchPathData.get("isJsFindUrl").equals("N")){
                        List<String> resultList = BurpExtender.getDataBaseService().selectPathDataByJsFindUrl((String) matchPathData.get("original_url"));
                        if (!resultList.isEmpty()){
                            findUrlTEditor.setText((String.join("\r\n", resultList)).getBytes());
                        }else{
                            findUrlTEditor.setText("-".getBytes());
                        }
                    }else {
                        findUrlTEditor.setText("-".getBytes());
                    }

                    resultTextPane.setText(("IS Find From JS: " + matchPathData.get("isJsFindUrl") + "<br>" + "Find js From Url: " + Utils.encodeForHTML((String) matchPathData.get("jsFindUrl")) + "<br>" +  (String) matchPathData.get("result info")));
                }
            } catch (Exception e) {
                e.printStackTrace(BurpExtender.getStderr());
            }

        }
    }

    public void refreshTableModel() {
        // 刷新页面, 如果自动更新关闭，则不刷新页面内容
        ConfigPanel.lbSuccessCount.setText(String.valueOf(BurpExtender.getDataBaseService().getApiDataCount()));

        if (ConfigPanel.getFlashButtonStatus()) {
            if (Duration.between(operationStartTime, LocalDateTime.now()).getSeconds() > 600) {
                ConfigPanel.setFlashButtonTrue();
            }
            return;
        }

        // 在EDT上获取值
        final String searchText = ConfigPanel.searchField.getText();
        final String selectedOption = (String)ConfigPanel.choicesComboBox.getSelectedItem();

        // 使用SwingWorker来处理数据更新，避免阻塞EDT
        SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
            @Override
            protected Void doInBackground() throws Exception {
                // 执行耗时的数据操作
                MailPanel.showFilter(selectedOption, searchText.isEmpty() ? "" : searchText);
                return null;
            }

            @Override
            protected void done() {
                // 更新UI组件
                SwingUtilities.invokeLater(new Runnable() {
                    public void run() {
                        model.fireTableDataChanged(); // 通知模型数据发生了变化，而不是连续插入或删除行
                    }
                });
            }
        };
        worker.execute();
    }


    @Override
    public byte[] getRequest() {
        return requestsData;
    }

    @Override
    public byte[] getResponse() {
        return responseData;
    }

    @Override
    public IHttpService getHttpService() {
        return iHttpService;
    }
    public static void showFilter(String selectOption, String searchText) {
        // 在后台线程获取数据，避免冻结UI
        new SwingWorker<DefaultTableModel, Void>() {
            @Override
            protected DefaultTableModel doInBackground() throws Exception {
                // 构建一个新的表格模型
                model.setRowCount(0);

                // 获取数据库中的所有ApiDataModels
                List<ApiDataModel> allApiDataModels = BurpExtender.getDataBaseService().getAllApiDataModels();

                // 遍历apiDataModelMap
                for (ApiDataModel apiDataModel : allApiDataModels) {
                    String url = apiDataModel.getUrl();
                    if (selectOption.equals("只看status为200") && !apiDataModel.getStatus().contains("200")){
                        continue;
                    } else if (selectOption.equals("只看重点") &&  !apiDataModel.getHavingImportant()) {
                        continue;
                    } else if (selectOption.equals("只看敏感内容") && !apiDataModel.getResult().contains("敏感内容")){
                        continue;
                    } else if (selectOption.equals("只看敏感路径") && !apiDataModel.getResult().contains("敏感路径")) {
                        continue;
                    }
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
                                apiDataModel.getDescribe(),
                                apiDataModel.getTime()
                        });
                    }
                }
                return null;
            }

            @Override
            protected void done() {
                try {
                    get();
                } catch (InterruptedException | ExecutionException e) {
                    BurpExtender.getStderr().println("[!] showFilter error:");
                    e.printStackTrace(BurpExtender.getStderr());
                }
            }
        }.execute();
    }

    public static void clearAllData(){
        synchronized (model) {
            // 清空model
            model.setRowCount(0);
            // 清空表格
            IProxyScanner.setHaveScanUrlNew();
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
            MailPanel.resultTextPane.setText("");
            MailPanel.findUrlTEditor.setText(new byte[0]);
            MailPanel.iHttpService = null; // 清空当前显示的项
            MailPanel.requestsData = null;
            MailPanel.responseData = null;
        }
    }
    public void modelExpand(ApiDataModel apiDataModel, int index) {
        // Disable auto-refresh
        ConfigPanel.setFlashButtonFalse();
        MailPanel.operationStartTime = LocalDateTime.now();

        // SwingWorker to fetch data in the background
        SwingWorker<List<Object[]>, Void> worker = new SwingWorker<List<Object[]>, Void>() {
            @Override
            protected List<Object[]> doInBackground() throws Exception {
                // Fetch data in the background thread
                String selectedOption = (String) ConfigPanel.choicesComboBox.getSelectedItem();
                Map<String, Object> filteredPathData = fetchData(selectedOption, apiDataModel.getUrl());

                // Prepare table rows
                List<Object[]> rows = new ArrayList<>();
                int tmpIndex = 0;
                for (Map.Entry<String, Object> entry : filteredPathData.entrySet()) {
                    tmpIndex++;
                    String listStatus = (tmpIndex == 1) ? "┗" : "┠";
                    String path = entry.getKey();
                    Map<String, Object> subPathValue = (Map<String, Object>) entry.getValue();

                    rows.add(new Object[]{
                            listStatus,
                            "-",
                            path,
                            "-",
                            subPathValue.get("method"),
                            subPathValue.get("status"),
                            subPathValue.get("isJsFindUrl"),
                            subPathValue.get("isImportant"),
                            subPathValue.get("result"),
                            subPathValue.get("describe"),
                            subPathValue.get("time")
                    });
                }
                return rows;
            }

            @Override
            protected void done() {
                try {
                    // Update table model on the EDT
                    List<Object[]> rows = get();
                    if (!rows.isEmpty()) {
                        for (Object[] row : rows) {
                            model.insertRow(index + 1, row);
                        }
                        model.fireTableRowsInserted(index + 1, index + rows.size());
                    }
                } catch (InterruptedException | ExecutionException e) {
                    BurpExtender.getStderr().println("[!] modelExpand error:");
                    e.printStackTrace(BurpExtender.getStderr());
                }
            }
        };

        worker.execute();
    }


    private Map<String, Object> fetchData(String selectedOption, String url) {
        // Your actual method to fetch data from the database
        // Replace the body of this method with your database access code
        // For example:
        switch (selectedOption) {
            case "只看status为200":
                return BurpExtender.getDataBaseService().selectPathDataByUrlAndStatus(url, "200");
            case "只看重点":
                return BurpExtender.getDataBaseService().selectPathDataByUrlAndImportance(url, true);
            case "只看敏感内容":
                return BurpExtender.getDataBaseService().selectPathDataByUrlAndResult(url, "敏感内容");
            case "只看敏感路径":
                return BurpExtender.getDataBaseService().selectPathDataByUrlAndResult(url, "敏感路径");
            default:
                return BurpExtender.getDataBaseService().selectAllPathDataByUrl(url);
        }
    }



    public void modeCollapse(ApiDataModel apiDataModel, int index) {
        // 看当前是否有过滤场景
        model.setValueAt(Constants.TREE_STATUS_COLLAPSE, index, 0);

        // 计算即将删除的行区间
        int startDeleteIndex = index + 1;
        int deleteNumber = 0;

        // 从后向前删除子项，这样索引就不会因为列表的变动而改变
        int numberOfRows = model.getRowCount();
        for (int i = 0; i < numberOfRows; i++) {
            try {
                if (startDeleteIndex > (model.getRowCount() - 1)){
                    break;
                }
                if (!model.getValueAt(startDeleteIndex, 0).equals(Constants.TREE_STATUS_EXPAND) && !model.getValueAt(startDeleteIndex, 0).equals(Constants.TREE_STATUS_COLLAPSE)) {
                    model.removeRow(startDeleteIndex);
                    deleteNumber += 1;
                } else {
                    break;
                }} catch (Exception e) {
                    BurpExtender.getStderr().println("[!] 数据收起报错，报错如下：");
                    e.printStackTrace(BurpExtender.getStderr());
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

    public ConfigPanel getConfigPanel(){
        return this.configPanel;
    }

}


