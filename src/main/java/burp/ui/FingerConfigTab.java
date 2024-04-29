package burp.ui;

import burp.BurpExtender;
import burp.Wrapper.FingerPrintRulesWrapper;
import burp.model.FingerPrintRule;

import java.io.*;
import java.lang.reflect.Type;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.net.URL;
import java.awt.event.*;

import burp.ui.renderer.ButtonRenderer;
import burp.ui.renderer.CenterRenderer;
import burp.ui.renderer.HeaderIconTypeRenderer;
import burp.util.UiUtils;
import burp.util.Utils;
import burp.ui.renderer.HeaderIconRenderer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;

import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.JFileChooser;
import javax.swing.JOptionPane;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.swing.border.EmptyBorder;



public class FingerConfigTab extends JPanel {
    private static DefaultTableModel model;
    private JTable table;
    private JDialog editPanel;  // 新增：编辑面板
    private Integer editingRow = null;
    private JTextField keywordField, describeField;  // 新增：编辑面板的文本字段
    private JComboBox<Boolean> isImportantField;
    private JComboBox<String> methodField, locationField, typeField;

    public static JToggleButton toggleButton;
    private static List<Integer> tableToModelIndexMap = new ArrayList<>();
    public Set<String> uniqueTypes = new HashSet<>();


    public FingerConfigTab() {
        setLayout(new BorderLayout());

        JPanel toolbar = new JPanel();
        toolbar.setLayout(new BorderLayout());
        JPanel leftPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JPanel rightPanel = new JPanel(new FlowLayout(FlowLayout.RIGHT));
        // 新增按钮
        JButton addButton = new JButton("新增");
        addButton.setIcon(UiUtils.getImageIcon("/icon/addButtonIcon.png"));
        // 创建一个面板来放置放在最左边的按钮
        leftPanel.add(addButton);

        // 居中，设置指纹识别的开关按钮
        JPanel centerPanel = new JPanel(new FlowLayout(FlowLayout.CENTER));

        // 调整 centerPanel 的位置
        int leftPadding = 150;  // 调整这个值来改变左边距
        centerPanel.setBorder(new EmptyBorder(0, leftPadding, 0, 0));
        // 所有指纹和重点指纹的选择

        ImageIcon shutdownIcon = UiUtils.getImageIcon("/icon/shutdownButtonIcon.png", 50, 24);
        ImageIcon openIcon = UiUtils.getImageIcon("/icon/openButtonIcon.png", 50, 24);


        toggleButton = new JToggleButton(openIcon);
        toggleButton.setSelectedIcon(shutdownIcon);
        toggleButton.setPreferredSize(new Dimension(50, 24));
        toggleButton.setBorder(null);  // 设置无边框
        toggleButton.setFocusPainted(false);  // 移除焦点边框
        toggleButton.setContentAreaFilled(false);  // 移除选中状态下的背景填充
        toggleButton.setToolTipText("指纹识别功能开");

        centerPanel.add(toggleButton);


        // 全部按钮
        JButton allButton = new JButton("全部");
        // 检索框
        JTextField searchField = new JTextField(15);
        // 检索按钮
        JButton searchButton = new JButton();
        searchButton.setIcon(UiUtils.getImageIcon("/icon/searchButton.png"));
        searchButton.setToolTipText("搜索");
        // 功能按钮
        JPopupMenu popupMenu = new JPopupMenu("功能");
        JMenuItem saveItem = new JMenuItem("保存");
        saveItem.setIcon(UiUtils.getImageIcon("/icon/saveItem.png"));
        JMenuItem importItem = new JMenuItem("导入");
        importItem.setIcon(UiUtils.getImageIcon("/icon/importItem.png"));
        JMenuItem exportItem = new JMenuItem("导出");
        exportItem.setIcon(UiUtils.getImageIcon("/icon/exportItem.png"));
        JMenuItem resetItem = new JMenuItem("重置");
        resetItem.setIcon(UiUtils.getImageIcon("/icon/resetItem.png"));
        popupMenu.add(saveItem);
        popupMenu.add(importItem);
        popupMenu.add(exportItem);
        popupMenu.add(resetItem);
        JButton moreButton = new JButton();
        moreButton.setIcon(UiUtils.getImageIcon("/icon/moreButton.png"));

        // 布局
        rightPanel.add(allButton);
        rightPanel.add(searchField);
        rightPanel.add(searchButton);
        rightPanel.add(moreButton);
        // 将左右面板添加到总的toolbar面板中
        toolbar.add(leftPanel, BorderLayout.WEST);
        toolbar.add(centerPanel, BorderLayout.CENTER);
        toolbar.add(rightPanel, BorderLayout.EAST);
        add(toolbar, BorderLayout.NORTH);


        // 输入”检索区域“的监听事件
        searchField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本

                // 清除表格的所有行
                model.setRowCount(0);
                if (toggleButton.isSelected()){
                    return;
                }
                int counter=1;
                // 清空映射
                tableToModelIndexMap.clear();

                // 重新添加匹配搜索文本的行，并更新映射
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    if (String.join(",", rule.getKeyword()).toLowerCase().contains(searchText.toLowerCase())){
                        // 保存当前规则在模型列表中的索引
                        tableToModelIndexMap.add(i);
                        model.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getMatch(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }

                }
            }
        });
        searchButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                String searchText = searchField.getText(); // 获取用户输入的搜索文本
                // 清除表格的所有行
                model.setRowCount(0);
                if (toggleButton.isSelected()){
                    return;
                }
                // 重新添加匹配搜索文本的行
                int counter=1;
                // 清空映射
                tableToModelIndexMap.clear();

                // 重新添加匹配搜索文本的行，并更新映射
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                    if (String.join(",", rule.getKeyword()).toLowerCase().contains(searchText.toLowerCase())){
                        // 保存当前规则在模型列表中的索引
                        tableToModelIndexMap.add(i);
                        model.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getMatch(), // 获取method信息
                                rule.getLocation(), // 获取location信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }
                }
            }
        });
        // 点击“全部“的监听事件
        allButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {

                // 清除表格的所有行
                model.setRowCount(0);
                if (toggleButton.isSelected()){
                    return;
                }

                int counter=1;
                // 清空映射
                tableToModelIndexMap.clear();

                // 重新添加匹配搜索文本的行，并更新映射
                for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);

                    // 保存当前规则在模型列表中的索引
                    tableToModelIndexMap.add(i);
                    model.addRow(new Object[]{
                            counter,
                            rule.getType(),
                            rule.getDescribe(),
                            rule.getIsImportant(),
                            rule.getMatch(), // 获取method信息
                            rule.getLocation(), // 获取location信息
                            String.join(",", rule.getKeyword()),
                            new String[] {"Edit", "Delete"} // 操作按钮
                    });
                    counter ++;
                }
            }
        });
        // 在新增按钮的点击事件中添加以下代码来设置 typeField 的值
        addButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 清空编辑面板的文本字段
                isImportantField.setSelectedItem(Boolean.TRUE); // 默认设置为非重要
                methodField.setSelectedItem("keyword"); // 默认方法设置为 keyword
                updateLocationField("keyword"); // 根据默认的方法更新 locationField
                keywordField.setText("");

                // 更新 typeField 下拉选项
                updateTypeField(); // 确保调用此方法以更新 JComboBox 的选项

                // 设置编辑面板的位置并显示
                Point locationOnScreen = ((Component)e.getSource()).getLocationOnScreen();
                editPanel.setLocation(locationOnScreen.x + 70, locationOnScreen.y);  // 设置编辑面板的位置
                editPanel.setVisible(true);  // 显示编辑面板
            }
        });

        // 点击”功能“的监听事件
        moreButton.addMouseListener(new MouseAdapter() {
            public void mouseClicked(MouseEvent e) {
                popupMenu.show(e.getComponent(), e.getX(), e.getY());
            }
        });
        // 点击导出按钮
        exportItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<FingerPrintRule> rulesToExport = BurpExtender.fingerprintRules;

                // 创建一个新的 FingerPrintRulesWrapper 并设置 fingerprint 列表
                FingerPrintRulesWrapper wrapper = new FingerPrintRulesWrapper();
                wrapper.setFingerprint(rulesToExport);

                // 将 wrapper 对象转换为 JSON 格式
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                String json = gson.toJson(wrapper);

                // 弹出文件选择对话框，让用户选择保存位置
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("保存为");
                fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
                int userSelection = fileChooser.showSaveDialog(FingerConfigTab.this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToSave = fileChooser.getSelectedFile();
                    // 确保文件有.json扩展名
                    if (!fileToSave.getAbsolutePath().endsWith(".json")) {
                        fileToSave = new File(fileToSave + ".json");
                    }

                    try {
                        // 使用UTF-8编码写入文件
                        OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8);
                        writer.write(json);
                        writer.close();

                        JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已导出至: " + fileToSave.getAbsolutePath(), "导出成功", JOptionPane.INFORMATION_MESSAGE);
                    } catch (IOException ex) {
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "写入文件时发生错误: " + ex.getMessage(), "导出失败", JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        });
        // 点击导入按钮
        importItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 弹出文件选择对话框，让用户选择 JSON 文件
                JFileChooser fileChooser = new JFileChooser();
                fileChooser.setDialogTitle("请选择文件");
                fileChooser.setFileFilter(new FileNameExtensionFilter("JSON文件 (*.json)", "json"));
                int userSelection = fileChooser.showOpenDialog(FingerConfigTab.this);

                if (userSelection == JFileChooser.APPROVE_OPTION) {
                    File fileToOpen = fileChooser.getSelectedFile();

                    try {
                        // 使用UTF-8编码读取文件
                        BufferedReader reader = new BufferedReader(new InputStreamReader(new FileInputStream(fileToOpen), StandardCharsets.UTF_8));
                        StringBuilder sb = new StringBuilder();
                        String line;
                        while ((line = reader.readLine()) != null) {
                            sb.append(line);
                        }
                        reader.close();

                        // 将文件内容转换为 JSON 格式
                        Gson gson = new Gson();
                        FingerPrintRulesWrapper wrapper = gson.fromJson(sb.toString(), FingerPrintRulesWrapper.class);
                        List<FingerPrintRule> rules = wrapper.getFingerprint();

                        wrapper.setFingerprint(rules);

                        // 清空原列表，并将新数据添加到原列表
                        synchronized (BurpExtender.fingerprintRules) {
                            // 清空原列表，并将新数据添加到原列表
                            BurpExtender.fingerprintRules.clear();
                            BurpExtender.fingerprintRules.addAll(wrapper.getFingerprint());
                        }

                        // 清除表格的所有行
                        model.setRowCount(0);

                        // 添加所有的行
                        int counter = 1;
                        for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                            model.addRow(new Object[]{
                                    counter,
                                    rule.getType(),
                                    rule.getDescribe(),
                                    rule.getIsImportant(),
                                    rule.getMatch(), // 获取 method 信息
                                    rule.getLocation(), // 获取 location 信息
                                    String.join(",", rule.getKeyword()),
                                    new String[] {"Edit", "Delete"} // 操作按钮
                            });
                            counter ++;
                        }


                        JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已从: " + fileToOpen.getAbsolutePath() + " 导入", "导入成功", JOptionPane.INFORMATION_MESSAGE);
                        model.fireTableDataChanged();
                    } catch (Exception ex) {
                        JOptionPane.showMessageDialog(FingerConfigTab.this, "读取文件或解析 JSON 数据时发生错误: " + ex.getMessage(), "导入失败", JOptionPane.ERROR_MESSAGE);
                        BurpExtender.getStdout().println(ex.getMessage());
                    }

                }
                toggleButton.setSelected(false);
            }
        });
        // 点击重置按钮
        resetItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取类加载器
                ClassLoader classLoader = getClass().getClassLoader();

                InputStream inputStream = classLoader.getResourceAsStream("conf/finger-important.json");

                try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
                    Gson gson = new Gson();
                    FingerPrintRulesWrapper rulesWrapper = gson.fromJson(reader, FingerPrintRulesWrapper.class);
                    // 清空原列表，并将新数据添加到原列表
                    synchronized (BurpExtender.fingerprintRules) {
                        // 清空原列表，并将新数据添加到原列表
                        BurpExtender.fingerprintRules.clear();
                        BurpExtender.fingerprintRules.addAll(rulesWrapper.getFingerprint());
                    }

                    // 清除表格的所有行
                    model.setRowCount(0);

                    // 添加所有的行
                    int counter = 1;
                    for (FingerPrintRule rule : BurpExtender.fingerprintRules){
                        model.addRow(new Object[]{
                                counter,
                                rule.getType(),
                                rule.getDescribe(),
                                rule.getIsImportant(),
                                rule.getMatch(), // 获取 method 信息
                                rule.getLocation(), // 获取 location 信息
                                String.join(",", rule.getKeyword()),
                                new String[] {"Edit", "Delete"} // 操作按钮
                        });
                        counter ++;
                    }


                    JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已重置到最原始状态", "重置成功",  JOptionPane.INFORMATION_MESSAGE);
                    model.fireTableDataChanged();
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "数据已重置失败： " + ex.getMessage(), "重置失败", JOptionPane.ERROR_MESSAGE);
                }
                toggleButton.setSelected(false);
            }
        });
        // 点击保存按钮
        saveItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                List<FingerPrintRule> rulesToExport = BurpExtender.fingerprintRules;

                // 创建一个新的 FingerPrintRulesWrapper 并设置 fingerprint 列表
                FingerPrintRulesWrapper wrapper = new FingerPrintRulesWrapper();
                wrapper.setFingerprint(rulesToExport);

                // 将 wrapper 对象转换为 JSON 格式
                Gson gson = new GsonBuilder().setPrettyPrinting().create();
                String json = gson.toJson(wrapper);

                try {
                    // 使用UTF-8编码写入文件
                    File fileToSave = new File(Utils.getExtensionFilePath(BurpExtender.getCallbacks()), "finger-tmp.json");
                    OutputStreamWriter writer = new OutputStreamWriter(new FileOutputStream(fileToSave), StandardCharsets.UTF_8);
                    writer.write(json);
                    writer.close();
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "指纹已保存，下次启动使用该指纹", "保存成功",  JOptionPane.INFORMATION_MESSAGE);
                } catch (IOException ex) {
                    JOptionPane.showMessageDialog(FingerConfigTab.this, "指纹保存失败： " + ex.getMessage(), "保存失败", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        // 表格数据
        model = new DefaultTableModel(new Object[]{"#", "type", "describe", "isImportant", "Match", "location", "keyword", "Action"}, 0) {
            @Override
            public Class<?> getColumnClass(int columnIndex) {
                switch (columnIndex) {
                    case 7:
                        return JButton.class;
                    default:
                        return super.getColumnClass(columnIndex);
                }
            }
        };
        int counter = 1;
        tableToModelIndexMap.clear();
        for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
            tableToModelIndexMap.add(i);
            uniqueTypes.add(rule.getType());
            model.addRow(new Object[]{
                    counter,
                    rule.getType(),
                    rule.getDescribe(),
                    rule.getIsImportant(),
                    rule.getMatch(), // 获取method信息
                    rule.getLocation(), // 获取location信息
                    String.join(",", rule.getKeyword()),
                    new String[] {"Edit", "Delete"} // 操作按钮
            });
            counter ++;

        }

        toggleButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                ConfigPanel.toggleButton.setSelected(toggleButton.isSelected());
                if(toggleButton.isSelected()){
                    toggleButton.setToolTipText("指纹识别功能关");
                    // 清除表格的所有行
                    model.setRowCount(0);
                }else{
                    toggleButton.setToolTipText("指纹识别功能开");
                }
            }
        });

        table = new JTable(model);
        CenterRenderer centerRenderer = new CenterRenderer();
        int maxColumnWidth = 200;
        int cmsColumnWidth = 180;
        table.getColumnModel().getColumn(0).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(0).setPreferredWidth(100);
        table.getColumnModel().getColumn(0).setMaxWidth(maxColumnWidth);
        table.getColumnModel().getColumn(1).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(1).setPreferredWidth(100);
        table.getColumnModel().getColumn(1).setMaxWidth(maxColumnWidth);
        table.getColumnModel().getColumn(3).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(3).setPreferredWidth(cmsColumnWidth);
        table.getColumnModel().getColumn(3).setMaxWidth(cmsColumnWidth);
        table.getColumnModel().getColumn(4).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(4).setPreferredWidth(100);
        table.getColumnModel().getColumn(4).setMaxWidth(maxColumnWidth);
        table.getColumnModel().getColumn(5).setCellRenderer(centerRenderer);
        table.getColumnModel().getColumn(5).setPreferredWidth(maxColumnWidth);
        table.getColumnModel().getColumn(5).setMaxWidth(maxColumnWidth);
        table.getColumnModel().getColumn(6).setCellRenderer(centerRenderer);
        // 设置操作列的宽度以适应两个按钮
        int actionColumnWidth = 100;  // 假设每个按钮宽度为70，中间间隔10
        table.getColumnModel().getColumn(7).setPreferredWidth(actionColumnWidth);
        table.getColumnModel().getColumn(7).setMaxWidth(actionColumnWidth);
        table.getColumnModel().getColumn(7).setCellRenderer(new ButtonRenderer());
        table.getColumnModel().getColumn(7).setCellEditor(new ButtonEditor(table));


        // 在 FingerConfigTab 构造函数中，设置表头渲染器的代码部分
        // 在FingerConfigTab构造函数中设置表头渲染器和监听器的代码
        JTableHeader header = table.getTableHeader();
        TableColumnModel columnModel = header.getColumnModel();
        TableColumn typeColumn = columnModel.getColumn(1); // 假定类型列的索引是1

        // 设置表头渲染器
        typeColumn.setHeaderRenderer(new HeaderIconTypeRenderer());

        // 在您的FingerConfigTab构造函数中
        header.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if (table.getColumnModel().getColumnIndexAtX(e.getX()) == 1) { // 假设类型列的索引是1
                    showFilterPopup(e.getComponent(), e.getX(), e.getY());
                }
            }
        });

        add(new JScrollPane(table), BorderLayout.CENTER);


        // 编辑页面框
        editPanel = new JDialog();
        editPanel.setTitle("新增指纹");
        editPanel.setLayout(new GridBagLayout());  // 更改为 GridBagLayout
        editPanel.setSize(500, 300);
        editPanel.setDefaultCloseOperation(JDialog.HIDE_ON_CLOSE);
        editPanel.setModal(false);
        editPanel.setResizable(true);

        typeField = new JComboBox<>();
        typeField.setEditable(true);
        isImportantField = new JComboBox<>(new Boolean[]{true, false});
        methodField = new JComboBox<>(new String[]{"keyword", "regular"});
        locationField = new JComboBox<>();
        keywordField = new JTextField();
        describeField = new JTextField("-");
        methodField.setSelectedItem("keyword");
        updateLocationField("keyword");

        // 创建 GridBagConstraints 对象来控制每个组件的布局
        GridBagConstraints constraints = new GridBagConstraints();
        constraints.anchor = GridBagConstraints.WEST;  // 紧靠左边
        constraints.fill = GridBagConstraints.HORIZONTAL;  // 水平填充
        constraints.insets = new Insets(10, 10, 10, 10);  // 设置内边距为10像素

        // 添加 "Type" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 0;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Type:"), constraints);

        // 添加 "Type" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(typeField, constraints);

        // 添加 "describeField" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 2;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Describe:"), constraints);

        // 添加 "describeField" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(describeField, constraints);

        // 添加 "isImportant" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 3;  // 在网格的第一行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("IsImportant:"), constraints);

        // 添加 "isImportant" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(isImportantField, constraints);

        // 添加 "Method" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 4;  // 在网格的第二行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Match:"), constraints);

        // 添加 "Method" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(methodField, constraints);

        // 添加 "Location" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 5;  // 在网格的第三行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Location:"), constraints);

        // 添加 "Location" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(locationField, constraints);

        // 添加 "Keyword" 标签
        constraints.gridx = 0;  // 在网格的第一列添加组件
        constraints.gridy = 6;  // 在网格的第四行添加组件
        constraints.weightx = 0;  // 不允许横向扩展
        editPanel.add(new JLabel("Keyword:"), constraints);

        // 添加 "Keyword" 输入框
        constraints.gridx = 1;  // 在网格的第二列添加组件
        constraints.weightx = 1.0;  // 允许横向扩展
        editPanel.add(keywordField, constraints);

        // 根据需要，为 Location 和 Keyword 输入框设置首选大小
        typeField.setPreferredSize(new Dimension(100, typeField.getPreferredSize().height));
        isImportantField.setPreferredSize(new Dimension(100, isImportantField.getPreferredSize().height));
        methodField.setPreferredSize(new Dimension(100, methodField.getPreferredSize().height));
        locationField.setPreferredSize(new Dimension(100, locationField.getPreferredSize().height));
        keywordField.setPreferredSize(new Dimension(100, keywordField.getPreferredSize().height));


        JButton saveButton = new JButton("Save");
        saveButton.setIcon(UiUtils.getImageIcon("/icon/saveItem.png"));

        // 在构造函数中为 methodField 添加事件监听器，以便动态更新 locationField 的选项
        methodField.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                JComboBox<String> methodCombo = (JComboBox<String>) e.getSource();
                String selectedMethod = (String) methodCombo.getSelectedItem();
                updateLocationField(selectedMethod); // 根据选择更新 locationField
            }
        });

        // 修改保存按钮的点击事件监听器
        saveButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                // 获取用户选择或输入的type值
                String type = (String) typeField.getEditor().getItem(); // 对于可编辑的JComboBox，使用getEditor().getItem()来获取文本字段中的值
                uniqueTypes.add(type);
                if (type != null) {
                    type = type.trim(); // 清除前后空格
                }
                Boolean isImportant = (Boolean) isImportantField.getSelectedItem();
                String method = (String) methodField.getSelectedItem();
                String location = (String) locationField.getSelectedItem();
                String describe = describeField.getText();
                List<String> keyword;
                if (method.equals("regular")){
                    keyword = Collections.singletonList(keywordField.getText());
                }else{
                    keyword = Arrays.asList(keywordField.getText().split(","));
                }
                if (type.trim().isEmpty() || method.trim().isEmpty() ||
                        location.trim().isEmpty() || keyword.stream().allMatch(String::isEmpty)) {
                    JOptionPane.showMessageDialog(editPanel, "所有输入框都必须填写。", "输入错误", JOptionPane.ERROR_MESSAGE);
                    return;
                }

                if (editingRow != null) {
                    // 如果是编辑现有规则，更新数据源和表格模型中的数据
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(editingRow);
                    rule.setType(type);
                    rule.setDescribe(describe);
                    rule.setIsImportant(isImportant);
                    rule.setMatch(method);
                    rule.setLocation(location);
                    rule.setKeyword(keyword);

                    // 更新表格模型
                    model.setValueAt(type, table.getSelectedRow(), 1);
                    model.setValueAt(describe, table.getSelectedRow(), 2);
                    model.setValueAt(isImportant, table.getSelectedRow(), 3);
                    model.setValueAt(method, table.getSelectedRow(), 4); // 假设Method列是第3列
                    model.setValueAt(location, table.getSelectedRow(), 5); // 假设Location列是第4列
                    model.setValueAt(String.join(",", keyword), table.getSelectedRow(), 6); // 假设Keyword列是第5列

                    // 通知模型数据已更新，触发表格重绘
                    model.fireTableRowsUpdated(table.getSelectedRow(), table.getSelectedRow());
                    // 关闭编辑面板
                    editPanel.setVisible(false);

                    // 重置编辑行索引
                    editingRow = null;
                } else {
                    // 创建新的 FingerPrintRule 对象
                    FingerPrintRule newRule = new FingerPrintRule(type, describe, isImportant, method, location, keyword);
                    synchronized (BurpExtender.fingerprintRules) {
                        // 将新规则添加到数据源的开始位置
                        BurpExtender.fingerprintRules.add(0, newRule);
                        // 更新表格模型
                        ((DefaultTableModel) table.getModel()).insertRow(0, new Object[]{
                                1, // 新行的序号始终为1
                                newRule.getType(),
                                newRule.getDescribe(),
                                newRule.getIsImportant(),
                                newRule.getMatch(),
                                newRule.getLocation(),
                                String.join(",", newRule.getKeyword()),
                                new String[]{"Edit", "Delete"} // 操作按钮
                        });
                        // 更新映射列表，因为添加了新的数据项
                        tableToModelIndexMap.add(0, 0); // 在映射列表的开始位置添加新项
                        // 由于添加了新元素，更新所有行的序号
                        for (int i = 1; i < table.getRowCount(); i++) {
                            table.getModel().setValueAt(i + 1, i, 0);
                        }
                        // 更新后续映射的索引
                        for (int i = 1; i < tableToModelIndexMap.size(); i++) {
                            tableToModelIndexMap.set(i, tableToModelIndexMap.get(i) + 1);
                        }
                    }

                    // 关闭编辑面板
                    editPanel.setVisible(false);
                    // 通知模型数据已更新，触发表格重绘
                    model.fireTableDataChanged();
                }
                BurpExtender.STATIC_FILE_EXT = new ArrayList<>();
                BurpExtender.UNCEKCK_PATH = new ArrayList<>();
                BurpExtender.UNCEKCK_DOMAINS = new ArrayList<>();
                if (BurpExtender.fingerprintRules != null && !BurpExtender.fingerprintRules.isEmpty()){
                    for (int i = 0 ; i < BurpExtender.fingerprintRules.size(); i ++){
                        FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                        String tmpType = rule.getType();
                        if (tmpType.equals("白名单URL后缀")){
                            BurpExtender.STATIC_FILE_EXT.addAll(rule.getKeyword());
                        } else if (tmpType.equals("白名单路径")) {
                            BurpExtender.UNCEKCK_PATH.addAll(rule.getKeyword());
                        } else if (tmpType.equals("白名单域名")) {
                            BurpExtender.UNCEKCK_DOMAINS.addAll(rule.getKeyword());
                        }
                    }
                }
                BurpExtender.getStdout().println("[+] STATIC_FILE_EXT: " + BurpExtender.STATIC_FILE_EXT);
                BurpExtender.getStdout().println("[+] UNCEKCK_PATH: " + BurpExtender.UNCEKCK_PATH);
                BurpExtender.getStdout().println("[+] UNCEKCK_DOMAINS: " + BurpExtender.UNCEKCK_DOMAINS);
            }
        });

        editPanel.add(saveButton);


    }


    // 添加一个新的方法来更新 locationField 的选项
    private void updateLocationField(String method) {
        locationField.removeAllItems(); // 清除之前的选项
        if ("keyword".equals(method)) {
            locationField.addItem("body");
            locationField.addItem("urlPath");
        } else if ("regular".equals(method)) {
            locationField.addItem("body");
            locationField.addItem("urlPath");
        }
        locationField.setSelectedItem("body"); // 默认选中 "body"
    }

    // 创建或更新typeField下拉框的方法
    public void updateTypeField() {
        // 将集合转换为数组
        String[] defaultTypes = uniqueTypes.toArray(new String[0]);
        // 如果typeField已经存在，那么更新它的模型
        if (typeField != null) {
            typeField.setModel(new DefaultComboBoxModel<>(defaultTypes));
        } else {
            // 否则创建新的typeField
            typeField = new JComboBox<>(defaultTypes);
            typeField.setEditable(true);
        }
    }

    private void filterTableByType(String type) {
        model.setRowCount(0); // 清空表格
        tableToModelIndexMap.clear(); // 清空索引映射

        int counter = 1;
        for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
            // 如果type为null或者与规则类型匹配，添加到表格中
            if (type == null || "全部".equals(type) || rule.getType().equals(type)) {
                model.addRow(new Object[]{
                        counter++,
                        rule.getType(),
                        rule.getDescribe(),
                        rule.getIsImportant(),
                        rule.getMatch(),
                        rule.getLocation(),
                        String.join(",", rule.getKeyword()),
                        new String[]{"Edit", "Delete"}
                });
                tableToModelIndexMap.add(i); // 将原始列表的索引添加到映射中
            }
        }
    }



    private void showFilterPopup(Component invoker, int x, int y) {
        JPopupMenu filterMenu = new JPopupMenu();

        // “全部”选项用于移除过滤
        JMenuItem allItem = new JMenuItem("全部");
        allItem.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                filterTableByType(null); // 移除过滤，显示全部
            }
        });
        filterMenu.add(allItem);

        filterMenu.add(new JSeparator()); // 分隔线

        // 为每个独特的类型创建菜单项
        for (String type : uniqueTypes) {
            JMenuItem menuItem = new JMenuItem(type);
            menuItem.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent e) {
                    filterTableByType(type); // 根据选中的类型过滤表格
                }
            });
            filterMenu.add(menuItem);
        }

        filterMenu.show(invoker, x, y); // 显示菜单
    }

    public static void toggleFingerprintsDisplay(boolean isOpen, boolean showImportantOnly) {
        // 清空当前表格数据
        model.setRowCount(0);

        if (isOpen){
            return;
        }

        // 临时计数器，用于表格中的序号
        int counter = 1;

        // 清空映射
        tableToModelIndexMap.clear();

        // 遍历所有指纹规则，并根据条件添加到表格模型中
        for (int i = 0; i < BurpExtender.fingerprintRules.size(); i++) {
            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);

            // 如果showImportantOnly为true，则只显示重要的指纹
            if (!showImportantOnly || rule.getIsImportant()) {
                // 添加行到表格模型
                model.addRow(new Object[]{
                        counter,
                        rule.getType(),
                        rule.getDescribe(),
                        rule.getIsImportant(),
                        rule.getMatch(),
                        rule.getLocation(),
                        String.join(",", rule.getKeyword()),
                        new String[]{"Edit", "Delete"} // 假设这是操作列的按钮
                });

                // 更新tableToModelIndexMap，以便我们知道每个表行对应的数据模型索引
                tableToModelIndexMap.add(i);

                counter++;
            }
        }
    }


    class ButtonEditor extends AbstractCellEditor implements TableCellEditor {
        private final JPanel panel;
        private final JButton editButton;
        private final JButton deleteButton;
        private JTable table;
        private int row;

        public ButtonEditor(JTable table) {
            this.table = table;
            panel = new JPanel(new FlowLayout(FlowLayout.CENTER, 5, 0));
            editButton = new JButton();
            editButton.setIcon(UiUtils.getImageIcon("/icon/editButton.png"));
            deleteButton = new JButton();
            deleteButton.setIcon(UiUtils.getImageIcon("/icon/deleteButton.png"));

            editButton.setPreferredSize(new Dimension(40, 20));
            deleteButton.setPreferredSize(new Dimension(40, 20));

            // 在编辑按钮的 ActionListener 中添加以下代码来设置 keywordField 的值
            editButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    int viewRow = table.getSelectedRow(); // 获取视图中选中的行
                    if (viewRow < 0) {
                        return; // 如果没有选中任何行，就不执行编辑操作
                    }
                    int modelRow = table.convertRowIndexToModel(viewRow); // 转换为模型索引
                    int dataIndex = tableToModelIndexMap.get(modelRow); // 使用模型索引查找原始数据列表中的索引

                    // 使用原始数据列表中的索引来获取和编辑正确的规则
                    editingRow = dataIndex; // 更新编辑行索引为原始数据列表中的索引
                    FingerPrintRule rule = BurpExtender.fingerprintRules.get(dataIndex);

                    // 填充编辑面板的字段
                    typeField.getEditor().setItem(rule.getType());
                    isImportantField.setSelectedItem(rule.getIsImportant());
                    methodField.setSelectedItem(rule.getMatch());
                    locationField.setSelectedItem(rule.getLocation());
                    describeField.setText(rule.getDescribe()); // 根据 rule 的 method 更新 locationField
                    keywordField.setText(String.join(",", rule.getKeyword())); // 设置 keywordField 的值

                    // 显示编辑面板
                    Point btnLocation = ((JButton) e.getSource()).getLocationOnScreen();
                    editPanel.setLocation(btnLocation.x - editPanel.getWidth() / 2, btnLocation.y + ((JButton) e.getSource()).getHeight());
                    editPanel.setVisible(true);

                    // 停止表格的编辑状态
                    fireEditingStopped();
                }
            });


            deleteButton.addActionListener(new ActionListener() {
                public void actionPerformed(ActionEvent e) {
                    fireEditingStopped(); // 确保停止编辑状态
                    int viewRow = table.getSelectedRow(); // 获取视图中选中的行
                    if (viewRow < 0) {
                        return; // 如果没有选中任何行，就不执行删除操作
                    }
                    int modelRow = table.convertRowIndexToModel(viewRow); // 转换为模型索引
                    int dataIndex = tableToModelIndexMap.get(modelRow); // 获取实际数据索引

                    // 删除数据源中的数据
                    BurpExtender.fingerprintRules.remove(dataIndex);

                    // 更新映射
                    tableToModelIndexMap.remove(modelRow);

                    // 由于删除了一个元素，需要更新所有后续元素的索引
                    for (int i = modelRow; i < tableToModelIndexMap.size(); i++) {
                        tableToModelIndexMap.set(i, tableToModelIndexMap.get(i) - 1);
                    }

                    // 删除表格模型中的数据
                    ((DefaultTableModel) table.getModel()).removeRow(viewRow);

                    // 在删除行之后，重新验证和重绘表格
                    table.revalidate();
                    table.repaint();
                    BurpExtender.STATIC_FILE_EXT = new ArrayList<>();
                    BurpExtender.UNCEKCK_PATH = new ArrayList<>();
                    BurpExtender.UNCEKCK_DOMAINS = new ArrayList<>();
                    if (BurpExtender.fingerprintRules != null && !BurpExtender.fingerprintRules.isEmpty()){
                        for (int i = 0 ; i < BurpExtender.fingerprintRules.size(); i ++){
                            FingerPrintRule rule = BurpExtender.fingerprintRules.get(i);
                            String tmpType = rule.getType();
                            if (tmpType.equals("白名单URL后缀")){
                                BurpExtender.STATIC_FILE_EXT.addAll(rule.getKeyword());
                            } else if (tmpType.equals("白名单路径")) {
                                BurpExtender.UNCEKCK_PATH.addAll(rule.getKeyword());
                            } else if (tmpType.equals("白名单域名")) {
                                BurpExtender.UNCEKCK_DOMAINS.addAll(rule.getKeyword());
                            }
                        }
                    }
                    BurpExtender.getStdout().println("[+] STATIC_FILE_EXT: " + BurpExtender.STATIC_FILE_EXT);
                    BurpExtender.getStdout().println("[+] UNCEKCK_PATH: " + BurpExtender.UNCEKCK_PATH);
                    BurpExtender.getStdout().println("[+] UNCEKCK_DOMAINS: " + BurpExtender.UNCEKCK_DOMAINS);
                }
            });


            panel.add(editButton);
            panel.add(deleteButton);
            panel.setBorder(BorderFactory.createEmptyBorder());
        }

        @Override
        public Object getCellEditorValue() {
            return null;
        }

        @Override
        public Component getTableCellEditorComponent(JTable table, Object value, boolean isSelected, int row, int column) {
            this.row = table.convertRowIndexToModel(row); // 转换为模型索引，以防有排序
            return panel;
        }
    }

}