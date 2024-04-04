package burp.ui.tabs;

import burp.IBurpExtenderCallbacks;
import burp.util.UIUtil;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.util.ArrayList;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：
 */
public class SettingUi {

    public enum Backends {
        Digpm, BurpCollaborator, Dnslog, Ceye
    }

    private IBurpExtenderCallbacks callbacks;

    // ui
    private JTabbedPane tabs;
    private JTabbedPane reverseTabs;
    private JCheckBox enableCheckBox;
    private JCheckBox errorCheckBox;
    private JCheckBox reverseCheckBox;
    private JLabel enableLabel;
    private JLabel checkLabel;
    private JLabel reverseLabel;
    private JPanel backendUI;
    private JComboBox<String> backendSelector;
    private JTextField apiInput;
    private JTextField tokenInput;


    public SettingUi(IBurpExtenderCallbacks callbacks, JTabbedPane tabs) {
        this.callbacks = callbacks;
        this.tabs = tabs;
        this.initUI();
        this.tabs.addTab("Setting", this.backendUI);
    }

    private void initUI() {
        this.backendUI = new JPanel();
        this.backendUI.setAlignmentX(0.0f);
        this.backendUI.setBorder(new EmptyBorder(10, 10, 10, 10));
        this.backendUI.setLayout(new BoxLayout(this.backendUI, BoxLayout.Y_AXIS));  // 垂直对齐

        this.enableLabel = new JLabel("插件:     ");
        this.checkLabel = new JLabel("检测方法:     ");
        this.reverseLabel = new JLabel("回连方法:     ");
        this.enableCheckBox = new JCheckBox("启动", true);
        this.errorCheckBox = new JCheckBox("回显检测   ", true);
        this.reverseCheckBox = new JCheckBox("回连检测", true);

        this.enableLabel.setForeground(new Color(255, 89, 18));
        this.enableLabel.setFont(new Font("Serif", Font.PLAIN, this.enableLabel.getFont().getSize() + 2));

        this.checkLabel.setForeground(new Color(255, 89, 18));
        this.checkLabel.setFont(new Font("Serif", Font.PLAIN, this.checkLabel.getFont().getSize() + 2));

        this.reverseLabel.setForeground(new Color(255, 89, 18));
        this.reverseLabel.setFont(new Font("Serif", Font.PLAIN, this.reverseLabel.getFont().getSize() + 2));

        this.backendSelector = new JComboBox<String>(this.getSelectors());
        this.backendSelector.setSelectedIndex(0);
        this.backendSelector.setMaximumSize(this.backendSelector.getPreferredSize());

        this.reverseTabs = new JTabbedPane();
        this.reverseTabs.addTab("Ceye", this.getCeyePanel());

        JPanel runPanel = UIUtil.GetXPanel();
        runPanel.add(this.enableLabel);
        runPanel.add(this.enableCheckBox);

        JPanel checkPanel = UIUtil.GetXPanel();
        checkPanel.add(this.checkLabel);
        checkPanel.add(this.errorCheckBox);
        checkPanel.add(this.reverseCheckBox);

        JPanel reversePanel = UIUtil.GetXPanel();
        reversePanel.add(this.reverseLabel);
        reversePanel.add(this.backendSelector);

        JPanel settingPanel = UIUtil.GetYPanel();
        settingPanel.add(runPanel);
        settingPanel.add(checkPanel);
        settingPanel.add(reversePanel);

        JPanel reverseInfoPanel = UIUtil.GetXPanel();
        reverseInfoPanel.add(this.reverseTabs);

        this.backendUI.add(settingPanel);
        this.backendUI.add(reverseInfoPanel);
    }


    private JPanel getCeyePanel() {
        JPanel jPanel = UIUtil.GetYPanel();
        JPanel apiPanel = UIUtil.GetXPanel();
        JPanel tokenPanel = UIUtil.GetXPanel();

        apiInput = new JTextField("xxxxxx.ceye.io", 50);
        tokenInput = new JTextField("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", 50);

        apiInput.setMaximumSize(apiInput.getPreferredSize());
        tokenInput.setMaximumSize(tokenInput.getPreferredSize());

        apiPanel.add(new JLabel("Identifier:     "));
        apiPanel.add(apiInput);

        tokenPanel.add(new JLabel("API Token:   "));
        tokenPanel.add(tokenInput);

        jPanel.add(apiPanel);
        jPanel.add(tokenPanel);
        return jPanel;
    }

    private String[] getSelectors() {
        ArrayList<String> selectors = new ArrayList<String>();
        for (Backends backend: Backends.values()) {
            selectors.add(backend.name().trim());
        }
        return selectors.toArray(new String[selectors.size()]);
    }

    /**
     * 插件是否开启状态
     * @return true/false
     */
    public boolean isEnable() {
        return this.enableCheckBox.isSelected();
    }

    /**
     * 是否开启报错检测
     * @return true/false
     */
    public boolean isErrorCheck() {
        return this.errorCheckBox.isSelected();
    }

    /**
     * 是否开启回连检测
     * @return true/false
     */
    public boolean isReverseCheck() {
        return this.reverseCheckBox.isSelected();
    }

    /**
     * 返回选择到回连平台
     * @return Dnslog/BurpCollaboratorClient/Ceye
     */
    public Backends getBackendPlatform() {
        return Backends.valueOf(this.backendSelector.getSelectedItem().toString());
    }

    /**
     * 获取 Ceye Api 地址
     * @return xxxxxx.ceye.io
     */
    public String getApiField() {
        return this.apiInput.getText().trim().toLowerCase();
    }

    /**
     * 获取 Ceye Token
     * @return xxxxxxxxxxxxxxxxx
     */
    public String getTokenField() {
        return this.tokenInput.getText().trim().toLowerCase();
    }
}
