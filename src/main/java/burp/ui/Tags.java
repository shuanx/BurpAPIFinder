package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;


public class Tags implements ITab {

    private final JTabbedPane tabs;
    private final String tagName;
    private final MailPanel mailPanel;
    public FingerConfigTab fingerConfigTab = new FingerConfigTab();

    public Tags(IBurpExtenderCallbacks callbacks, String name){
        this.tagName = name;
        this.mailPanel = new MailPanel(callbacks, name);
        // 定义tab标签页
        tabs = new JTabbedPane();
        tabs.add("配置", this.fingerConfigTab);
        tabs.add("主页", MailPanel.getContentPane());

        // 将整个tab加载到平台即可
        callbacks.customizeUiComponent(tabs);
        // 将自定义选项卡添加到Burp的UI
        callbacks.addSuiteTab(Tags.this);

    }


    @Override
    public String getTabCaption() {
        return this.tagName;
    }

    public MailPanel getMainPanel(){
        return this.mailPanel;
    }

    public FingerConfigTab getFingerConfigTab(){
        return this.fingerConfigTab;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}