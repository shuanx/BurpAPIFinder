package burp.ui;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.ITab;

import javax.swing.*;
import java.awt.*;


public class Tags implements ITab {

    private final JTabbedPane tabs;
    private final String tagName;
    private MailPanel mailPanel;

    public Tags(IBurpExtenderCallbacks callbacks, String name){
        this.tagName = name;
        this.mailPanel = new MailPanel(callbacks, name);
        // 定义tab标签页
        tabs = new JTabbedPane();
        tabs.add("主页", this.mailPanel);

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

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}