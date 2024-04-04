package burp.ui;

import burp.IBurpExtenderCallbacks;
import burp.ITab;
import burp.ui.tabs.ScannerUi;
import burp.ui.tabs.SettingUi;

import javax.swing.*;
import java.awt.*;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：
 */
public class Tags implements ITab {

    private final JTabbedPane tabs;

    private SettingUi settingUi;
    private ScannerUi scannerUi;

    private String name;
    private IBurpExtenderCallbacks callbacks;

    public Tags(IBurpExtenderCallbacks callbacks, String name) {
        this.callbacks = callbacks;
        this.name = name;

        this.tabs = new JTabbedPane();

        this.scannerUi = new ScannerUi(callbacks, this.tabs);
        this.settingUi = new SettingUi(callbacks, this.tabs);

        this.callbacks.addSuiteTab(this);
        this.callbacks.customizeUiComponent(this.tabs);
    }

    public SettingUi getSettingUi() {
        return this.settingUi;
    }

    public ScannerUi getScannerUi() {
        return this.scannerUi;
    }

    @Override
    public String getTabCaption() {
        return this.name;
    }

    @Override
    public Component getUiComponent() {
        return this.tabs;
    }
}
