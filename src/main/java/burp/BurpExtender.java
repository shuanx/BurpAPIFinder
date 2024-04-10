package burp;

import burp.ui.ConfigPanel;
import burp.ui.Tags;
import burp.util.Utils;

import java.io.PrintWriter;
import java.util.HashSet;
import java.util.Set;

public class BurpExtender implements IBurpExtender {
    public final static String extensionName = "JsUrlFinder";
    public final static String version = "v2024-04-08";
    public final static String author = "Shaun";

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IBurpExtenderCallbacks callbacks;
    private static IExtensionHelpers helpers;
    private static ConfigPanel configPanel;
    private static Tags tags;
    private static IProxyScanner iProxyScanner;
    public static Set<String> hasScanDomainSet = new HashSet<>();

    public static PrintWriter getStdout() {
        return stdout;
    }

    public static PrintWriter getStderr() {
        return stderr;
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static IExtensionHelpers getHelpers() {
        return helpers;
    }

    public static ConfigPanel getConfigPanel() {
        return configPanel;
    }

    public static void setConfigPanel(ConfigPanel configPanel) {
        BurpExtender.configPanel = configPanel;
    }

    public static Tags getTags() {
        return tags;
    }

    public static IProxyScanner getIProxyScanner() {
        return iProxyScanner;
    }

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        BurpExtender.callbacks = callbacks;
        BurpExtender.helpers = callbacks.getHelpers();
        BurpExtender.stdout = new PrintWriter(callbacks.getStdout(), true);
        BurpExtender.stderr = new PrintWriter(callbacks.getStderr(), true);

        // 标签界面, ExtensionTab 构造时依赖 BurpExtender.callbacks, 所以这个必须放在下面
        BurpExtender.tags = new Tags(callbacks, extensionName);
        BurpExtender.iProxyScanner = new IProxyScanner();

        callbacks.registerProxyListener(iProxyScanner);

        BurpExtender.stdout.println(Utils.getBanner());
    }


}