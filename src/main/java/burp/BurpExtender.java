package burp;

import burp.Wrapper.FingerPrintRulesWrapper;
import burp.model.FingerPrintRule;
import burp.ui.ConfigPanel;
import burp.ui.Tags;
import burp.util.Utils;
import com.google.gson.Gson;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
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
    public static List<FingerPrintRule> fingerprintRules;
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

        // 获取类加载器
        ClassLoader classLoader = getClass().getClassLoader();
        String extensionPath = Utils.getExtensionFilePath(BurpExtender.callbacks);
        File tmpFile = new File(extensionPath, "finger-tmp.json");
        InputStream inputStream = null;
        if (tmpFile.exists()) {
            try {
                inputStream = new FileInputStream(tmpFile);
            } catch (FileNotFoundException e) {
                stderr.println("[!] Failed to load the configuration file finger.json, because finger-tmp.json not found");
                return;
            }
        } else {
            inputStream = classLoader.getResourceAsStream("conf/finger-important.json");
        }
        if (inputStream == null) {
            stderr.println("[!] Failed to load the configuration file finger.json, because config/finger.json not found");
            return;
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream, StandardCharsets.UTF_8))) {
            Gson gson = new Gson();
            FingerPrintRulesWrapper rulesWrapper = gson.fromJson(reader, FingerPrintRulesWrapper.class);
            fingerprintRules = rulesWrapper.getFingerprint();
            stdout.println("[+] Successfully loaded the configuration file finger.json");
        } catch (IOException e) {
            stderr.println("[!] Failed to load the configuration file finger.json, because: " + e.getMessage());
        }

        // 标签界面, ExtensionTab 构造时依赖 BurpExtender.callbacks, 所以这个必须放在下面
        BurpExtender.tags = new Tags(callbacks, extensionName);
        BurpExtender.iProxyScanner = new IProxyScanner();

        callbacks.registerProxyListener(iProxyScanner);

        BurpExtender.stdout.println(Utils.getBanner());
    }


}