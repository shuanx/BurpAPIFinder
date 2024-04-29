package burp;

import burp.Wrapper.FingerPrintRulesWrapper;
import burp.dataModel.DatabaseService;
import burp.model.FingerPrintRule;
import burp.ui.ConfigPanel;
import burp.ui.MailPanel;
import burp.ui.Tags;
import burp.util.Utils;
import com.google.gson.Gson;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class BurpExtender implements IBurpExtender, IExtensionStateListener {
    public final static String extensionName = "APIFinder";
    public final static String version = "v2024-04-28";
    public final static String author = "Shaun";

    private static PrintWriter stdout;
    private static PrintWriter stderr;
    private static IBurpExtenderCallbacks callbacks;
    private static DatabaseService dataBaseService;
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

    public static DatabaseService getDataBaseService(){
        return dataBaseService;
    }

    public static List<String> STATIC_FILE_EXT = new ArrayList<>();
    public static List<String> UNCEKCK_PATH = new ArrayList<>();
    public static List<String> UNCEKCK_DOMAINS = new ArrayList<>();

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
            if (tmpFile.exists()) {
                stdout.println("[+] Successfully loaded the configuration file finger-tmp.json");
            }else{
                stdout.println("[+] Successfully loaded the configuration file finger-important.json");
            }
            if (fingerprintRules != null && !fingerprintRules.isEmpty()){
                for (int i = 0 ; i < fingerprintRules.size(); i ++){
                    FingerPrintRule rule = fingerprintRules.get(i);
                    String type = rule.getType();
                    if (type.equals("白名单URL后缀")){
                        STATIC_FILE_EXT.addAll(rule.getKeyword());
                    } else if (type.equals("白名单路径")) {
                        UNCEKCK_PATH.addAll(rule.getKeyword());
                    } else if (type.equals("白名单域名")) {
                        UNCEKCK_DOMAINS.addAll(rule.getKeyword());
                    }
                }
            }
        } catch (IOException e) {
            stderr.println("[!] Failed to load the configuration file finger.json, because: " + e.getMessage());
        }

        dataBaseService = DatabaseService.getInstance();

        // 标签界面, ExtensionTab 构造时依赖 BurpExtender.callbacks, 所以这个必须放在下面
        BurpExtender.tags = new Tags(callbacks, extensionName);
        BurpExtender.iProxyScanner = new IProxyScanner();

        callbacks.registerProxyListener(iProxyScanner);
        callbacks.registerExtensionStateListener(this);

        BurpExtender.stdout.println(Utils.getBanner());
    }

    @Override
    public void extensionUnloaded() {
        // 扩展卸载时，立刻关闭线程池
        BurpExtender.getStdout().println("[+] Extension is being unloaded, cleaning up resources...");

        // 立刻关闭线程池
        if (iProxyScanner.executorService != null) {
            // 尝试立即关闭所有正在执行的任务
            List<Runnable> notExecutedTasks = iProxyScanner.executorService.shutdownNow();
            BurpExtender.getStdout().println("[+] 尝试停止所有正在执行的任务，未执行的任务数量：" + notExecutedTasks.size());
        }

        MailPanel.timer.stop();

        // 关闭数据库连接
        if (dataBaseService != null) {
            dataBaseService.closeConnection();
            BurpExtender.getStdout().println("[+] 断开数据连接成功.");
        }

        // 关闭计划任务
        IProxyScanner.shutdownMonitorExecutor();
        BurpExtender.getStdout().println("[+] 定时爬去任务断开成功.");
    }


}