package burp;

import java.io.PrintWriter;
import burp.ui.Tags;
import burp.ui.menu.Menu;

/**
 * @author： shaun
 * @create： 2023/9/8 23:58
 * @description：入口
 */
public class BurpExtender implements IBurpExtender, IExtensionStateListener
{
    private final String NAME = "FingerPrint";
    private final String VERSION = "1.0";

    public IBurpExtenderCallbacks callbacks;
    public IExtensionHelpers helpers;
    public PrintWriter stdout;
    public PrintWriter stderr;
    public Tags tags;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // keep a reference to our callbacks object
        this.callbacks = callbacks;

        // set our extension name
        this.callbacks.setExtensionName(NAME);

        // set helpers
        this.helpers = this.callbacks.getHelpers();

        // obtain our output and error streams
        this.stdout = new PrintWriter(this.callbacks.getStdout(), true);
        this.stderr = new PrintWriter(this.callbacks.getStderr(), true);

        // 注册menu
        this.callbacks.registerContextMenuFactory(new Menu(this));

        // 添加tag标签到ui
        tags = new Tags(callbacks, this.NAME);

        // 输出插件信息
        this.stdout.println(this.extenderInfo());
    }


    public String extenderInfo() {
        String logo = " ____             _             ____                  \n/ ___| _ __  _ __(_)_ __   __ _/ ___|  ___ __ _ _ __  \n\\___ \\| '_ \\| '__| | '_ \\ / _` \\___ \\ / __/ _` | '_ \\ \n ___) | |_) | |  | | | | | (_| |___) | (_| (_| | | | |\n|____/| .__/|_|  |_|_| |_|\\__, |____/ \\___\\__,_|_| |_|\n      |_|                 |___/                       \n";
        String author = "by Shaun";
        String line = "\n\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t\t";
        String payloads = "BurpSuite被动指纹扫描并进行OA弱口令爆破插件";
        return logo + line + "V" + this.VERSION + line + author + "\n" + payloads;
    }

    @Override
    public void extensionUnloaded() {

    }
}