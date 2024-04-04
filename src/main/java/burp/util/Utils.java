package burp.util;

import burp.BurpExtender;

/**
 * @author： shaun
 * @create： 2024/2/18 21:11
 * @description：TODO
 */
public class Utils {
    public static String getBanner(){
        String bannerInfo =
                "[+] " + BurpExtender.extensionName + " is loaded\n"
                        + "[+] ^_^            ^_^\n"
                        + "[+] #####################################\n"
                        + "[+] " + BurpExtender.extensionName + " " + BurpExtender.version +"\n"
                        + "[+] Author: " + BurpExtender.author + "\n"
                        + "[+] ####################################\n"
                        + "[+] Please enjoy it!\n";
        return bannerInfo;
    }
}
