package burp.util;

import burp.BurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IHttpService;

import java.io.File;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author： shaun
 * @create： 2024/2/18 21:11
 * @description：TODO
 */
public class Utils {
    public final static List<String> STATIC_FILE_EXT = List.of(
            "vue",
            "ts",
            "min",
            "png",
            "jpg",
            "jpeg",
            "gif",
            "bmp",
            "css",
            "woff",
            "woff2",
            "ttf",
            "otf",
            "ttc",
            "svg",
            "psd",
            "exe",
            "zip",
            "rar",
            "7z",
            "msi",
            "tar",
            "gz",
            "mp3",
            "mp4",
            "mkv",
            "swf",
            "iso",
            "ico",
            "gif"
    );

    // 对以下URl提取URL
    public final static  List<String> STATIC_URl_EXT = List.of(
            "js",
            "ppt",
            "pptx",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "cvs",
            "php",
            "jsp",
            "asp",
            "aspx"
    );

    // 不对下面URL进行指纹识别
    public final static  List<String> UNCEKCK_DOMAINS = List.of(
            ".baidu.com",
            ".google.com",
            ".bing.com",
            ".yahoo.com",
            ".aliyun.com",
            ".alibaba.com"
    );

    public final static List<String> UNCEKCK_PATH = List.of(
            "zh-CN",
            "/static/",
            "&",
            "=",
            "~",
            ".css",
            ",",
            "??",
            ".",
            "<",
            ">",
            "[",
            "]",
            "(",
            ")",
            "}",
            "{",
            "@"
    );


    public static boolean isStaticPathByPath(String urlPath){
        // 使用正则表达式匹配中文字符的模式
        String chinesePattern = "[\u4E00-\u9FA5]";
        // 判断字符串是否包含中文字符
        if (urlPath.matches(".*" + chinesePattern + ".*")){
            return true;
        }

        for (String key : BurpExtender.UNCEKCK_PATH){
            if (urlPath.contains(key)){
                return true;
            }
        }
        return false;
    }

    public static boolean isStaticFile(String url) {
        for (String ext : BurpExtender.STATIC_FILE_EXT) {
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    public  static boolean isGetUrlExt(String url){

        for (String ext : STATIC_URl_EXT){
            if (ext.equalsIgnoreCase(Utils.getUriExt(url))) return true;
        }
        return false;
    }

    public static boolean isWhiteDomain(String url){
        for (String uncheckDomains : BurpExtender.UNCEKCK_DOMAINS){
            if (url.contains(uncheckDomains)) return true;
        }
        return false;
    }

    public static String getPathFromUrl(String url) {
        try {
            URL urlObj = new URL(url);
            String path = urlObj.getPath();

            // 确保路径不以斜杠开头
            if (path.isEmpty() || path.equals("/")) {
                path = "/";
            }else{
                path = path.replaceAll("/+$", "").replaceAll("\\?+$", "");
            }
            return path;
        } catch (MalformedURLException e) {
            e.printStackTrace(BurpExtender.getStderr());
            return "/";
        }
    }

    public static String getUriExt(String url) {
        String pureUrl = url.substring(0, url.contains("?") ? url.indexOf("?") : url.length());
        return (pureUrl.lastIndexOf(".") > -1 ? pureUrl.substring(pureUrl.lastIndexOf(".") + 1) : "").toLowerCase();
    }

    public static List<String> extractUrlsFromHtml(String uri, String html) {
        // 使用正则表达式提取文本内容中的 URL
        List<String> urlList = new ArrayList<String>();
        if (!html.contains("http")){
            return urlList;
        }
        Pattern pattern = Pattern.compile(
                "(http|https)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");
        Matcher matcher = pattern.matcher(html);
        while (matcher.find()) {
            String url = matcher.group();
            if (!url.contains("http") && url.startsWith("/")) {
                try {
                    URI baseUri = new URI(uri);
                    url = baseUri.resolve(url).toString();
                } catch (URISyntaxException e) {
                    continue;
                }
            }
            try{
                String subdomain = (new URL(uri)).getHost() ;
                String domain = (new URL(url)).getHost();
                if (!subdomain.equalsIgnoreCase(domain)){
                    continue;
                }
            } catch (Exception e) {
                continue;
            }
            if (!isStaticFile(url)  && !isStaticPathByPath(getPathFromUrl(url)) && !isWhiteDomain(url)){
                urlList.add(url);
            }
        }
        return urlList;
    }

    public static List<String> findUrl(URL url, String js)
    {
        // 方式一：原有的正则提取js中的url的逻辑
        String pattern_raw = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')";
        Pattern r = Pattern.compile(pattern_raw);
        Matcher m = r.matcher(js);
        int matcher_start = 0;
        List<String> ex_urls = new ArrayList<String>();
        while (m.find(matcher_start)){
            String matchGroup = m.group(1);
            if (matchGroup != null){
                if (!isStaticPathByPath(matchGroup)){
                    ex_urls.add(matchGroup.replaceAll("\"","").replaceAll("'","").replaceAll("\n","").replaceAll("\t","").trim());
                }
            }
            matcher_start = m.end();
        }
        // 方式二：
        String regex = "\"(/[^\"\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*)\"|'(/[^'\\\\s,@\\[\\]\\(\\)<>{}，%\\+：:/-]*?)'";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher_result = pattern.matcher(js);
        while (matcher_result.find()){
            // 检查第一个捕获组
            String group1 = matcher_result.group(1);
            if (group1 != null) {
                if (!isStaticPathByPath(group1)){
                    ex_urls.add(group1.replaceAll("\"", "").replaceAll("\n", "").replaceAll("\t", "").trim());
                }
            }
            // 检查第二个捕获组
            String group2 = matcher_result.group(2);
            if (group2 != null) {
                if (!isStaticPathByPath(group2)){
                    ex_urls.add(group2.replaceAll("'", "").replaceAll("\n", "").replaceAll("\t", "").trim());
                }
            }
        }

        LinkedHashSet<String> hashSet = new LinkedHashSet<>(ex_urls);
        ArrayList<String> temp_urls = new ArrayList<>(hashSet);
        List<String> all_urls = new ArrayList<>();
        for(String temp_url:temp_urls){
            all_urls.add(process_url(url, temp_url));
        }
        List<String> result = new ArrayList<String>();
        for(String singerurl : all_urls){
            String domain = url.getHost();
            try {
                URL subURL = new URL(singerurl);
                String subdomain = subURL.getHost();
                if(subdomain.equalsIgnoreCase(domain) && !isStaticFile(singerurl)){
                    result.add(singerurl);
                }

            } catch (Exception e) {
                BurpExtender.getStderr().println("findUrl error: " + singerurl);
                e.printStackTrace(BurpExtender.getStderr());
            }

        }
        return  result;
    }

    public static String process_url(URL url, String re_URL) {
        String black_url = "javascript:";
        String ab_URL = url.getHost() + ":"+ url.getPort();
        String host_URL = url.getProtocol();
        String result = "";
        if (re_URL.length() < 4) {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + "//" + ab_URL + re_URL.substring(1);
            } else if (!re_URL.startsWith("//")) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            }
        } else {
            if (re_URL.startsWith("//")) {
                result = host_URL + ":" + re_URL;
            } else if (re_URL.startsWith("http")) {
                result = re_URL;
            } else if (!re_URL.startsWith("//") && !re_URL.contains(black_url)) {
                if (re_URL.startsWith("/")) {
                    result = host_URL + "://" + ab_URL + re_URL;
                } else {
                    if (re_URL.startsWith(".")) {
                        if (re_URL.startsWith("..")) {
                            result = host_URL + "://" + ab_URL + re_URL.substring(2);
                        } else {
                            result = host_URL + "://" + ab_URL + re_URL.substring(1);
                        }
                    } else {
                        result = host_URL + "://" + ab_URL + "/" + re_URL;
                    }

                }

            } else {
                result = url.toString();
            }
        }
        return result;

    }

    public static String getUriFromUrl(String urlString)  {
        // 匹配 "https://xxx/" 或 "http://xxx/" 或 "https://xxx" 或 "http://xxx" 的正则表达式
        String regex = "(https?://[^/]+/?)(?=/|$)";
        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(urlString);

        if (matcher.find()) {
            return matcher.group(1).replaceAll("/+$", "").replaceAll("\\?+$", "").
                    replaceAll(":443$", "").replaceAll(":80$", "");
        }
        else{
            return urlString.replaceAll("/+$", "").replaceAll("\\?+$", "").
                    replaceAll(":443$", "").replaceAll(":80$", "");
        }
    }

    public static String extractBaseUrl(String fullUrl) {
        try {
            URL url = new URL(fullUrl);
            // 构造基本URL，不包含查询参数
            return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getPath()).toString();
        } catch (MalformedURLException e) {
            BurpExtender.getStdout().println("URL解析报错： " + fullUrl + ":" + e.getMessage()); // 打印异常信息
            return "-"; // 或者根据你的需求返回适当的值
        }
    }

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

    /**
     * 获取-插件运行路径
     *
     * @return
     */
    public static String getExtensionFilePath(IBurpExtenderCallbacks callbacks) {
        String path = "";
        Integer lastIndex = callbacks.getExtensionFilename().lastIndexOf(File.separator);
        path = callbacks.getExtensionFilename().substring(0, lastIndex) + File.separator;
        return path;
    }

    public static IHttpService iHttpService(String host, int port, String protocol){
        return new IHttpService() {
            @Override
            public String getHost() {
                return host;
            }

            @Override
            public int getPort() {
                return port;
            }

            @Override
            public String getProtocol() {
                return protocol;
            }
        };
    }


    // 转换ArrayList<Byte>为byte[]

    public static void main(String[] args) {

        System.out.println(getPathFromUrl("http://www.baidu.com"));
    }
}
