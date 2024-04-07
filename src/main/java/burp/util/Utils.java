package burp.util;

import burp.BurpExtender;

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
    public final static String[] STATIC_FILE_EXT = new String[]{
            "png",
            "jpg",
            "jpeg",
            "gif",
            "pdf",
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
    };

    // 对以下URl提取URL
    public final static String[] STATIC_URl_EXT = new String[]{
            "js",
            "ppt",
            "pptx",
            "doc",
            "docx",
            "xls",
            "xlsx",
            "cvs"
    };

    // 不对下面URL进行指纹识别
    public final static  String[] UNCEKCK_DOMAINS = new String[]{
            ".baidu.com",
            ".google.com",
            ".bing.com",
            ".yahoo.com",
            ".aliyun.com",
            ".alibaba.com"
    };

    public final static String[] UNCEKCK_PATH = new String[]{
            "zh-CN",
            "/static/",
            "&",
            "="
    };

    public static boolean isStaticPath(String url){
        String path = getPathFromUrl(url);
        for (String key : UNCEKCK_PATH){
            if (path.contains(key)){
                return true;
            }
        }
        return false;
    }

    public static boolean isStaticFile(String url) {
        for (String ext : STATIC_FILE_EXT) {
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
        for (String uncheckDomains : UNCEKCK_DOMAINS){
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
            e.printStackTrace();
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
        Pattern pattern = Pattern.compile(
                "(http|https|ftp)://([\\w_-]+(?:(?:\\.[\\w_-]+)+))([\\w.,@?^=%&:/~+#-]*[\\w@?^=%&/~+#-])?");
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
                String subdomain = (new URL(uri)).getHost() + ":" + (new URL(uri)).getPort();
                String domain = (new URL(url)).getHost() + ":" + (new URL(uri)).getPort();
                if (!subdomain.equalsIgnoreCase(domain)){
                    continue;
                }
            } catch (Exception e) {
                continue;
            }

            if (!isStaticFile(url) && !url.endsWith(".js") && !url.contains(".js?") && !isStaticPath(url)){
                urlList.add(url);
            }
        }
        return urlList;
    }

    public static List<String> findUrl(URL url, String js)
    {
        String pattern_raw = "(?:\"|')(((?:[a-zA-Z]{1,10}://|//)[^\"'/]{1,}\\.[a-zA-Z]{2,}[^\"']{0,})|((?:/|\\.\\./|\\./)[^\"'><,;|*()(%%$^/\\\\\\[\\]][^\"'><,;|()]{1,})|([a-zA-Z0-9_\\-/]{1,}/[a-zA-Z0-9_\\-/]{1,}\\.(?:[a-zA-Z]{1,4}|action)(?:[\\?|/|;][^\"|']{0,}|))|([a-zA-Z0-9_\\-]{1,}\\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:\\?[^\"|']{0,}|)))(?:\"|')";
        Pattern r = Pattern.compile(pattern_raw);
        Matcher m = r.matcher(js);
        int matcher_start = 0;
        List<String> ex_urls = new ArrayList<String>();
        while (m.find(matcher_start)){
            ex_urls.add(m.group(1).replaceAll("\"","").replaceAll("'","").replaceAll("\n","").replaceAll("\t","").trim());
            matcher_start = m.end();
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
                if(!subdomain.equalsIgnoreCase(domain) && !isStaticFile(singerurl) && !getPathFromUrl(singerurl).endsWith(".js") && !singerurl.contains(".js?") && !isStaticPath(singerurl)){
                    result.add(singerurl);
                }

            } catch (Exception e) {
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


    public static void main(String[] args) {

        System.out.println(getPathFromUrl("http://www.baidu.com"));
    }
}
