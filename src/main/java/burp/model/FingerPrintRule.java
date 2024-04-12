package burp.model;

import java.util.List;

/**
 * @author： shaun
 * @create： 2024/3/2 17:49
 * @description：TODO
 */
public class FingerPrintRule {
    private String match;
    private String location;
    private List<String> keyword;
    private boolean isImportant;
    private String type;
    // 新添加的构造函数
    public FingerPrintRule(String type, boolean isImportant, String match, String location, List<String> keyword) {
        this.match = match;
        this.location = location;
        this.keyword = keyword;
        this.type = type;
        this.isImportant = isImportant;
    }
    public String getType(){return type;}
    public void setType(String type){this.type = type;}
    public boolean getIsImportant(){return isImportant;}
    public void setIsImportant(boolean isImportant){this.isImportant = isImportant;}
    public String getMatch() {
        return match;
    }

    public void setMatch(String match) {
        this.match = match;
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public List<String> getKeyword() {
        return keyword;
    }

    public void setKeyword(List<String> keyword) {
        this.keyword = keyword;
    }

    public String getInfo(){
        return "match: " + match + "\r\nlocation: " + location + "\r\nkeyword: " + keyword.toString();
    }
}
