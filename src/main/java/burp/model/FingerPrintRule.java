package burp.model;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * @author： shaun
 * @create： 2024/3/2 17:49
 * @description：TODO
 */
public class FingerPrintRule {
    private String match;
    private String location;
    private String describe;
    private List<String> keyword;
    private boolean isImportant;
    private String type;
    private boolean isOpen;
    private String accuracy;
    // 新添加的构造函数
    public FingerPrintRule(String type, String describe, boolean isImportant, String match, String location, List<String> keyword, boolean isOpen, String accuracy) {
        this.match = match;
        this.describe = describe;
        this.location = location;
        this.keyword = keyword;
        this.type = type;
        this.isImportant = isImportant;
        this.isOpen = isOpen;
        this.accuracy = accuracy;
    }
    public boolean getIsOpen(){
        return isOpen;
    }
    public void setOpen(boolean isOpen){
        this.isOpen = isOpen;
    }
    public String getAccuracy(){
        return accuracy;
    }
    public void setAccuracy(String accuracy){
        this.accuracy = accuracy;
    }
    public String getDescribe(){return describe;}
    public void setDescribe(String describe){
        this.describe = describe;
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
        return "Time: " + new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()) + "\r\nmatch: " + match + "\r\nType: " + type + "\r\naccuracy: " + accuracy + "\r\ndescribe: " + describe +  "\r\nlocation: " + location + "\r\nkeyword: " + keyword.toString() + "\r\n";
    }
}
