package burp.model;

import burp.*;
import com.alibaba.fastjson2.JSON;
import com.alibaba.fastjson2.JSONObject;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;


/**
 * @author： shaun
 * @create： 2023/9/24 11:19
 * @description：指纹识别类
 */
public class Finger {

    public JSONObject fingerJson;

    public BurpExtender burpExtender;

    public IExtensionHelpers helpers;


    public Finger(){
        // 获取父类的操作类
//        this.burpExtender = burpExtender;
//        this.helpers = this.burpExtender.helpers;
        try{
            System.out.println(System.getProperty("user.dir"));
            String content = new String(Files.readAllBytes(Paths.get("/Volumes/Shaun-Data/开发/JavaProject/FingerPrint/src/main/java/burp/conf/finger.json")));
            this.fingerJson = JSON.parseObject(content);
        } catch (IOException e){
            e.printStackTrace();
        }
    }

    public void getFinger(){
    }

}


