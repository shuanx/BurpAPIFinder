package burp.model;

import com.alibaba.fastjson2.JSONObject;
import junit.framework.TestCase;
import org.junit.Test;
import org.junit.Assert;

/**
 * @author： shaun
 * @create： 2023/9/24 14:26
 * @description：TODO
 */
public class FingerTest  {
    @Test
    public void testGetFinger() {
        Finger finger = new Finger();

        JSONObject fingerJson = finger.fingerJson;
        System.out.println(fingerJson.get("fingerprint"));
        Assert.assertNotNull(fingerJson);
        Assert.assertTrue(fingerJson.containsKey("fingerprint"));
    }


}