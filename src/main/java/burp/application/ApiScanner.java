package burp.application;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import burp.application.apitypes.ApiType;
import burp.util.CommonUtils;

import java.util.ArrayList;
import java.util.function.BiFunction;

public class ApiScanner {
    private final ArrayList<BiFunction<IHttpRequestResponse, Boolean, ApiType>> apiTypeConstructors = new ArrayList<>();

    public ApiScanner() {
    }

    public ArrayList<ApiType> detect(IHttpRequestResponse baseRequestResponse, boolean isPassive) {
        ArrayList<ApiType> apiTypes = new ArrayList<>();
        for (BiFunction<IHttpRequestResponse, Boolean, ApiType> apiTypeConstructor : apiTypeConstructors) {
            try {
                ApiType apiType = apiTypeConstructor.apply(baseRequestResponse, isPassive);
                if (apiType.isFingerprintMatch()) {
                    apiTypes.add(apiType);
                }
            } catch (Exception e) {
                BurpExtender.getStderr().println(CommonUtils.exceptionToString(e));
            }
        }
        return apiTypes;
    }
}
