package burp.Wrapper;

import burp.model.FingerPrintRule;

import java.util.List;

/**
 * @author： shaun
 * @create： 2024/3/2 17:51
 * @description：TODO
 */
public class FingerPrintRulesWrapper {
    private List<FingerPrintRule> fingerprint;

    public List<FingerPrintRule> getFingerprint() {
        return fingerprint;
    }

    public void setFingerprint(List<FingerPrintRule> fingerprint) {
        this.fingerprint = fingerprint;
    }

}
