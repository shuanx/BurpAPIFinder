package burp.dataModel;

import burp.IHttpRequestResponse;
import burp.IHttpService;

import java.util.Map;

/**
 * @author： shaun
 * @create： 2024/4/9 22:12
 * @description：TODO
 */

public class ApiDataModel {
    final String id;
    final String url;
    IHttpService iHttpService;
    String status;
    final String isJsFindUrl;
    final String method;
    String pathNumber;
    Boolean havingImportant;
    String result ;
    String time;
    String listStatus;
    String describe;
    String resultInfo;
    int requestsResponseIndex;



    public ApiDataModel(String listStatus, String id, String url, String pathNumber, Boolean havingImportant, String result, int requestsResponseIndex, IHttpService iHttpService, String time, String status, String isJsFindUrl, String method, String describe, String resultInfo) {
        this.listStatus = listStatus;
        this.id = id;
        this.url = url;
        this.pathNumber = pathNumber;
        this.havingImportant = havingImportant;
        this.result = result;
        this.requestsResponseIndex = requestsResponseIndex;
        this.iHttpService = iHttpService;
        this.time = time;
        this.status = status;
        this.isJsFindUrl = isJsFindUrl;
        this.method = method;
        this.describe = describe;
        this.resultInfo = resultInfo;
    }


    public String getDescribe() {
        return describe;
    }

    public void setDescribe(String describe) {
        this.describe = describe;
    }

    public void setResultInfo(String resultInfo) {
        this.resultInfo = resultInfo;
    }

    public String getResultInfo() {
        return resultInfo;
    }

    public int getRequestsResponseIndex(){
        return this.requestsResponseIndex;
    }

    public IHttpService getiHttpService(){
        return this.iHttpService;
    }

    public String getListStatus(){
        return this.listStatus;
    }

    public void setListStatus(String listStatus){
        this.listStatus = listStatus;
    }


    public String getId(){
        return this.id;
    }

    public String getUrl(){
        return this.url;
    }

    public String getPATHNumber(){
        return this.pathNumber;
    }

    public void setPathNumber(String pathNumber){
        this.pathNumber = pathNumber;
    }

    public String getMethod(){
        return this.method;
    }

    public String getStatus(){
        return this.status;
    }

    public void setStatus(String status){
        this.status = status;
    }

    public String getIsJsFindUrl(){
        return this.isJsFindUrl;
    }

    public Boolean getHavingImportant(){
        return this.havingImportant;
    }

    public void setHavingImportant(Boolean havingImportant){
        this.havingImportant = havingImportant;
    }

    public String getResult(){
        return this.result;
    }

    public void setResult(String result){
        this.result = result;
    }

    public String getTime(){
        return this.time;
    }

    public void setTime(String time){
        this.time = time;
    }

}
