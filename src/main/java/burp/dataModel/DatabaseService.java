package burp.dataModel;

import java.io.File;
import java.nio.file.Paths;
import java.sql.*;

import burp.BurpExtender;
import burp.IHttpService;
import burp.util.Utils;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import java.lang.reflect.Type;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;

public class DatabaseService {

    private static final String CONNECTION_STRING = "jdbc:sqlite:" + Paths.get(Utils.getExtensionFilePath(BurpExtender.getCallbacks()), "BurpApiFinder.db").toAbsolutePath().toString();;
    private Gson gson = new Gson();

    private static DatabaseService instance;
    private Connection connection;

    private DatabaseService() {
        initializeConnection();
        initializeDatabase();
    }

    public static synchronized DatabaseService getInstance() {
        if (instance == null) {
            instance = new DatabaseService();
        }
        return instance;
    }

    private Connection connect() throws SQLException {
        return DriverManager.getConnection(CONNECTION_STRING);
    }

    private void initializeConnection() {
        try {
            Class.forName("org.sqlite.JDBC");
            connection = DriverManager.getConnection(CONNECTION_STRING);
            // Enable foreign key support
            connection.createStatement().execute("PRAGMA foreign_keys = ON");
            BurpExtender.getStdout().println("[+] load db connect success~ ");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] load db connect Fail, befalse:");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    private synchronized void initializeDatabase() {
        // 用于创建表的SQL语句
        String sql = "CREATE TABLE IF NOT EXISTS api_data (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " pid INTEGER, \n"
                + " url TEXT NOT NULL,\n"
                + " status TEXT,\n"
                + " is_js_find_url TEXT,\n"
                + " method TEXT NOT NULL,\n"
                + " path_number TEXT,\n"
                + " having_important INTEGER,\n"
                + " result TEXT,\n"
                + " time TEXT,\n"
                + " list_status TEXT,\n"
                + " describe TEXT,\n"
                + " result_info TEXT,\n"
                + "path_data TEXT, \n"
                + "request BLOB, \n"
                + "response BLOB, \n"
                + "host TEXT, \n"
                + "port INTEGER, \n"
                + "protocol TEXT\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            BurpExtender.getStdout().println("[+] create db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public Connection getConnection() {
        return connection;
    }


    private Map<String, Object> deserializePathData(String json) {
        Type type = new TypeToken<Map<String, Object>>(){}.getType();
        return gson.fromJson(json, type);
    }

    // Method to serialize Map<String, Object>
    private String serializePathData(Map<String, Object> pathData) {
        return gson.toJson(pathData);
    }

    // Method to insert a new ApiDataModel
    public synchronized void insertApiDataModel(ApiDataModel model) {
        String sql = "INSERT INTO api_data(pid, url, status, is_js_find_url, method, path_number, having_important, result, time, list_status, describe, result_info, path_data, request, response, host, port, protocol) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, model.getId());
            pstmt.setString(2, model.getUrl());
            pstmt.setString(3, model.getStatus());
            pstmt.setString(4, model.getIsJsFindUrl());
            pstmt.setString(5, model.getMethod());
            pstmt.setString(6, model.getPATHNumber());
            pstmt.setBoolean(7, model.getHavingImportant());
            pstmt.setString(8, model.getResult());
            pstmt.setString(9, model.getTime());
            pstmt.setString(10, model.getListStatus());
            pstmt.setString(11, model.getDescribe());
            pstmt.setString(12, model.getResultInfo());
            pstmt.setString(13, serializePathData(model.getPathData()));
            pstmt.setBytes(14, model.getRequestsData());
            pstmt.setBytes(15, model.getResponseData());
            pstmt.setString(16, model.getiHttpService().getHost());
            pstmt.setInt(17, model.getiHttpService().getPort());
            pstmt.setString(18, model.getiHttpService().getProtocol());
            pstmt.executeUpdate();
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]插入数据库报错： " + model);
            e.printStackTrace(BurpExtender.getStderr());
        }

    }

    public synchronized boolean isExistApiDataModelByUri(String uri) {
        String sql = "SELECT * FROM api_data WHERE url = ?";
        ApiDataModel model = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, uri);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                return true;
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]查询数据库错误: URI=" + uri);
            e.printStackTrace(BurpExtender.getStderr());
        }

        return false;
    }

    // Method to select an ApiDataModel by uri
    public synchronized ApiDataModel selectApiDataModelByUri(String uri) {
        String sql = "SELECT * FROM api_data WHERE url = ?";
        ApiDataModel model = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, uri);
            ResultSet rs = pstmt.executeQuery();

            if (rs.next()) {
                model = new ApiDataModel(
                        rs.getString("list_status"),
                        rs.getString("id"),
                        rs.getString("url"),
                        rs.getString("path_number"),
                        rs.getBoolean("having_important"),
                        rs.getString("result"),
                        rs.getBytes("request"),
                        rs.getBytes("response"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getString("time"),
                        rs.getString("status"),
                        rs.getString("is_js_find_url"),
                        rs.getString("method"),
                        deserializePathData(rs.getString("path_data")), // 使用你已经定义的方法反序列化路径数据
                        rs.getString("describe"),
                        rs.getString("result_info")
                );
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]查询数据库错误: URI=" + uri);
            e.printStackTrace(BurpExtender.getStderr());
        }

        return model;
    }


    // Method to update an ApiDataModel
    public synchronized void updateApiDataModelByUrl(ApiDataModel model) {
        String sql = "UPDATE api_data SET "
                + "pid=?, "
                + "status=?, "
                + "is_js_find_url=?, "
                + "method=?, "
                + "path_number=?, "
                + "having_important=?, "
                + "result=?, "
                + "time=?, "
                + "describe=?, "
                + "result_info=?, "
                + "path_data=?, "
                + "request=?, "
                + "response=?, "
                + "host=?, "
                + "port=?, "
                + "protocol=? "
                + "WHERE url=?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置更新语句中的参数
            pstmt.setString(1, model.getId());
            pstmt.setString(2, model.getStatus());
            pstmt.setString(3, model.getIsJsFindUrl());
            pstmt.setString(4, model.getMethod());
            pstmt.setString(5, model.getPATHNumber());
            pstmt.setBoolean(6, model.getHavingImportant());
            pstmt.setString(7, model.getResult());
            pstmt.setString(8, model.getTime());
            pstmt.setString(9, model.getDescribe());
            pstmt.setString(10, model.getResultInfo());
            pstmt.setString(11, serializePathData(model.getPathData())); // 假设你有这个方法来序列化路径数据为 String
            pstmt.setBytes(12, model.getRequestsData());
            pstmt.setBytes(13, model.getResponseData());
            pstmt.setString(14, model.getiHttpService().getHost());
            pstmt.setInt(15, model.getiHttpService().getPort());
            pstmt.setString(16, model.getiHttpService().getProtocol());

            // 最后设置匹配 URL 的参数
            pstmt.setString(17, model.getUrl());

            // 执行更新
            pstmt.executeUpdate();
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]更新数据库报错： URL=" + model.getUrl());
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    // Method to update the list_status by URL
    public synchronized void updateListStatusByUrl(String url, String newListStatus) {
        String sql = "UPDATE api_data SET list_status = ? WHERE url = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置新的 list_status 值和匹配的 URL
            pstmt.setString(1, newListStatus);
            pstmt.setString(2, url);

            // 执行更新
            pstmt.executeUpdate();

        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error updating list_status in the database for URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized void updateListStatus(String newListStatus) {
        String sql = "UPDATE api_data SET list_status = ?";

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置新的 list_status 值和匹配的 URL
            pstmt.setString(1, newListStatus);

            pstmt.executeUpdate();

        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error updating list_status in the database for ALLURL");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }


    // 从数据库获取所有ApiDataModels
    public synchronized List<ApiDataModel> getAllApiDataModels() {
        List<ApiDataModel> apiDataModels = new ArrayList<>();
        String sql = "SELECT * FROM api_data";

        try (Connection conn = this.connect();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                // 根据你的数据库结构和ApiDataModel构造函数创建ApiDataModel对象
                ApiDataModel model = new ApiDataModel(
                        rs.getString("list_status"),
                        rs.getString("id"),
                        rs.getString("url"),
                        rs.getString("path_number"),
                        rs.getBoolean("having_important"),
                        rs.getString("result"),
                        rs.getBytes("request"),
                        rs.getBytes("response"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getString("time"),
                        rs.getString("status"),
                        rs.getString("is_js_find_url"),
                        rs.getString("method"),
                        deserializePathData(rs.getString("path_data")), // 使用你已经定义的方法反序列化路径数据
                        rs.getString("describe"),
                        rs.getString("result_info")
                );
                apiDataModels.add(model);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]查询所有数据库报错，详细如下");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return apiDataModels;
    }

    public synchronized int getApiDataCount() {
        String sql = "SELECT COUNT(*) FROM api_data"; // 确保表名与你的数据库匹配
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {

            if (rs.next()) {
                count = rs.getInt(1); // 获取第一列的值，即 COUNT(*) 的结果
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error getting the count of api_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return count;
    }

    public synchronized void clearApiDataTable() {
        String sql = "DELETE FROM api_data"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] api_data table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing api_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    // 关闭数据库连接的方法
    public void closeConnection() {
        try {
            if (this.connection != null && !this.connection.isClosed()) {
                this.connection.close();
                System.out.println("数据库连接已关闭。");
            }
        } catch (SQLException ex) {
            System.err.println("关闭数据库连接时发生错误: " + ex.getMessage());
        }
    }





}
