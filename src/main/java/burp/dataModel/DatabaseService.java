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
import java.util.HashMap;
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
            // 注册 SQLite 驱动程序
            Driver driver = new org.sqlite.JDBC();
            DriverManager.registerDriver(driver);
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
                + "path_data_index INTEGER, \n"
                + "request_response_index INTEGER, \n"
                + "host TEXT, \n"
                + "port INTEGER, \n"
                + "protocol TEXT\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(sql);
            BurpExtender.getStdout().println("[+] create api data db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create api data db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }

        // 用来创建数据库requestResponse
        String requestsResponseSQL = "CREATE TABLE IF NOT EXISTS requests_response (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " url TEXT NOT NULL,\n"
                + " request BLOB, \n"
                + " response BLOB\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(requestsResponseSQL);
            BurpExtender.getStdout().println("[+] create requests response db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create requests response db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }

        // 用来创建数据库path_data
        String pathDataSQL = "CREATE TABLE IF NOT EXISTS path_data (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " url TEXT NOT NULL,\n"
                + " path TEXT NOT NULL,\n"
                + " having_important INTEGER,\n"
                + " status TEXT,\n"
                + " result TEXT,\n"
                + " path_data TEXT\n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(pathDataSQL);
            BurpExtender.getStdout().println("[+] create path data db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create path data db failed, because：");
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
        String sql = "INSERT INTO api_data(pid, url, status, is_js_find_url, method, path_number, having_important, result, time, list_status, describe, result_info, request_response_index, host, port, protocol) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)";
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
            pstmt.setInt(13, model.getRequestsResponseIndex());
            pstmt.setString(14, model.getiHttpService().getHost());
            pstmt.setInt(15, model.getiHttpService().getPort());
            pstmt.setString(16, model.getiHttpService().getProtocol());
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
                        rs.getInt("request_response_index"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getString("time"),
                        rs.getString("status"),
                        rs.getString("is_js_find_url"),
                        rs.getString("method"),
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
                + "request_response_index=?, "
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
            pstmt.setInt(11, model.getRequestsResponseIndex());
            pstmt.setString(12, model.getiHttpService().getHost());
            pstmt.setInt(13, model.getiHttpService().getPort());
            pstmt.setString(14, model.getiHttpService().getProtocol());

            // 最后设置匹配 URL 的参数
            pstmt.setString(15, model.getUrl());

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
                        rs.getInt("request_response_index"),
                        Utils.iHttpService(rs.getString("host"), rs.getInt("port"), rs.getString("protocol")),
                        rs.getString("time"),
                        rs.getString("status"),
                        rs.getString("is_js_find_url"),
                        rs.getString("method"),
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
            }
        } catch (SQLException ex) {
            BurpExtender.getStderr().println("关闭数据库连接时发生错误: ");
            ex.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized int insertOrUpdateRequestResponse(String url, byte[] request, byte[] response) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM requests_response WHERE url = ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, url);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String updateSql = "UPDATE requests_response SET request = ?, response = ? WHERE id = ?";
                try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                    updateStmt.setBytes(1, request);
                    updateStmt.setBytes(2, response);
                    updateStmt.setInt(3, generatedId);
                    updateStmt.executeUpdate();
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO requests_response(url, request, response) VALUES(?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, url);
                    insertStmt.setBytes(2, request);
                    insertStmt.setBytes(3, response);
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error inserting or updating requests_response table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }

    public synchronized Map<String, byte[]> selectRequestResponseById(int id) {
        String sql = "SELECT * FROM requests_response WHERE id = ?";
        Map<String, byte[]> requestResponse = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setInt(1, id);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    requestResponse = new HashMap<>();
                    requestResponse.put("request", rs.getBytes("request"));
                    requestResponse.put("response", rs.getBytes("response"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from requests_response table by ID: " + id);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return requestResponse;
    }


    // 方法以插入或更新 path_data 表
    // 方法以插入或更新 path_data 表
    public synchronized int insertOrUpdatePathData(String url, String path, boolean havingImportant, String status, String result, Map<String, Object> pathData) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id, status FROM path_data WHERE url = ? AND path = ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, url);
            checkStmt.setString(2, path);
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String currentStatus = rs.getString("status");
                // 如果记录存在，但状态不是200，则更新记录
                if (!"200".equals(currentStatus)) {
                    String updateSql = "UPDATE path_data SET having_important = ?, status = ?, result = ?, path_data = ? WHERE id = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                        updateStmt.setBoolean(1, havingImportant);
                        updateStmt.setString(2, status);
                        updateStmt.setString(3, result);
                        updateStmt.setString(4, serializePathData(pathData));
                        updateStmt.setInt(5, generatedId);
                        updateStmt.executeUpdate();
                    }
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO path_data(url, path, having_important, status,  result, path_data) VALUES(?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, url);
                    insertStmt.setString(2, path);
                    insertStmt.setBoolean(3, havingImportant);
                    insertStmt.setString(4, status);
                    insertStmt.setString(4, result);
                    insertStmt.setString(5, serializePathData(pathData));
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error inserting or updating path_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }


    public synchronized Map<String, Object> selectPathDataByUrlAndPath(String url, String path) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND path = ?";
        Map<String, Object> pathData = null;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, path);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    pathData = deserializePathData(rs.getString("path_data"));
                    // 你也可以将 having_important 和 result 字段添加到返回的 map 中
                    pathData.put("having_important", rs.getInt("having_important"));
                    pathData.put("result", rs.getString("result"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data table by URL and Path: " + url + ", " + path);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return pathData;
    }


    public synchronized List<Map<String, Object>> selectAllPathDataByUrl(String url) {
        String sql = "SELECT * FROM path_data WHERE url = ?";
        List<Map<String, Object>> allPathData = new ArrayList<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> pathData = new HashMap<>();
                    // 直接从结果集中获取字段值
                    pathData.put(rs.getString("path"), rs.getString("path_data"));
                    allPathData.add(pathData);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting all from path_data table by URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return allPathData;
    }

    public synchronized String getPathDataCountByUrl(String url) {
        String sql = "SELECT COUNT(*) FROM path_data WHERE url = ?";
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt(1); // 获取第一列的值，即 COUNT(*) 的结果
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error counting path_data entries for URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }

        return String.valueOf(count);
    }

    public synchronized List<Map<String, Object>> selectPathDataByConditions(
            String url, String path, String result, boolean isImportant, String statusCondition) {
        // 假设 statusCondition 是一个字符串，例如 "200"，用来匹配 status 字段
        String sql = "SELECT * FROM path_data WHERE url = ? AND path = ? AND result LIKE ? AND having_important = ? AND status = ?";
        List<Map<String, Object>> filteredPathData = new ArrayList<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, path);
            pstmt.setString(3, "%" + result + "%");
            pstmt.setInt(4, isImportant ? 1 : 0);
            pstmt.setString(5, statusCondition); // 添加 status 条件

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    Map<String, Object> pathData = new HashMap<>();
                    // 直接从结果集中获取字段值
                    pathData.put("id", rs.getInt("id"));
                    pathData.put("url", rs.getString("url"));
                    pathData.put("path", rs.getString("path"));
                    pathData.put("having_important", rs.getInt("having_important"));
                    pathData.put("status", rs.getString("status"));
                    pathData.put("result", rs.getString("result"));
                    // 假设 deserializePathData 方法可以处理 path_data 字段，将其转换成一个 Map
                    pathData.putAll(deserializePathData(rs.getString("path_data")));
                    filteredPathData.add(pathData);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data table with the given conditions: URL=" + url + ", Path=" + path + ", Result=" + result + ", IsImportant=" + isImportant + ", Status=" + statusCondition);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized List<Map<String, Object>> selectPathDataByUrlAndImportance(String url, boolean isImportant) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND having_important = ?";
        List<Map<String, Object>> filteredPathData = new ArrayList<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setInt(2, isImportant ? 1 : 0);

            try (ResultSet rs = pstmt.executeQuery()) {
                Map<String, Object> pathData = new HashMap<>();
                // 直接从结果集中获取字段值
                pathData.put(rs.getString("path"), rs.getString("path_data"));
                filteredPathData.add(pathData);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndImportance: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized List<Map<String, Object>> selectPathDataByUrlAndStatus(String url, String status) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND status = ?";
        List<Map<String, Object>> filteredPathData = new ArrayList<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, status);

            try (ResultSet rs = pstmt.executeQuery()) {
                Map<String, Object> pathData = new HashMap<>();
                // 直接从结果集中获取字段值
                pathData.put(rs.getString("path"), rs.getString("path_data"));
                filteredPathData.add(pathData);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndStatus: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized List<Map<String, Object>> selectPathDataByUrlAndResult(String url, String result) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND result LIKE ?";
        List<Map<String, Object>> filteredPathData = new ArrayList<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, "%" + result + "%");

            try (ResultSet rs = pstmt.executeQuery()) {
                Map<String, Object> pathData = new HashMap<>();
                // 直接从结果集中获取字段值
                pathData.put(rs.getString("path"), rs.getString("path_data"));
                filteredPathData.add(pathData);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndResult: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }








}
