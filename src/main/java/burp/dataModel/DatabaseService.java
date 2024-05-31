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
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.List;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Set;
import java.util.Arrays;

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
                + " request_response_index INTEGER, \n"
                + " host TEXT, \n"
                + " port INTEGER, \n"
                + " protocol TEXT, \n"
                + " jsMatchTime TEXT DEFAULT '-', \n"
                + " jsMatchNumber INTEGER DEFAULT 0"
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

        // 用来需要敏感信息提取的url
        String originalDataSQL = "CREATE TABLE IF NOT EXISTS original_data (\n"
                + " id INTEGER PRIMARY KEY AUTOINCREMENT,\n"
                + " pid TEXT, \n"
                + " url TEXT NOT NULL,\n"
                + " method TEXT, \n"
                + " status TEXT, \n"
                + " run_status TEXT, \n"
                + " request_response_index INTEGER, \n"
                + " host TEXT, \n"
                + " port INTEGER, \n"
                + " protocol TEXT \n"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(originalDataSQL);
            BurpExtender.getStdout().println("[+] create original data db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create original data failed, because：");
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
                + " describe TEXT,\n"
                + " path_data TEXT,\n"
                + " method TEXT,\n"
                + " isJsFindUrl TEXT,\n"
                + " jsFindUrl TEXT, \n"
                + " mayNewParentPath TEXT DEFAULT '', \n"
                + " isTryNewParentPath INTEGER DEFAULT 0"
                + ");";

        try (Statement stmt = connection.createStatement()) {
            stmt.execute(pathDataSQL);
            BurpExtender.getStdout().println("[+] create path data db success~");
        } catch (Exception e) {
            BurpExtender.getStderr().println("[!] create path data db failed, because：");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    private Map<String, Object> deserializePathData(String json) {
        Type type = new TypeToken<Map<String, Object>>(){}.getType();
        return gson.fromJson(json, type);
    }

    // Method to serialize Map<String, Object>
    private String serializePathData(Map<String, Object> pathData) {
        return gson.toJson(pathData);
    }



    public synchronized String fetchAndMarkApiData() {
        // 首先选取一条记录的ID
        String selectSQL = "SELECT * FROM api_data WHERE ( strftime('%s', 'now', 'localtime') - strftime('%s', replace(time, '/', '-')) > 600  AND jsMatchTime = '-') OR strftime('%s', 'now', 'localtime') - strftime('%s', replace(jsMatchTime, '/', '-')) > 3000 LIMIT 1";
        String updateSQL = "UPDATE api_data SET jsMatchTime = ? , jsMatchNumber = ? WHERE id = ?";

        try (PreparedStatement selectStatement = connection.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next()) {
                int selectedId = rs.getInt("id");
                String url = rs.getString("url");
                if (!rs.getString("jsMatchTime").equals('-') && (rs.getInt("jsMatchNumber") == getPathDataCountByUrlAndIsJsFindUrlAndStatus(url))){
                    return "";
                }

                try (PreparedStatement updateStatement = connection.prepareStatement(updateSQL)) {
                    updateStatement.setString(1, new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date()));
                    updateStatement.setInt(2, getPathDataCountByUrlAndIsJsFindUrlAndStatus(url));
                    updateStatement.setInt(3, selectedId);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        return url;
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error fetchAndMarkSinglePathAsCrawling: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return "";
    }


    public synchronized int insertOrUpdateOriginalData(String url, int pid, String status, String method, int requestResponseIndex, IHttpService iHttpService) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id FROM original_data WHERE url = ? AND method = ? AND host = ? AND port = ? AND protocol = ? AND run_status != ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, url);
            checkStmt.setString(2, method);
            checkStmt.setString(3, iHttpService.getHost());
            checkStmt.setInt(4, iHttpService.getPort());
            checkStmt.setString(5, iHttpService.getProtocol());
            checkStmt.setString(6, "等待解析");
            ResultSet rs = checkStmt.executeQuery();
            if (!rs.next()) {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO original_data(url, method, status, request_response_index, host, port, protocol, pid, run_status) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, url);
                    insertStmt.setString(2, method);
                    insertStmt.setString(3, status);
                    insertStmt.setInt(4, requestResponseIndex);
                    insertStmt.setString(5, iHttpService.getHost());
                    insertStmt.setInt(6, iHttpService.getPort());
                    insertStmt.setString(7, iHttpService.getProtocol());
                    insertStmt.setString(8, String.valueOf(pid));
                    insertStmt.setString(9, "等待解析");
                    insertStmt.executeUpdate();

                    // 获取生成的键值
                    try (ResultSet generatedKeys = insertStmt.getGeneratedKeys()) {
                        if (generatedKeys.next()) {
                            generatedId = generatedKeys.getInt(1); // 获取生成的ID
                        }
                    }
                }
            }
        } catch (SQLException e) {
            BurpExtender.getStderr().println("[-] Error inserting or updating original_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return generatedId; // 返回ID值，无论是更新还是插入
    }



    public synchronized Map<String, Object> fetchAndMarkOriginalDataAsCrawling() {
        // 事务开启
        Map<String, Object> filteredPathData = new HashMap<>();

        // 首先选取一条记录的ID
        String selectSQL = "SELECT * FROM original_data WHERE run_status = '等待解析' LIMIT 1;";
        String updateSQL = "UPDATE original_data SET run_status = '解析中' WHERE id = ?;";

        try (PreparedStatement selectStatement = connection.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next()) {
                int selectedId = rs.getInt("id");


                try (PreparedStatement updateStatement = connection.prepareStatement(updateSQL)) {
                    updateStatement.setInt(1, selectedId);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        filteredPathData.put("id", rs.getInt("id"));
                        filteredPathData.put("method", rs.getString("method"));
                        filteredPathData.put("host", rs.getString("host"));
                        filteredPathData.put("port", rs.getInt("port"));
                        filteredPathData.put("protocol", rs.getString("protocol"));
                        filteredPathData.put("request_response_index", rs.getInt("request_response_index"));
                        filteredPathData.put("url", rs.getString("url"));
                        filteredPathData.put("pid", rs.getString("pid"));
                        filteredPathData.put("status", rs.getString("status"));
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error fetchAndMarkOriginalDataAsCrawling: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return filteredPathData;
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


    public synchronized void updatePathDataMayNewParentPath(String mayNewParentPath, String jsFindUrl) {
        String sql = "UPDATE path_data SET "
                + " mayNewParentPath=?, "
                + " isTryNewParentPath=? "
                + "WHERE mayNewParentPath = '' AND mayNewParentPath != ? AND result = '-' AND jsFindUrl = ? AND isJsFindUrl = 'Y'";
        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置更新语句中的参数
            pstmt.setString(1, mayNewParentPath);
            pstmt.setBoolean(2, false);
            pstmt.setString(3, mayNewParentPath);
            pstmt.setString(4, jsFindUrl);

            // 执行更新
            pstmt.executeUpdate();
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-]更新数据库报错： URL=" + jsFindUrl);
            e.printStackTrace(BurpExtender.getStderr());
        }
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

    public synchronized boolean deleteApiDataModelByUri(String url) {
        String sql = "DELETE FROM api_data WHERE url = ?";
        boolean isDeleted = false;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            int affectedRows = pstmt.executeUpdate();

            if (affectedRows > 0) {
                isDeleted = true;
                BurpExtender.getStdout().println("[+]delete Api Data: URI=" + url);
            } else {
                BurpExtender.getStdout().println("[-]no found Api data to delete: URI=" + url);
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error updating list_status in the database for URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }

        return isDeleted;
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

    public synchronized void clearRequestsResponseTable() {
        String sql = "DELETE FROM requests_response"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] requests_response table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing requests_response table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized void clearPathDataTable() {
        String sql = "DELETE FROM path_data"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] path_data table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing path_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }

    public synchronized void clearOriginalDataTable() {
        String sql = "DELETE FROM original_data"; // 用 DELETE 语句来清空表

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.executeUpdate();
            BurpExtender.getStdout().println("[-] original_data table has been cleared.");
        } catch (Exception e) {
            BurpExtender.getStderr().println("Error clearing original_data table: ");
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
            BurpExtender.getStderr().println("[-] Error inserting or updating requests_response table: " + url);
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
    public synchronized int insertOrUpdatePathData(String url, String path, boolean havingImportant, String status, String result, String describe, Map<String, Object> pathData) {
        int generatedId = -1; // 默认ID值，如果没有生成ID，则保持此值
        String checkSql = "SELECT id, status, result, having_important FROM path_data WHERE url = ? AND path = ? AND method = ?";

        try (Connection conn = this.connect();
             PreparedStatement checkStmt = conn.prepareStatement(checkSql)) {
            // 检查记录是否存在
            checkStmt.setString(1, url);
            checkStmt.setString(2, path);
            checkStmt.setString(3, (String) pathData.get("method"));
            ResultSet rs = checkStmt.executeQuery();
            if (rs.next()) {
                // 记录存在，更新记录
                generatedId = rs.getInt("id");
                String currentStatus = rs.getString("status");
                String currentResult = rs.getString("result");
                Boolean currentHavingImportant = rs.getBoolean("having_important");
                // 如果记录存在，但状态不是200，则更新记录
                if (currentResult.equals("误报") || status.equals("等待爬取") || currentHavingImportant){
                    return generatedId;
                }
                if ((!"200".equals(currentStatus)) || (currentStatus.equals("爬取中")) || result.equals("误报") || havingImportant ) {
                    String updateSql = "UPDATE path_data SET having_important = ?, status = ?, result = ?, describe = ?, path_data = ? WHERE id = ?";
                    try (PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {
                        updateStmt.setBoolean(1, havingImportant);
                        updateStmt.setString(2, status);
                        updateStmt.setString(3, result);
                        updateStmt.setString(4, describe);
                        updateStmt.setString(5, serializePathData(pathData));
                        updateStmt.setInt(6, generatedId);
                        updateStmt.executeUpdate();
                    }
                }
            } else {
                // 记录不存在，插入新记录
                String insertSql = "INSERT INTO path_data(url, path, having_important, status,  result, describe, path_data, method, isJsFindUrl, jsFindUrl) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                try (PreparedStatement insertStmt = conn.prepareStatement(insertSql, Statement.RETURN_GENERATED_KEYS)) {
                    insertStmt.setString(1, url);
                    insertStmt.setString(2, path);
                    insertStmt.setBoolean(3, havingImportant);
                    insertStmt.setString(4, status);
                    insertStmt.setString(5, result);
                    insertStmt.setString(6, describe);
                    insertStmt.setString(7, serializePathData(pathData));
                    insertStmt.setString(8, (String) pathData.get("method"));
                    insertStmt.setString(9, (String) pathData.get("isJsFindUrl"));
                    insertStmt.setString(10, (String) pathData.get("jsFindUrl"));
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


    // 方法以插入或更新 path_data 表
    public synchronized boolean updatePathDataBy4xxAnd3XXAndUrl(String url, String mayNewParentPath) {
        String sql = "UPDATE path_data SET "
                + " mayNewParentPath=?, "
                + " isTryNewParentPath=? "
                + "WHERE (status LIKE '3%' OR status LIKE '4%') AND  describe = '-' AND url = ? ";
        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置更新语句中的参数
            pstmt.setString(1, mayNewParentPath);
            pstmt.setBoolean(2, false);
            pstmt.setString(3, url);

            // 执行更新
            pstmt.executeUpdate();
            return true;
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] ERROR in updatePathDataBy4xxAnd3XXAndUrl： URL=" + url + mayNewParentPath);
            e.printStackTrace(BurpExtender.getStderr());
            return false;
        }
    }


    public synchronized boolean updatePathDataByUrlAndPath(String url, String path, String mayNewParentPath) {
        String sql = "UPDATE path_data SET "
                + " mayNewParentPath=?, "
                + " isTryNewParentPath=?, "
                + " isJsFindUrl=?"
                + "WHERE path = ? AND url = ? ";
        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            // 设置更新语句中的参数
            pstmt.setString(1, mayNewParentPath);
            pstmt.setBoolean(2, false);
            pstmt.setString(3, "YY");
            pstmt.setString(4, path);
            pstmt.setString(5, url);

            // 执行更新
            pstmt.executeUpdate();
            return true;
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] ERROR in updatePathDataByUrlAndPath： URL=" + url + mayNewParentPath);
            e.printStackTrace(BurpExtender.getStderr());
            return false;
        }
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
                    pathData.put("method", rs.getString("method"));
                    pathData.put("isJsFindUrl", rs.getString("isJsFindUrl"));
                    pathData.put("jsFindUrl", rs.getString("jsFindUrl"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data table by URL and Path: " + url + ", " + path);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return pathData;
    }


    public synchronized Map<String, Object> selectAllPathDataByUrl(String url) {
        String sql = "SELECT path, path_data FROM path_data WHERE url = ?";
        Map<String, Object> allPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) {
                    allPathData.put(rs.getString("path"), deserializePathData(rs.getString("path_data")));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting all from path_data table by URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return allPathData;
    }

    public synchronized Map<String, Object> fetchAndMarkSinglePathAsCrawling() {
        // 事务开启
        Map<String, Object> filteredPathData = new HashMap<>();

        // 首先选取一条记录的ID
        String selectSQL = "SELECT id, path_data, url, path FROM path_data WHERE status = '等待爬取' LIMIT 1;";
        String updateSQL = "UPDATE path_data SET status = '爬取中' WHERE id = ?;";

        try (PreparedStatement selectStatement = connection.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next()) {
                int selectedId = rs.getInt("id");
                String selectedPathData = rs.getString("path_data");
                String url = rs.getString("url");
                String path = rs.getString("path");


                try (PreparedStatement updateStatement = connection.prepareStatement(updateSQL)) {
                    updateStatement.setInt(1, selectedId);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        // 序列化 path_data
                        Object deserializedPathData = deserializePathData(selectedPathData);
                        filteredPathData.put("id", selectedId);
                        filteredPathData.put("path_data", deserializedPathData);
                        filteredPathData.put("url", url);
                        filteredPathData.put("path", path);
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error fetchAndMarkSinglePathAsCrawling: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return filteredPathData;
    }

    public synchronized Map<String, Object> fetchAndMarkSinglePathAsCrawlingByNewParentPath() {
        // 事务开启
        Map<String, Object> filteredPathData = new HashMap<>();

        // 首先选取一条记录的ID
        String selectSQL = "SELECT id, path_data, url, path, mayNewParentPath FROM path_data WHERE isTryNewParentPath = 0 AND mayNewParentPath != '' LIMIT 1;";
        String updateSQL = "UPDATE path_data SET isTryNewParentPath = 1 WHERE id = ?;";

        try (PreparedStatement selectStatement = connection.prepareStatement(selectSQL)) {
            ResultSet rs = selectStatement.executeQuery();
            if (rs.next()) {
                int selectedId = rs.getInt("id");
                String selectedPathData = rs.getString("path_data");
                String url = rs.getString("url");
                String pathParent = rs.getString("mayNewParentPath");
                String path = rs.getString("path");

                try (PreparedStatement updateStatement = connection.prepareStatement(updateSQL)) {
                    updateStatement.setInt(1, selectedId);
                    int affectedRows = updateStatement.executeUpdate();
                    if (affectedRows > 0) {
                        // 序列化 path_data
                        Object deserializedPathData = deserializePathData(selectedPathData);
                        filteredPathData.put("id", selectedId);
                        filteredPathData.put("path_data", deserializedPathData);
                        filteredPathData.put("url", url);
                        filteredPathData.put("pathParent", pathParent);
                        filteredPathData.put("path", path);
                    }
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error fetchAndMarkSinglePathAsCrawling: ");
            e.printStackTrace(BurpExtender.getStderr());
        }

        return filteredPathData;
    }

    public synchronized int getJSCrawledTotalCountPathDataWithIsJsFindUrl() {
        String sql = "SELECT COUNT(*) FROM path_data WHERE isJsFindUrl = ?";
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, "Y");
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error getCountPathDataWithIsJsFindUrl:");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return count;
    }

    public synchronized int getUrlCrawledCountOriginalDataWithStatus() {
        String sql = "SELECT COUNT(*) FROM original_data WHERE run_status !=  ?";
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, "等待解析");
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error getCountPathDataWithStatus:");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return count;
    }

    public synchronized int getJSCrawledTotalCountOriginalData() {
        String sql = "SELECT COUNT(*) FROM original_data";
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error getCountPathDataWithIsJsFindUrl:");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return count;
    }

    public synchronized int getJSCrawledCountPathDataWithStatus() {
        String sql = "SELECT COUNT(*) FROM path_data WHERE status !=  ? and isJsFindUrl = ?";
        int count = 0;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, "等待爬取");
            pstmt.setString(2, "Y");
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    count = rs.getInt(1);
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error getCountPathDataWithStatus:");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return count;
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

    public synchronized int getPathDataCountByUrlAndIsJsFindUrlAndStatus(String url) {
        String sql = "SELECT COUNT(*) FROM path_data WHERE url = ? AND isJsFindUrl != 'YY' AND status NOT LIKE '3%' AND status NOT LIKE '4%' ";
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

        return count;
    }

    public synchronized Map<String, Object> selectPathDataByUrlAndImportance(String url, boolean isImportant) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND having_important = ?";
        Map<String, Object> filteredPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setBoolean(2, isImportant);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) { // 注意这里使用了 while 循环来处理所有的结果
                    filteredPathData.put(rs.getString("path"), deserializePathData(rs.getString("path_data")));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndImportance: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized Map<String, Object> selectPathDataByUrlAndStatusNot404(String url) {
        String sql = "SELECT path, jsFindUrl FROM path_data WHERE url = ? AND status NOT LIKE '3%' AND status NOT LIKE '4%' AND isJsFindUrl = 'N'";
        Map<String, Object> filteredPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) { // 注意这里使用了 while 循环来处理所有的结果
                    filteredPathData.put(rs.getString("path"), rs.getString("jsFindUrl"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndStatus: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized Map<String, Object> selectPathDataByUrlAndIsJsFindUrl(String url) {
        String sql = "SELECT path, jsFindUrl FROM path_data WHERE url = ? AND isJsFindUrl = 'Y'";
        Map<String, Object> filteredPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) { // 注意这里使用了 while 循环来处理所有的结果
                    filteredPathData.put(rs.getString("path"), rs.getString("jsFindUrl"));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndStatus: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized Map<String, Object> selectPathDataByUrlAndStatus(String url, String status) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND status = ?";
        Map<String, Object> filteredPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, status);

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) { // 注意这里使用了 while 循环来处理所有的结果
                    filteredPathData.put(rs.getString("path"), deserializePathData(rs.getString("path_data")));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndStatus: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized Map<String, Object> selectPathDataByUrlAndResult(String url, String result) {
        String sql = "SELECT * FROM path_data WHERE url = ? AND result LIKE ?";
        Map<String, Object> filteredPathData = new HashMap<>();

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            pstmt.setString(2, "%" + result + "%");

            try (ResultSet rs = pstmt.executeQuery()) {
                while (rs.next()) { // 注意这里使用了 while 循环来处理所有的结果
                    filteredPathData.put(rs.getString("path"), deserializePathData(rs.getString("path_data")));
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error selecting from path_data selectPathDataByUrlAndResult: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
        return filteredPathData;
    }

    public synchronized void updateIsImportantToFalse(String url) {
        String selectSql = "SELECT path_data, path FROM path_data WHERE url = ? and having_important = 1";
        String updateSql = "UPDATE path_data SET path_data = ? , having_important = 0 WHERE url = ? and path = ?";

        try (Connection conn = this.connect();
             PreparedStatement selectStmt = conn.prepareStatement(selectSql);
             PreparedStatement updateStmt = conn.prepareStatement(updateSql)) {

            // 执行查询
            selectStmt.setString(1, url);
            ResultSet rs = selectStmt.executeQuery();

            // 如果查询结果不为空
            while (rs.next()) {
                Map<String, Object> allPathData = deserializePathData(rs.getString("path_data"));
                // 修改isImportant为false
                allPathData.put("isImportant", false);
                allPathData.put("result", "误报");
                allPathData.put("describe", "误报");
                // 将更新后的JSON字符串更新回数据库
                updateStmt.setString(1, serializePathData(allPathData));
                updateStmt.setString(2, url);
                updateStmt.setString(3, rs.getString("path"));
                updateStmt.executeUpdate();
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error updating isImportant in path_data table: ");
            e.printStackTrace(BurpExtender.getStderr());
        }
    }


    public synchronized boolean hasImportantPathDataByUrl(String url) {
        String sql = "SELECT EXISTS(SELECT 1 FROM path_data WHERE url = ? AND having_important = 1)";
        boolean hasImportant = false;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    hasImportant = rs.getInt(1) == 1; // If the query returns 1, then there are important records
                }
            }
        } catch (Exception e) {
            BurpExtender.getStderr().println("[-] Error checking for important path_data by URL: " + url);
            e.printStackTrace(BurpExtender.getStderr());
        }
        return hasImportant;
    }

    public synchronized boolean deletePathDataByUrl(String url) {
        String sql = "DELETE FROM path_data WHERE url = ?";
        boolean isDeleted = false;

        try (Connection conn = this.connect();
             PreparedStatement pstmt = conn.prepareStatement(sql)) {

            pstmt.setString(1, url);
            int affectedRows = pstmt.executeUpdate();

            if (affectedRows > 0) {
                isDeleted = true;
                 BurpExtender.getStdout().println("[+] Successfully deleted path_data for URL: " + url);
            } else {
                 BurpExtender.getStdout().println("[-] No records found to delete for URL: " + url);
            }
        } catch (Exception e) {
             BurpExtender.getStderr().println("[-] Error deleting from path_data table by URL: " + url);
             e.printStackTrace(BurpExtender.getStderr()); // 或者可以选择将异常栈打印到其他日志系统
        }

        return isDeleted;
    }

    // Method to delete an ApiDataModel by url and path
    public synchronized boolean deletePathDataByUrlAndPath(String url, String path) {
        String sqlDelete = "DELETE FROM path_data WHERE url = ? AND path = ?";
        String sqlSelect = "SELECT status, result, describe FROM path_data WHERE url = ?";
        String sqlUpdate = "UPDATE api_data SET status = ?, describe = ?, result = ?, path_number = ?, having_important = ? WHERE url = ?";
        boolean isDeleted = true;

        try (Connection conn = this.connect()) {

            try (PreparedStatement pstmtDelete = conn.prepareStatement(sqlDelete)) {
                // Delete the path data
                pstmtDelete.setString(1, url);
                pstmtDelete.setString(2, path);
                int affectedRows = pstmtDelete.executeUpdate();
                if (affectedRows > 0) {
                    BurpExtender.getStdout().println("[+] Successfully deleted path data for URL and Path: " + url + ", " + path);
                } else {
                    isDeleted = false;
                    BurpExtender.getStdout().println("[-] No records found path data to delete for URL and Path: " + url + ", " + path);
                }
            }

            // If deletion was successful, update the api_data table
            if (isDeleted) {
                Set<String> statuses = new HashSet<>();
                Set<String> descriptions = new HashSet<>();
                Set<String> results = new HashSet<>();

                try (PreparedStatement pstmtSelect = conn.prepareStatement(sqlSelect)) {
                    pstmtSelect.setString(1, url);
                    try (ResultSet rs = pstmtSelect.executeQuery()) {
                        while (rs.next()) {
                            // 分割每个字段值，并将它们添加到对应的集合中
                            String[] statusArray = rs.getString("status").split(",");
                            String[] descriptionArray = rs.getString("describe").split(",");
                            String[] resultArray = rs.getString("result").split(",");

                            // 添加到集合中，自动去重
                            statuses.addAll(Arrays.asList(statusArray));
                            descriptions.addAll(Arrays.asList(descriptionArray));
                            results.addAll(Arrays.asList(resultArray));
                        }
                    }
                }

                String combinedStatus = statuses.isEmpty() ? "-" : String.join(", ", statuses).replace("-, ", "").replace(", -", "");
                String combinedDescription = descriptions.isEmpty() ? "-" : String.join(", ", descriptions).replace("-, ", "").replace(", -", "");
                String combinedResult = results.isEmpty() ? "-" : String.join(", ", results).replace("-, ", "").replace(", -", "");


                try (PreparedStatement pstmtUpdate = conn.prepareStatement(sqlUpdate)) {
                    pstmtUpdate.setString(1, combinedStatus);
                    pstmtUpdate.setString(2, combinedDescription);
                    pstmtUpdate.setString(3, combinedResult);
                    pstmtUpdate.setString(4, getPathDataCountByUrl(url));
                    pstmtUpdate.setBoolean(5, hasImportantPathDataByUrl(url));
                    pstmtUpdate.setString(6, url);
                    pstmtUpdate.executeUpdate();
                }
            }
        } catch (Exception e) {
            isDeleted = false;
            // 如果定义了BurpExtender类和getStderr方法，可以打印错误信息
            BurpExtender.getStderr().println("[-] Error deleting path data from api_data table by URL and Path: " + url + ", " + path);
            e.printStackTrace(BurpExtender.getStderr()); // 或者可以选择将异常栈打印到其他日志系统
        }

        return isDeleted;
    }



}
