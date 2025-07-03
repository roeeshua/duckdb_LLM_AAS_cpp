// main.cpp - 主应用程序框架
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <string>
#include <vector>
#include <deque>
#include <mutex>
#include <thread>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <atomic>
#include <time.h>
#include <duckdb.h>
#include <regex>

using namespace std;

int counts = 0;
// Web框架
#define CROW_MAIN
#include "crow_all.h"

// 数据库
#include "sqlite3.h"

// HTTP客户端
#include <curl/curl.h>

// JSON处理
#include "nlohmann/json.hpp"
using json = nlohmann::json;

// 系统监控
#ifdef __linux__
#include <sys/sysinfo.h>
#include <fstream>
#elif _WIN32
#include <windows.h>
#include <psapi.h>
#include <ifmib.h>
#endif

// 全局配置
const std::string LLAMA_URL = "http://localhost:8080/v1/chat/completions";
const std::string DB_FILE = "query_history.db";
const std::string CSV_FILE = "device_metrics_random.csv";

// 系统资源数据结构
struct SystemStats {
    std::deque<double> cpu;
    std::deque<double> memory;
    std::deque<double> disk;
    std::deque<double> network;
    std::mutex mtx;
    uint64_t last_net_io = 0;
};

SystemStats system_stats;
constexpr size_t STATS_HISTORY_SIZE = 60;

// 或者替换为转义序列
void escapeControlCharacters(std::string& str) {
    size_t pos = 0;
    while (pos < str.size()) {
        if (str[pos] == '\n') {
            str.replace(pos, 1, "\\n");
            pos += 2;
        }
        else if (str[pos] == '\r') {
            str.replace(pos, 1, "\\r");
            pos += 2;
        }
        else if (str[pos] == '\t') {
            str.replace(pos, 1, "\\t");
            pos += 2;
        }
        else if (static_cast<unsigned char>(str[pos]) <= 0x1F || str[pos] == 0x7F) {
            str.erase(pos, 1); // 直接删除其他控制字符
        }
        else {
            pos++;
        }
    }
}

std::string replace_from_table(const std::string& sql) {
    std::regex pattern(R"(FROM\s+([^\s]+))");
    std::string replacement = "FROM \"$1.csv\"";
    return std::regex_replace(sql, pattern, replacement);
}

void runLlamaScript() {
    // 打开llama进程
    FILE* pipe = _popen(".\\llama\\lanuch.cmd", "r");
    if (!pipe) {
        cerr << "Failed to open pipe" << endl;
        return;
    }

    char buffer[128];
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        cout << "Received: " << buffer;
    }

    _pclose(pipe);
}

// 数据库连接包装类
class SQLiteDB {
public:
    SQLiteDB(const std::string& filename) {
        if (sqlite3_open(filename.c_str(), &db_) != SQLITE_OK) {
            throw std::runtime_error("无法打开数据库: " + filename);
        }
        create_table();
    }

    ~SQLiteDB() {
        sqlite3_close(db_);
    }

    void execute(const std::string& sql) {
        char* err_msg = nullptr;
        if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err_msg) != SQLITE_OK) {
            std::string error = err_msg;
            sqlite3_free(err_msg);
            throw std::runtime_error("SQL错误: " + error);
        }
    }

    sqlite3* handle() { return db_; }

private:
    void create_table() {
        const char* sql = R"(
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME,
                user_query TEXT,
                generated_sql TEXT,
                natural_language_result TEXT
            )
        )";
        execute(sql);
    }

    sqlite3* db_;
};

// HTTP客户端封装
class HTTPClient {
public:
    static size_t WriteCallback(char* data, size_t size, size_t nmemb, std::string* buffer) {
        buffer->append(data, size * nmemb);
        return size * nmemb;
    }

    static std::string Post(const std::string& url, const std::string& data) {
        CURL* curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("无法初始化CURL");
        }

        std::string response_buffer;
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            throw std::runtime_error("HTTP请求失败: " + std::string(curl_easy_strerror(res)));
        }

        return response_buffer;
    }
};

// 查询历史记录管理
class QueryHistory {
public:
    QueryHistory(SQLiteDB& db) : db_(db) {}

    void add(const std::string& user_query, const std::string& generated_sql,
        const std::string& natural_result) {
        std::time_t now = std::time(nullptr);
        std::tm* tm_now = std::localtime(&now);
        std::ostringstream oss;
        oss << std::put_time(tm_now, "%Y-%m-%d %H:%M:%S");
        std::string timestamp = oss.str();

        std::string sql = "INSERT INTO history (timestamp, user_query, generated_sql, natural_language_result) "
            "VALUES (?, ?, ?, ?)";

        sqlite3_stmt* stmt;
        if (sqlite3_prepare_v2(db_.handle(), sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("准备SQL语句失败");
        }

        sqlite3_bind_text(stmt, 1, timestamp.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, user_query.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, generated_sql.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 4, natural_result.c_str(), -1, SQLITE_STATIC);

        if (sqlite3_step(stmt) != SQLITE_DONE) {
            sqlite3_finalize(stmt);
            throw std::runtime_error("执行SQL插入失败");
        }

        sqlite3_finalize(stmt);
    }

    json get_recent(int limit = 5) {
        std::string sql = "SELECT * FROM history ORDER BY timestamp DESC LIMIT ?";
        sqlite3_stmt* stmt;

        if (sqlite3_prepare_v2(db_.handle(), sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            throw std::runtime_error("准备SQL语句失败");
        }

        sqlite3_bind_int(stmt, 1, limit);
        json result = json::array();

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            json record;
            record["id"] = sqlite3_column_int(stmt, 0);
            record["timestamp"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
            record["user_query"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
            record["generated_sql"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3));
            record["natural_language_result"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 4));
            result.push_back(record);
        }

        sqlite3_finalize(stmt);
        return result;
    }

private:
    SQLiteDB& db_;
};

// SQL生成器
class SQLGenerator {
public:
    static std::string generate_from_query(const std::string& query) {
        std::string payload = R"({
            "messages": [
        {"role": "system", "content" : "你是一个SQL生成助手，只返回SQL语句，不要包含任何其他内容。"},
        { "role": "user", "content" : ")"+ create_prompt(query) + R"(" }
            ] ,
            "max_tokens" : 200,
            "temperature" : 0.2
    })";
        auto payload_json = json::parse(payload);
        try {
            std::string response = HTTPClient::Post(LLAMA_URL, payload_json.dump());
            json response_json = json::parse(response);
            std::string sql_response = response_json["choices"][0]["message"]["content"];
            return extract_sql(sql_response);
        }
        catch (const std::exception& e) {
            std::cerr << "SQL生成失败: " << e.what() << std::endl;
            return "SELECT * FROM \"" + CSV_FILE + "\" LIMIT 10";
        }
    }

private:
    static std::string create_prompt(const std::string& query) {
        return
            "你是一个SQL专家，根据用户的问题生成SQL查询语句。"
            "只返回SQL语句，不要包含任何其他解释或文本。"
            "数据库表名：device_metrics_random"
            "数据库表结构：(timestamp(yyyy/mm/dd xx:xx:xx)、cpu_temp(float)、cpu_usage(float)、"
            "memory_usage(float)、disk_usage(float)、network_up(float)、network_down(float))"
            "用户问题: " + query + "SQL:";
    }

    static std::string extract_sql(const std::string& response) {
        // 简单实现 - 实际需要更健壮的解析
        size_t start = response.find("```sql\n");
        if (start == std::string::npos) return response;

        start += 7; // 跳过```sql\n
        size_t end = response.find("\n```", start);
        if (end == std::string::npos) return response.substr(start);

        return response.substr(start, end - start);
    }
};

// 系统监控实现
class SystemMonitor {
    // 在SystemMonitor类中添加以下公共方法：
public:
    static void init_stats() {
        std::lock_guard<std::mutex> lock(system_stats.mtx);
        for (int i = 0; i < STATS_HISTORY_SIZE; ++i) {
            system_stats.cpu.push_back(random_between(15, 45));
            system_stats.memory.push_back(random_between(40, 75));
            system_stats.disk.push_back(random_between(20, 50));
            system_stats.network.push_back(random_between(10, 40));
        }
    }

    static void update_stats_thread() {
        while (true) {
            try {
                update_stats();
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            catch (const std::exception& e) {
                std::cerr << "监控更新错误: " << e.what() << std::endl;
            }
        }
    }

    static json get_current_stats() {
        std::lock_guard<std::mutex> lock(system_stats.mtx);
        return {
            {"cpu", system_stats.cpu},
            {"memory", system_stats.memory},
            {"disk", system_stats.disk},
            {"network", system_stats.network},
            {"timestamp", current_time_str()}
        };
    }

    static json get_device_status() {
        try {
            double cpu_temp = get_cpu_temperature();

            return {
                {"cpu", SystemMonitor::get_cpu_usage()},
                {"cpu_temp", cpu_temp},
                {"memory", SystemMonitor::get_memory_usage()},
                {"status", cpu_temp > 80 ? "warning" : "normal"},
                {"timestamp", current_time_str()}
            };
        }
        catch (const std::exception& e) {
            return {
                {"error", e.what()},
                {"status", "offline"}
            };
        }
    }

    static json get_full_system_status() {
        std::lock_guard<std::mutex> lock(system_stats.mtx);

        return {
            {"cpu", {
                {"usage", system_stats.cpu},
                {"current", get_cpu_usage()},
                {"temperature", get_cpu_temperature()}
            }},
            {"memory", {
                {"usage", system_stats.memory},
                {"current", get_memory_usage()},
                {"total", get_total_memory()},
                {"free", get_free_memory()}
            }},
            {"disk", {
                {"usage", system_stats.disk},
                {"current", get_disk_usage()},
                {"total", get_total_disk()},
                {"free", get_free_disk()}
            }},
            {"network", {
                {"usage", system_stats.network},
                {"current", 10},
                {"sent", get_network_sent()},
                {"received", get_network_received()}
            }},
            {"timestamp", current_time_str()}
        };
    }

private:
    static void update_stats() {
        std::lock_guard<std::mutex> lock(system_stats.mtx);

        // CPU使用率
        double cpu = get_cpu_usage();
        system_stats.cpu.push_back(cpu);
        if (system_stats.cpu.size() > STATS_HISTORY_SIZE) {
            system_stats.cpu.pop_front();
        }

        // 内存使用率
        double mem = get_memory_usage();
        system_stats.memory.push_back(mem);
        if (system_stats.memory.size() > STATS_HISTORY_SIZE) {
            system_stats.memory.pop_front();
        }

        // 磁盘使用率
        double disk = get_disk_usage();
        system_stats.disk.push_back(disk);
        if (system_stats.disk.size() > STATS_HISTORY_SIZE) {
            system_stats.disk.pop_front();
        }
    }

    static double get_cpu_usage() {
#ifdef __linux__
        static unsigned long long last_total = 0, last_idle = 0;
        std::ifstream stat_file("/proc/stat");
        std::string line;
        std::getline(stat_file, line);

        unsigned long long user, nice, system, idle, iowait, irq, softirq;
        sscanf(line.c_str(), "cpu %llu %llu %llu %llu %llu %llu %llu",
            &user, &nice, &system, &idle, &iowait, &irq, &softirq);

        unsigned long long total = user + nice + system + irq + softirq + iowait;
        unsigned long long total_diff = total - last_total;
        unsigned long long idle_diff = idle - last_idle;

        last_total = total;
        last_idle = idle;

        return (total_diff > 0) ? (100.0 * (total_diff - idle_diff) / total_diff) : 0.0;
#elif _WIN32
        FILETIME idle_time, kernel_time, user_time;
        if (GetSystemTimes(&idle_time, &kernel_time, &user_time)) {
            ULARGE_INTEGER idle, kernel, user;
            idle.LowPart = idle_time.dwLowDateTime;
            idle.HighPart = idle_time.dwHighDateTime;
            kernel.LowPart = kernel_time.dwLowDateTime;
            kernel.HighPart = kernel_time.dwHighDateTime;
            user.LowPart = user_time.dwLowDateTime;
            user.HighPart = user_time.dwHighDateTime;

            static ULARGE_INTEGER last_idle, last_kernel, last_user;
            ULARGE_INTEGER delta_idle = { .QuadPart = idle.QuadPart - last_idle.QuadPart };
            ULARGE_INTEGER delta_kernel = { .QuadPart = kernel.QuadPart - last_kernel.QuadPart };
            ULARGE_INTEGER delta_user = { .QuadPart = user.QuadPart - last_user.QuadPart };

            last_idle = idle;
            last_kernel = kernel;
            last_user = user;

            unsigned long long total = delta_kernel.QuadPart + delta_user.QuadPart;
            return (total > 0) ? (100.0 * (total - delta_idle.QuadPart) / total) : 0.0;
        }
        return 0.0;
#endif
    }

    // 在SystemMonitor类中添加以下私有方法实现：

    static double get_memory_usage() {
#ifdef __linux__
        struct sysinfo mem_info;
        if (sysinfo(&mem_info) != 0) {
            throw std::runtime_error("获取内存信息失败");
        }

        unsigned long total_mem = mem_info.totalram * mem_info.mem_unit;
        unsigned long free_mem = mem_info.freeram * mem_info.mem_unit;
        return 100.0 - (100.0 * free_mem / total_mem);

#elif _WIN32
        MEMORYSTATUSEX mem_info;
        mem_info.dwLength = sizeof(MEMORYSTATUSEX);
        if (!GlobalMemoryStatusEx(&mem_info)) {
            throw std::runtime_error("获取内存信息失败");
        }
        return mem_info.dwMemoryLoad;
#endif
    }

    static double get_disk_usage() {
#ifdef __linux__
        struct statvfs stat;
        if (statvfs("/", &stat) != 0) {
            throw std::runtime_error("获取磁盘信息失败");
        }

        unsigned long total = stat.f_blocks * stat.f_frsize;
        unsigned long available = stat.f_bavail * stat.f_frsize;
        return 100.0 - (100.0 * available / total);

#elif _WIN32
        ULARGE_INTEGER free_bytes, total_bytes;
        if (!GetDiskFreeSpaceExA("C:", &free_bytes, &total_bytes, nullptr)) {
            throw std::runtime_error("获取磁盘信息失败");
        }
        return 100.0 - (100.0 * free_bytes.QuadPart / total_bytes.QuadPart);
#endif
    }

    static double get_cpu_temperature() {
#ifdef __linux__
        std::ifstream temp_file("/sys/class/thermal/thermal_zone0/temp");
        if (!temp_file.is_open()) {
            throw std::runtime_error("无法读取CPU温度");
        }

        int temp;
        temp_file >> temp;
        return temp / 1000.0; // 转换为摄氏度

#elif _WIN32
        // Windows没有标准方法获取CPU温度，需要硬件特定API
        // 这里使用模拟数据
        static std::mt19937 gen(std::random_device{}());
        static std::normal_distribution<> dist(45.0, 5.0);
        return std::max(30.0, std::min(90.0, dist(gen)));
#endif
    }


private:
    // 辅助方法
    static uint64_t get_total_memory() {
#ifdef __linux__
        struct sysinfo mem_info;
        sysinfo(&mem_info);
        return mem_info.totalram * mem_info.mem_unit;
#elif _WIN32
        MEMORYSTATUSEX mem_info;
        mem_info.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&mem_info);
        return mem_info.ullTotalPhys;
#endif
    }

    static uint64_t get_free_memory() {
#ifdef __linux__
        struct sysinfo mem_info;
        sysinfo(&mem_info);
        return mem_info.freeram * mem_info.mem_unit;
#elif _WIN32
        MEMORYSTATUSEX mem_info;
        mem_info.dwLength = sizeof(MEMORYSTATUSEX);
        GlobalMemoryStatusEx(&mem_info);
        return mem_info.ullAvailPhys;
#endif
    }

    static uint64_t get_total_disk() {
#ifdef __linux__
        struct statvfs stat;
        statvfs("/", &stat);
        return stat.f_blocks * stat.f_frsize;
#elif _WIN32
        ULARGE_INTEGER total_bytes;
        GetDiskFreeSpaceExA("C:", nullptr, &total_bytes, nullptr);
        return total_bytes.QuadPart;
#endif
    }

    static uint64_t get_free_disk() {
#ifdef __linux__
        struct statvfs stat;
        statvfs("/", &stat);
        return stat.f_bavail * stat.f_frsize;
#elif _WIN32
        ULARGE_INTEGER free_bytes;
        GetDiskFreeSpaceExA("C:", &free_bytes, nullptr, nullptr);
        return free_bytes.QuadPart;
#endif
    }

    static uint64_t get_network_sent() {
        // 实现类似get_network_usage()中的发送字节统计
        // 返回累计发送字节数
        // ...
        return 1;
    }

    static uint64_t get_network_received() {
        // 实现类似get_network_usage()中的接收字节统计
        // 返回累计接收字节数
        // ...
        return 1;
    }

    static std::string current_time_str() {
        auto now = std::chrono::system_clock::now();
        auto in_time_t = std::chrono::system_clock::to_time_t(now);
        std::tm tm_buf;
        localtime_s( &tm_buf, &in_time_t);
       

        std::ostringstream oss;
        oss << std::put_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
        return oss.str();
    }

    static double random_between(double min, double max) {
        static std::mt19937 gen(std::random_device{}());
        std::uniform_real_distribution<> dis(min, max);
        return dis(gen);
    }
};

// 工具函数
namespace Utils {
    std::string read_file(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("无法打开文件: " + filename);
        }
        return std::string((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
    }

    void write_file(const std::string& filename, const std::string& content) {
        std::ofstream file(filename);
        if (!file.is_open()) {
            throw std::runtime_error("无法写入文件: " + filename);
        }
        file << content;
    }

    std::string replace_sql_table(const std::string& sql) {
        // 简单实现 - 实际需要更健壮的SQL解析
        size_t from_pos = sql.find("FROM");
        if (from_pos == std::string::npos) return sql;

        size_t table_start = sql.find_first_not_of(" \t", from_pos + 4);
        if (table_start == std::string::npos) return sql;

        size_t table_end = sql.find_first_of(" \t;", table_start);
        if (table_end == std::string::npos) table_end = sql.length();

        std::string table_name = sql.substr(table_start, table_end - table_start);
        return sql.substr(0, table_start) + "\"" + table_name + ".csv\"" + sql.substr(table_end);
    }
}

// 查询处理器
class QueryProcessor {
public:
    QueryProcessor(SQLiteDB& db) : db_(db), history_(db) {}

    json process_query(const std::string& user_query) {
        // 生成SQL
        std::string generated_sql = SQLGenerator::generate_from_query(user_query);
        cout << "生成SQL" << endl;

        // 执行查询
        auto result = execute_query(generated_sql, user_query);
        cout << "执行查询" << endl;
        // 保存历史
        history_.add(user_query, generated_sql, result["natural_language"]);
        cout << "保存历史" << endl;
        // 获取历史记录
        result["history"] = history_.get_recent();
        cout << "获取历史记录" << endl;
        // 添加系统状态
        result["system_stats"] = SystemMonitor::get_current_stats();

        return result;
    }

private:
    json execute_query(const std::string& sql, const std::string& user_query) {
        try {
            duckdb_database db;
            duckdb_connection con;
            duckdb_result result;
            // 1. 初始化DuckDB
            if (duckdb_open(nullptr, &db)) {
                throw std::runtime_error("无法打开DuckDB数据库");
            }
            if (duckdb_connect(db, &con)) {
                duckdb_close(&db);
                throw std::runtime_error("无法连接DuckDB数据库");
            }
            // 2. 创建表并加载CSV数据
            std::string create_table_sql =
                "CREATE TABLE device_metrics AS SELECT * FROM read_csv_auto('" +
                CSV_FILE + "');";

            if (duckdb_query(con, create_table_sql.c_str(), &result) != DuckDBSuccess) {
                std::string error = duckdb_result_error(&result);
                duckdb_destroy_result(&result);
                duckdb_disconnect(&con);
                duckdb_close(&db);
                throw std::runtime_error("创建表失败: " + error);
            }
            duckdb_destroy_result(&result);
            std::string sql_query = "";
            cout << "sql语句：" << sql << endl;
            if (sql.find(".csv") != sql.npos)
            {
                sql_query = sql.ends_with(";") ? sql.substr(0, sql.length() - 1) : sql;
            }
            else
            {
                 sql_query = sql.ends_with(";") ? replace_from_table(sql.substr(0, sql.length() - 1)) : replace_from_table(sql);
            }
            
            cout <<"sql语句：" << sql_query << endl;
            // 3. 执行用户查询
            if (duckdb_query(con, sql_query.c_str(), &result) != DuckDBSuccess) {
                std::string default_sql =
                    "SELECT * FROM '" + CSV_FILE + "'";
                duckdb_destroy_result(&result);
                cout << default_sql << endl;
                duckdb_query(con, default_sql.c_str(), &result);
            }
            // 4. 将结果转换为CSV字符串
            std::ostringstream csv_stream;
            idx_t col_count = duckdb_column_count(&result);
            idx_t row_count = duckdb_row_count(&result);

            // 添加列标题
            for (idx_t col = 0; col < col_count; col++) {
                if (col > 0) csv_stream << ",";
                csv_stream << duckdb_column_name(&result, col);
            }
            csv_stream << "\n";
            // 添加数据行
            for (idx_t row = 0; row < row_count; row++) {
                for (idx_t col = 0; col < col_count; col++) {
                    if (col > 0) csv_stream << ",";
                    char* value = duckdb_value_varchar(&result, col, row);
                    csv_stream << (value ? value : "NULL");
                    duckdb_free(value);
                }
                csv_stream << "\n";
            }

            std::string csv_output = csv_stream.str();
            duckdb_destroy_result(&result);
            // 5. 清理资源
            duckdb_disconnect(&con);
            duckdb_close(&db);

            cout << "csv结果：" << csv_output<<endl;
            // 6. 调用LLM解释结果
            std::string natural_language = explain_results(csv_output);

            return {
                {"sql", sql},
                {"natural_language", csv_output+"\\n"+natural_language},
                {"result_count", row_count},
                {"execution_time", 0.1}//, // 实际应用中应计算真实时间
                /*{"csv_content", csv_output}*/
            };
        }
        catch (const std::exception& e) {
            return {
                {"error", e.what()},
                {"natural_language", std::string("查询执行出错: ") + e.what()},
                {"result_count", 0},
                {"execution_time", 0}
            };
        }
    }


    // 修改explain_results方法
    std::string explain_results(const std::string& csv_content) {
        std::string mod_csv = csv_content;
        escapeControlCharacters(mod_csv);
        std::string payload = R"({
            "messages": [
            {"role": "user", "content": "数据库表结构：(timestamp(yyyy/mm/dd xx:xx:xx)、cpu_temp(float)cpu温度、cpu_usage(float)cpu使用、memory_usage(float)内存使用、disk_usage(float)硬盘使用、network_up(float)网络上传、network_down(float)网络下载)，m/s为网速不是风速，这些不是气象局数据，这些是硬件监控数据，以下提供我的数据库内容（只提取了部分数据，具体展示给你的是那一部分，请看表头），请你把其中的每一行解释为自然语言，尽量简短一些： )"+ mod_csv + R"( "}
            ],
            "max_tokens": 600
        })";
        json payload_json = json::parse(payload);
        std::string response = HTTPClient::Post(LLAMA_URL, payload_json.dump());
        json response_json = json::parse(response);
        return response_json["choices"][0]["message"]["content"];
    }

    SQLiteDB& db_;
public:
    QueryHistory history_;
};

// 在Utils命名空间中添加CSV清理函数
namespace Utils {
    std::string clean_csv_value(const std::string& value) {
        if (value.find(',') != std::string::npos ||
            value.find('"') != std::string::npos ||
            value.find('\n') != std::string::npos) {

            std::string escaped = value;
            // 转义双引号
            size_t pos = 0;
            while ((pos = escaped.find('"', pos)) != std::string::npos) {
                escaped.replace(pos, 1, "\"\"");
                pos += 2;
            }
            return "\"" + escaped + "\"";
        }
        return value;
    }
}

void webService()
{
    try {
        // 初始化数据库
        SQLiteDB db(DB_FILE);

        // 初始化系统监控
        SystemMonitor::init_stats();
        std::thread monitor_thread(SystemMonitor::update_stats_thread);
        monitor_thread.detach();

        // 创建应用
        crow::SimpleApp app;
        QueryProcessor processor(db);

        //首页绑定
        CROW_ROUTE(app, "/")([](const crow::request&, crow::response& res) {
            res.set_static_file_info("templates/index.html");
            res.end();
            });


        CROW_ROUTE(app, "/query")
            .methods("POST"_method)
            ([&processor](const crow::request& req) {
            try {
                auto body = json::parse(req.body);
                std::string query = body["query"];
                json result = processor.process_query(query);
                return crow::response(200, result.dump());
            }
            catch (const std::exception& e) {
                return crow::response(500, json{ {"error", e.what()} }.dump());
            }
                });

        CROW_ROUTE(app, "/history")([&processor]() {
            try {
                auto history = processor.history_.get_recent(10);
                return crow::response(200, history.dump());
            }
            catch (const std::exception& e) {
                return crow::response(500, json{ {"error", e.what()} }.dump());
            }
            });

        CROW_ROUTE(app, "/api/system_stats")([]() {
            try {
                auto stats = SystemMonitor::get_current_stats();
                return crow::response(200, stats.dump());
            }
            catch (const std::exception& e) {
                return crow::response(500, json{ {"error", e.what()} }.dump());
            }
            });

        CROW_ROUTE(app, "/api/device_status")([]() {
            try {
                auto status = SystemMonitor::get_device_status();
                return crow::response(200, status.dump());
            }
            catch (const std::exception& e) {
                return crow::response(500, json{ {"error", e.what()} }.dump());
            }
            });

        CROW_ROUTE(app, "/api/full_status")([]() {
            try {
                auto status = SystemMonitor::get_full_system_status();
                return crow::response(200, status.dump());
            }
            catch (const std::exception& e) {
                return crow::response(500, json{ {"error", e.what()} }.dump());
            }
            });

        // 启动服务
        app.port(5002).bindaddr("127.0.0.1").multithreaded().run();

    }
    catch (const std::exception& e) {
        std::cerr << "应用启动失败: " << e.what() << std::endl;
        return ;
    }
}

// 主应用
int main() {
    thread llamaThread(runLlamaScript);
    thread webServiceThread(webService);
    llamaThread.join();
    webServiceThread.join();

    return 0;
}