#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <db_cxx.h>
#include "./my_folder/root_servers.h"
#include "./my_folder/utils.h"

using namespace std;

string COLUMBIA_IP = "128.59.1.3";
//string COLUMBIA_IP = "8.8.8.8";

Db *db = new Db(NULL, DB_CXX_NO_EXCEPTIONS);

string checkCache(Db* db, const string& domain) {
    Dbt key(const_cast<char*>(domain.c_str()), domain.size());
    Dbt data;
    data.set_flags(DB_DBT_MALLOC); // Berkeley DB allocates memory for us

    try {
        if (db->get(NULL, &key, &data, 0) == 0) {
            string val((char*)data.get_data(), data.get_size());
            free(data.get_data()); // free memory allocated by DB

            auto sep = val.find('|');
            if (sep == string::npos) return ""; // invalid format

            string ip = val.substr(0, sep);
            long expire = stol(val.substr(sep + 1));

            if (time(nullptr) <= expire) {
                return ip; // cache hit
            } else {
                // expired
                db->del(NULL, &key, 0);
                return "";
            }
        }
    } catch (DbException &e) {
        cerr << "DB get error: " << e.what() << endl;
    }
    return "";
}

void insertCache(Db* db, const string& domain, const string& ip, uint32_t ttl) {
    long expire = time(nullptr) + ttl;
    string value = ip + "|" + to_string(expire);

    Dbt key(const_cast<char*>(domain.c_str()), domain.size());
    Dbt data(const_cast<char*>(value.c_str()), value.size());

    try {
        db->put(NULL, &key, &data, 0);
    } catch (DbException &e) {
        cerr << "DB put error: " << e.what() << endl;
    }
}

int main(int argc, char *argv[]){

    //DB
    try {
        db->open(NULL, "dns_cache.db", NULL, DB_HASH, DB_CREATE, 0);
    } catch (DbException &e) {
        cerr << "DB open error: " << e.what() << endl;
        return 1;
    }

    cout << "DB initialized!" << endl;

    //ROOT servers
    auto roots = getRootServers();

    unsigned int port_num = 53;
    int dns_fd = 0;
    char buffer[1024];

    if(argc == 2)
        port_num = atoi(argv[1]);

    struct sockaddr_in dns_addr;

    dns_fd = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&dns_addr, '0', sizeof(dns_addr));

    dns_addr.sin_family = AF_INET;
    dns_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    dns_addr.sin_port = htons(port_num);
    cout << "Created DNS server on port " << htons(port_num) << endl;

    bind(dns_fd, (struct sockaddr*)&dns_addr, sizeof(dns_addr));

    sockaddr_in client_addr;

    while(1){

        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        ssize_t bytes_received = recvfrom(dns_fd, buffer, sizeof(buffer), 0, 
                                    (struct sockaddr *)&client_addr, &client_len);

        if(bytes_received < 0){
            cerr << "Error receiving dns bytes" << endl;
            return -1;
        }else {
            cout<<"Received bytes"<<endl;
            for (int i = 0; i < bytes_received; i++)
                printf("%02x ", (uint8_t)buffer[i]);
            cout << endl;
			cout << buffer << endl;
        }

        string domain = parse_dns_domain(buffer);

        string cached_ip = checkCache(db, domain);
        if (!cached_ip.empty()) {
            cout << "Cache hit for " << domain << ": " << cached_ip << endl;
            auto response_packet = build_dns_response(buffer, cached_ip);
            sendto(dns_fd, response_packet.data(), response_packet.size(), 0,
                (struct sockaddr*)&client_addr, client_len);
            continue;
        }

        string resolved_ip;
        try {
            resolved_ip = iterativeResolve(domain);
        } catch (const exception &e) {
            cerr << "Resolution failed for domain " << domain << ": " << e.what() << endl;
            continue;
        }

        if (!resolved_ip.empty()) {
            uint32_t ttl = 300;  // fixed TTL in seconds
            insertCache(db, domain, resolved_ip, ttl);
            cout << "Cached " << domain << " -> " << resolved_ip
                << " (TTL=" << ttl << "s)" << endl;
        }

        auto response_packet = build_dns_response(buffer, resolved_ip);
        sendto(dns_fd, response_packet.data(), response_packet.size(), 0,
            (struct sockaddr*)&client_addr, client_len);

        cout << "Sent response to client " 
            << inet_ntoa(client_addr.sin_addr) << ":" 
            << ntohs(client_addr.sin_port) << endl;
        
        sleep(1);
    }

    close(dns_fd);
    db->close(0);

    return 0;
}