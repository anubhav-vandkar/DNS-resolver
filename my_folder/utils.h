#ifndef UTILS_H
#define UTILS_H

#include <string>
#include <vector>
#include <cstdint>

enum RecordType { 
    A_RECORD = 1, 
    NS_RECORD = 2 
};

struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t a_count;
    uint16_t n_count;
    uint16_t arr_count;
};

struct DNSAnswer {
    std::string name;
    uint32_t ttl;
    std::string ip;
    std::string ns_name;
    int type;
};

struct DNSParsed {
    std::vector<DNSAnswer> answers;
    std::vector<DNSAnswer> authorities;
    std::vector<DNSAnswer> additional;
};

std::string parse_dns_domain(char* buffer);
std::string read_name(uint8_t* buffer, uint8_t** ptr);
std::vector<uint8_t> build_dns_query(const std::string& domain, uint16_t id, bool rd=false);
std::vector<uint8_t> send_dns_query(const std::string& server_ip, const std::string& domain, bool rd=false);
DNSParsed parse_dns_response(std::vector<uint8_t>& resp);
std::vector<uint8_t> build_dns_response(char* query_buf, const std::string& ip_str);
std::string iterativeResolve(const std::string domain);

#endif