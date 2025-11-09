#include "utils.h"
#include "root_servers.h"
#include <iostream>
#include <bits/stdc++.h>
#include <netinet/in.h>
#include <arpa/inet.h>

using namespace std;

string read_name(uint8_t* buffer, uint8_t** ptr) {
    string name;
    uint8_t* p = *ptr;

    while (true) {
        uint8_t len = *p;

        // case 1: pointer compression (starts with 11xxxxxx)
        if ((len & 0xC0) == 0xC0) {
            uint16_t offset = ((len & 0x3F) << 8) | *(p + 1);
            p += 2;
            uint8_t* new_ptr = buffer + offset;
            name += read_name(buffer, &new_ptr);
            break;
        }

        // case 2: normal label
        if (len == 0) {
            p++;
            break;
        }

        p++;
        for (int i = 0; i < len; i++) {
            name.push_back(*p);
            p++;
        }
        name.push_back('.');
    }

    *ptr = p;
    if (!name.empty() && name.back() == '.')
        name.pop_back();
    return name;
}

string parse_dns_domain(char* buffer) {

    char* ptr = buffer + 12; // skip 12-byte DNS header
    string domain;

    while (true) {
        uint8_t len = *ptr;
        if (len == 0) { // end of QNAME
            ptr++;
            break;
        }

        if (!domain.empty()) domain.push_back('.');
        ptr++;
        for (int i = 0; i < len; i++) {
            domain.push_back(*ptr);
            ptr++;
        }
    }
    return domain;
}

DNSParsed parse_dns_response(vector<uint8_t>& resp) {
    DNSParsed parsed;
    uint8_t* ptr = resp.data();

    DNSHeader* hdr = (DNSHeader*)ptr;
    int q_count = ntohs(hdr->q_count);
    int a_count = ntohs(hdr->a_count);
    int n_count = ntohs(hdr->n_count);
    int arr_count = ntohs(hdr->arr_count);

    ptr += sizeof(DNSHeader);

    // Skip question section
    for (int i = 0; i < q_count; i++) {
        read_name(resp.data(), &ptr);
        ptr += 4; // QTYPE + QCLASS
    }

    auto parse_rr = [&](int count, vector<DNSAnswer>& container) {
        for (int i = 0; i < count; i++) {
            DNSAnswer ans;
            ans.name = read_name(resp.data(), &ptr);
            uint16_t type = ntohs(*(uint16_t*)ptr); ptr += 2;
            uint16_t class_ = ntohs(*(uint16_t*)ptr); ptr += 2;
            ans.ttl = ntohl(*(uint32_t*)ptr); ptr += 4;
            uint16_t rdlen = ntohs(*(uint16_t*)ptr); ptr += 2;

            if (type == 1 && rdlen == 4) { // A record
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, ptr, ip, INET_ADDRSTRLEN);
                ans.type = A_RECORD;
                ans.ip = ip;
            }
            else if (type == 2) { // NS record
                ans.type = NS_RECORD;
                uint8_t* rdata_ptr = ptr;
                ans.ns_name = read_name(resp.data(), &rdata_ptr);
            }
            ptr += rdlen;
            container.push_back(ans);
        }
    };

    parse_rr(a_count, parsed.answers);
    parse_rr(n_count, parsed.authorities);
    parse_rr(arr_count, parsed.additional);

    return parsed;
}

vector<uint8_t> build_dns_query(const string& domain, uint16_t id, bool rd) {
    vector<uint8_t> packet;

    // --- Header ---
    DNSHeader hdr;
    hdr.id = htons(id);
    hdr.flags = htons((rd ? 0x0100 : 0x0000)); // RD bit if rd=true
    hdr.q_count = htons(1);
    hdr.a_count = 0;
    hdr.n_count = 0;
    hdr.arr_count = 0;

    packet.insert(packet.end(), (uint8_t*)&hdr, (uint8_t*)&hdr + sizeof(DNSHeader));

    size_t pos = 0;
    while (pos < domain.size()) {
        size_t dot = domain.find('.', pos);
        if (dot == string::npos) dot = domain.size();
        uint8_t len = dot - pos;
        packet.push_back(len);
        for (size_t i = pos; i < dot; i++) packet.push_back(domain[i]);
        pos = dot + 1;
    }
    packet.push_back(0); 

    uint16_t qtype = htons(1);  // A record
    uint16_t qclass = htons(1); // IN
    packet.insert(packet.end(), (uint8_t*)&qtype, (uint8_t*)&qtype + 2);
    packet.insert(packet.end(), (uint8_t*)&qclass, (uint8_t*)&qclass + 2);

    return packet;
}

vector<uint8_t> send_dns_query(const string& server_ip, const string& domain, bool rd) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    sockaddr_in servaddr{};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(53);
    inet_pton(AF_INET, server_ip.c_str(), &servaddr.sin_addr);

    uint16_t id = rand() % 65536;
    auto query_packet = build_dns_query(domain, id, rd);

    sendto(sock, query_packet.data(), query_packet.size(), 0,
           (struct sockaddr*)&servaddr, sizeof(servaddr));
    cout<<"sent dns query for: "<<server_ip<<endl;

    uint8_t buffer[512];
    socklen_t len = sizeof(servaddr);
    ssize_t n = recvfrom(sock, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&servaddr, &len);
    cout<<"received dns data from: "<<server_ip<<endl;

    close(sock);

    return vector<uint8_t>(buffer, buffer + n);
}

vector<uint8_t> build_dns_response(char* query_buf, const std::string& ip_str) {
    vector<uint8_t> response;

    DNSHeader* reqHdr = (DNSHeader*)query_buf;

    DNSHeader respHdr{};
    respHdr.id      = reqHdr->id;
    respHdr.flags   = htons(0x8180);
    respHdr.q_count = reqHdr->q_count;
    respHdr.a_count = htons(1);
    respHdr.n_count = 0;
    respHdr.arr_count = 0;

    response.insert(response.end(), (uint8_t*)&respHdr, (uint8_t*)&respHdr + sizeof(DNSHeader));

    int offset = sizeof(DNSHeader);
    response.insert(response.end(), (uint8_t*)query_buf + offset, (uint8_t*)query_buf + offset + ntohs(reqHdr->q_count) * 512);

    char* ptr = query_buf + 12;
    while (*ptr != 0) ptr++;
    ptr++;
    ptr += 4;

    int question_len = ptr - (query_buf + offset);
    response.resize(sizeof(DNSHeader) + question_len);

    uint16_t namePtr = htons(0xC00C);
    response.insert(response.end(), (uint8_t*)&namePtr, (uint8_t*)&namePtr + 2);

    uint16_t type = htons(1);
    uint16_t clas = htons(1);
    uint32_t ttl = htonl(60);
    uint16_t rdLen = htons(4);

    response.insert(response.end(), (uint8_t*)&type, (uint8_t*)&type + 2);
    response.insert(response.end(), (uint8_t*)&clas, (uint8_t*)&clas + 2);
    response.insert(response.end(), (uint8_t*)&ttl, (uint8_t*)&ttl + 4);
    response.insert(response.end(), (uint8_t*)&rdLen, (uint8_t*)&rdLen + 2);

    uint8_t ip_bytes[4];
    inet_pton(AF_INET, ip_str.c_str(), ip_bytes);
    response.insert(response.end(), ip_bytes, ip_bytes + 4);

    return response;
}

string iterativeResolve(string domain) {
    auto servers = getRootServers();
    cout << "Got root servers" << endl;

    while (true) {
        if (servers.empty()) {
            throw runtime_error("No DNS servers left to query.");
        }

        cout << "Current server pool size = " << servers.size() << endl;

        RootServer current = servers[rand() % servers.size()];
        if (current.ip.empty()) continue;
        cout << "Querying server: " << current.ip << endl;

        auto resp = send_dns_query(current.ip, domain, false);
        DNSParsed parsed = parse_dns_response(resp);

        for (auto& ans : parsed.answers) {
            if (ans.type == A_RECORD) {
                cout << "Found A record " << ans.ip << endl;
                return ans.ip;
            }
        }

        if (!parsed.authorities.empty()) {

            vector<RootServer> nextServers;

            for (auto& add : parsed.additional)
                if (add.type == A_RECORD)
                    nextServers.push_back({add.name, add.ip});

            if (!nextServers.empty()) {
                cout << "Switching to glue A record servers" << endl;
                servers = nextServers;
                continue;
            }

            for (auto& ns : parsed.authorities) {
                cout << "Recursively resolving NS hostname: " << ns.ns_name << endl;

                string nsIp = iterativeResolve(ns.ns_name);

                if (nsIp.empty()) {
                    continue;
                }
                servers.push_back({ns.ns_name, nsIp});

                servers = { { ns.ns_name, nsIp } };
                break;
            }
            continue;
        }
        throw runtime_error("Domain not found iteratively — no useful DNS records.");
    }
}