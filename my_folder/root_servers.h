#ifndef ROOT_SERVERS_H
#define ROOT_SERVERS_H

#include <string>
#include <vector>

using namespace std;

struct RootServer {
    string name;
    string ip;
};

vector<RootServer> getRootServers();

#endif
