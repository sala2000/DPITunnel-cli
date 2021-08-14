#ifndef PACKET_H
#define PACKET_H

int parse_request(const std::string& request, std::string & method, std::string & host, int & port);

#endif //PACKET_H
