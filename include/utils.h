#ifndef UTILS_H
#define UTILS_H

#include <cstddef>
#include <string>

bool check_host_name(const char *pattern, size_t pattern_len, std::string host);
std::string last_n_chars(const std::string & input, unsigned int n);
void get_tls_sni(const std::string & bytes, unsigned int last_char, unsigned int & start_pos, unsigned int & len);
bool validate_http_method(std::string method);
void daemonize();
int ignore_sigpipe();

#endif //UTILS_H
