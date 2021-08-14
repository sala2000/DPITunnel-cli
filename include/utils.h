#ifndef UTILS_H
#define UTILS_H

bool check_host_name(const char *pattern, size_t pattern_len, std::string host);
std::string last_n_chars(const std::string & input, unsigned int n);
void get_tls_sni(const std::string & bytes, unsigned int last_char, unsigned int & start_pos, unsigned int & len);
void daemonize();

#endif //UTILS_H
