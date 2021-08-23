#include "dpitunnel-cli.h"

#include "utils.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <unistd.h>

bool is_space_or_tab(char c) { return c == ' ' || c == '\t'; }

std::pair<size_t, size_t> trim(const char *b, const char *e, size_t left,
				size_t right) {
	while (b + left < e && is_space_or_tab(b[left]))
		left++;
	while (right > 0 && is_space_or_tab(b[right - 1]))
		right--;
	return std::make_pair(left, right);
}

template <class Fn> void split(const char *b, const char *e, char d, Fn fn) {
	size_t i = 0;
	size_t beg = 0;

	while (e ? (b + i < e) : (b[i] != '\0')) {
		if (b[i] == d) {
			auto r = trim(b, e, beg, i);
			if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
				beg = i + 1;
		}
		i++;
	}

	if (i) {
		auto r = trim(b, e, beg, i);
		if (r.first < r.second) { fn(&b[r.first], &b[r.second]); }
	}
}

bool check_host_name(const char *pattern, size_t pattern_len, std::string host) {
        if (host.size() == pattern_len && host == pattern) { return true; }
        std::vector<std::string> pattern_components;
        std::vector<std::string> host_components;
        split(&pattern[0], &pattern[pattern_len], '.',
                        [&](const char *b, const char *e) {
                                pattern_components.emplace_back(std::string(b, e));
                        });
        split(&host[0], &host[host.size()], '.',
                        [&](const char *b, const char *e) {
                                host_components.emplace_back(std::string(b, e));
                        });
        if (host_components.size() != pattern_components.size()) { return false; }

        auto itr = pattern_components.begin();
        for (const auto &h : host_components) {
                auto &p = *itr;
                if (p != h && p != "*") {
                        auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' &&
                                                !p.compare(0, p.size() - 1, h));
                        if (!partial_match) { return false; }
                }
                ++itr;
        }
        return true;
}

std::string last_n_chars(const std::string & input, unsigned int n) {
	unsigned int inputSize = input.size();
	return (n > 0 && inputSize > n) ? input.substr(inputSize - n) : input;
}

void get_tls_sni(const std::string & bytes, unsigned int last_char, unsigned int & start_pos, unsigned int & len) {
	unsigned int it;
	if(last_char <= 43) {
		start_pos = 0; len = 0;
		return;
	}
	unsigned short sidlen = bytes[43];
	it = 1 + 43 + sidlen;
	if(last_char <= it) {
		start_pos = 0; len = 0;
		return;
	}
	unsigned short cslen = ntohs(*(unsigned short*) &bytes[it]);
	it += 2 + cslen;
	if(last_char <= it) {
		start_pos = 0; len = 0;
		return;
	}
	unsigned short cmplen = bytes[it];
	it += 1 + cmplen;
	if(last_char <= it) {
		start_pos = 0; len = 0;
		return;
	}
	unsigned short maxcharit = it + 2 + ntohs(*(unsigned short*) &bytes[it]);
	it += 2;
	unsigned short ext_type = 1;
	unsigned short ext_len;
	while(it < maxcharit && ext_type != 0) {
		if(last_char <= it + 9) {
			start_pos = 0; len = 0;
			return;
		}
		ext_type = ntohs(*(unsigned short*) &bytes[it]);
		it += 2;
		ext_len = ntohs(*(unsigned short*) &bytes[it]);
		it += 2;
		if(ext_type == 0) {
			it += 3;
			unsigned short namelen = ntohs(*(unsigned short*) &bytes[it]);
			it += 2;
			len = namelen;
			start_pos = it;
			return;
		} else it += ext_len;
	}
	start_pos = 0; len = 0;
}

void daemonize() {
	int pid;

	pid = fork();
	if (pid == -1) {
		perror("fork");
		exit(2);
	}
	else if (pid != 0)
		exit(0);

	if (setsid() == -1)
		exit(2);
	if (chdir("/") == -1)
		exit(2);
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);
	/* redirect fd's 0,1,2 to /dev/null */
	open("/dev/null", O_RDWR);
	int fd;
	/* stdin */
	fd = dup(0);
	/* stdout */
	fd = dup(0);
	/* stderror */
}

int ignore_sigpipe() {
	struct sigaction act;
	std::memset(&act, 0, sizeof(act));
	act.sa_handler = SIG_IGN;
	act.sa_flags = SA_RESTART;
	if(sigaction(SIGPIPE, &act, NULL)) {
		std::cerr << "Failed ignore SIGPIPE. Errno: " << std::strerror(errno) << std::endl;
		return -1;
	}

	return 0;
}
