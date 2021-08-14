#ifndef DPITUNNEL_CLI_H
#define DPITUNNEL_CLI_H

#include <iostream>
#include <atomic>
#include <cerrno>
#include <regex>
#include <random>
#include <ctime>
#include <chrono>
#include <string>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/wireless.h>
#include <linux/if_ether.h>
#include <thread>
#include <poll.h>
#include <unistd.h>
#include <getopt.h>

#include <netlink/netlink.h>    //lots of netlink functions
#include <netlink/genl/genl.h>  //genl_connect, genlmsg_put
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>  //genl_ctrl_resolve
#include <linux/nl80211.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <cpp-httplib/httplib.h>

#include <RawSocket/CheckSum.h>

#include <dnslib/exception.h>
#include <dnslib/message.h>
#include <dnslib/rr.h>

#include <base64.h>

enum Desync_zero_attacks {
	DESYNC_ZERO_FAKE,
	DESYNC_ZERO_RST,
	DESYNC_ZERO_RSTACK,
	DESYNC_ZERO_NONE
};

enum Desync_first_attacks {
	DESYNC_FIRST_DISORDER,
	DESYNC_FIRST_DISORDER_FAKE,
	DESYNC_FIRST_SPLIT,
	DESYNC_FIRST_SPLIT_FAKE,
	DESYNC_FIRST_NONE
};

static const std::map<Desync_zero_attacks, std::string> ZERO_ATTACKS_NAMES = {
	{DESYNC_ZERO_FAKE, "fake"},
	{DESYNC_ZERO_RST, "rst"},
	{DESYNC_ZERO_RSTACK, "rstack"}
};

static const std::map<Desync_first_attacks, std::string> FIRST_ATTACKS_NAMES = {
	{DESYNC_FIRST_DISORDER, "disorder"},
	{DESYNC_FIRST_DISORDER_FAKE, "disorder_fake"},
	{DESYNC_FIRST_SPLIT, "split"},
	{DESYNC_FIRST_SPLIT_FAKE, "split_fake"}
};

struct Settings_s {
	int server_port = 8080;
	unsigned int buffer_size = 512;
	unsigned int split_position = 3;
	unsigned short fake_packets_ttl = 10;
	unsigned short window_size = 0;
	short window_scale_factor = -1;
	unsigned short test_ssl_handshake_timeout = 5;
	unsigned short packet_capture_timeout = 5000;

	std::string server_address = "0.0.0.0";
	std::string doh_server = "https://dns.google/dns-query";
	std::string ca_bundle_path = "./ca.bundle";
	std::string ca_bundle;

	bool daemon = false;
	bool split_at_sni = false;
	bool desync_attacks = false;
	bool doh = false;

	Desync_zero_attacks desync_zero_attack = DESYNC_ZERO_NONE;
	Desync_first_attacks desync_first_attack = DESYNC_FIRST_NONE;
};

#endif //DPITUNNEL_CLI_H
