#include "dpitunnel-cli.h"

#include "dns.h"
#include "ssl.h"
#include "utils.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <sys/types.h>
#include <sys/socket.h>
#include <vector>
#include <netdb.h>

#include <dnslib/exception.h>
#include <dnslib/message.h>
#include <dnslib/rr.h>

#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <cpp-httplib/httplib.h>

#include <base64.h>

extern struct Profile_s Profile;

int resolve_host_over_dns(const std::string & host, std::string & ip) {

	ip.resize(50, ' ');

	struct addrinfo hints, *res;
	std::memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;

	int err = getaddrinfo(host.c_str(), NULL, &hints, &res);
	if(err != 0) {
		std::cerr << "Failed to get host address. Error: " << std::strerror(errno) << std::endl;
		return -1;
	}

	while(res) {
		char addrstr[100];
		inet_ntop(res->ai_family, res->ai_addr->sa_data, addrstr, sizeof(addrstr));
		if(res->ai_family == AF_INET) {// If current address is ipv4 address

			void *ptr = &((struct sockaddr_in *) res->ai_addr)->sin_addr;
			inet_ntop(res->ai_family, ptr, &ip[0], ip.size());

			size_t first_zero_char = ip.find(' ');
			ip = ip.substr(0, first_zero_char);

			// Free memory
			freeaddrinfo(res);
			return 0;
		}
		res = res->ai_next;
	}

	// Free memory
	freeaddrinfo(res);

	return -1;
}

size_t writeFunction(void *ptr, size_t size, size_t nmemb, std::string* data) {
	data->append((char*) ptr, size * nmemb);
	return size * nmemb;
}

int resolve_host_over_doh(const std::string & host, std::string & ip) {
	// Make DNS query
	dns::Message dns_msg;
	dns_msg.setQr(dns::Message::typeQuery);

	// Add A query to find ipv4 address
	std::string host_full = host;
	if(host_full.back() != '.') host_full.push_back('.');
	dns::QuerySection *qs = new dns::QuerySection(host_full);
	qs->setType(dns::RDATA_A);
	qs->setClass(dns::QCLASS_IN);

	dns_msg.addQuery(qs);
	dns_msg.setId(rand() % 65535);
	dns_msg.setRD(1);

	// Encode message
	uint dns_msg_size;
	std::string dns_buf(2048, ' ');
	dns_msg.encode(&dns_buf[0], dns_buf.size(), dns_msg_size);
	dns_buf.resize(dns_msg_size);
	// Encode with base64
	dns_buf = base64_encode(dns_buf);

	std::string serv_host = Profile.doh_server;
	std::string path;
	// Remove scheme (https://)
	if(serv_host.size() >= 8 && serv_host.substr(0, 8) == "https://")
		serv_host.erase(0, 8);
	// Proper process test.com and test.com/dns-query urls
	if(serv_host.back() == '/') serv_host.pop_back();
	if(last_n_chars(serv_host, 10) == "/dns-query") {
		serv_host.resize(serv_host.size() - 10);
		path += "/dns-query?dns=";
	} else path += "/?dns=";
	path += dns_buf;

	// Make request
	httplib::SSLClient cli(serv_host.c_str());

	// Load CA store
	X509_STORE *store = gen_x509_store();
	if(store == NULL) {
		std::cerr << "Failed to parse CA Bundle" << std::endl;
		return -1;
	}
	cli.set_ca_cert_store(store);
	cli.enable_server_certificate_verification(true);

	// Add header
	httplib::Headers headers = {
		{ "Accept", "application/dns-message" }
	};

	std::string response_string;
	httplib::Result res = cli.Get(path.c_str());
	if(res && res->status == 200)
		response_string = res->body;
	else {
		std::cerr << "Failed to make DoH request. Errno: " << res.error() << std::endl;
		return -1;
	}

	// Parse response
	dns::Message dns_msg_resp;
	try {
		dns_msg_resp.decode(response_string.c_str(), response_string.size());
	} catch(dns::Exception& e) {
		std::cerr << "Exception occured while parsing DNS response: " << e.what() << std::endl;
		return -1;
	}

	std::vector<dns::ResourceRecord*> answers = dns_msg_resp.getAnswers();
	for(dns::ResourceRecord *rr : answers) {
		if(rr->getType() != dns::RDATA_A) continue;
		dns::RDataA *rdata = (dns::RDataA *) rr->getRData();
		unsigned char *addr = rdata->getAddress();
		std::ostringstream addr_str;
		addr_str << (unsigned int) addr[0] << '.' << (unsigned int) addr[1]
				<< '.' << (unsigned int) addr[2] << '.' << (unsigned int) addr[3];
		ip = addr_str.str();

		return 0;
	}

	return -1;
}

int resolve_host(const std::string & host, std::string & ip) {

	if (host.empty())
		return -1;

	// Check if host is IP
	struct sockaddr_in sa;
	int result = inet_pton(AF_INET, host.c_str(), &sa.sin_addr);
	if(result > 0) {
		ip = host;
		return 0;
	}

	if(Profile.doh)
		return resolve_host_over_doh(host, ip);
	else
		return resolve_host_over_dns(host, ip);
}
