#include "dpitunnel-cli.h"

#include "socket.h"
#include "desync.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <chrono>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <iostream>
#include <thread>
#include <unistd.h>

extern struct Profile_s Profile;

int count_hops(std::string server_ip, int server_port) {
	int sock;
	std::atomic<bool> flag(true);
	std::atomic<int> local_port_atom(-1);
	int status;
	std::thread sniff_thread;
	std::string sniffed_handshake_packet;
	sniff_thread = std::thread(sniff_handshake_packet, &sniffed_handshake_packet,
					server_ip, server_port, &local_port_atom, &flag, &status);
	auto start = std::chrono::high_resolution_clock::now();
	if(init_remote_server_socket(sock, server_ip, server_port) == -1) {
		// Stop sniff thread
		flag = false;
		if(sniff_thread.joinable()) sniff_thread.join();
		close(sock);
		return -1;
	}
	auto stop = std::chrono::high_resolution_clock::now();
	unsigned int connect_time = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();

	// Get local port to choose proper SYN, ACK packet
	struct sockaddr_in local_addr;
	socklen_t len = sizeof(local_addr);
	if(getsockname(sock, (struct sockaddr *) &local_addr, &len) == -1) {
		std::cerr << "Failed to get local port. Errno: " << std::strerror(errno) << std::endl;
		// Stop sniff thread
		flag = false;
		if(sniff_thread.joinable()) sniff_thread.join();
		close(sock);
		return -1;
	}
	int local_port = ntohs(local_addr.sin_port);
	local_port_atom.store(local_port);

	// Get received ACK packet
	if(sniff_thread.joinable()) sniff_thread.join();
	if(status == -1) {
		std::cerr << "Failed to capture handshake packet" << std::endl;
		close(sock);
		return -1;
	}

	// Fill server address
        struct sockaddr_in serv_addr;
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = inet_addr(server_ip.c_str());
        serv_addr.sin_port = htons(server_port);
        std::memset(serv_addr.sin_zero, '\0', sizeof(serv_addr.sin_zero));

	// Create raw socket to send packets with low ttl
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if(sockfd == -1) {
                std::cerr << "Sniff raw socket creation failure. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
                return -1;
        }

	// Tell system we will include IP header in packet
        int yes = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &yes, sizeof(yes)) < 0) {
                std::cerr << "Failed to enable IP_HDRINCL. Errno: " << std::strerror(errno) << std::endl;
		close(sock);
                close(sockfd);
                return -1;
        }

	// Send packet, increase ttl, wait for ACK
	std::string sniffed_ack_packet;
	std::string packet_fake;
	std::string data_empty(255, '\x00');
	unsigned int ttl = 1;
	flag.store(true);
	uint8_t flags = TH_PUSH | TH_ACK;
	sniff_thread = std::thread(sniff_ack_packet, &sniffed_ack_packet, server_ip, server_port, local_port, &flag);
	while(flag.load() && ttl <= 255) {
		packet_fake = form_packet(sniffed_handshake_packet, data_empty.c_str(), ttl, rand() % 65535,
						ttl, 0, 1, 128, true, &flags);
		if(send_string_raw(sockfd, packet_fake, packet_fake.size(),
			(struct sockaddr*) &serv_addr, sizeof(serv_addr)) == -1) {
			// Stop sniff thread
			flag.store(false);
			if(sniff_thread.joinable()) sniff_thread.join();
			close(sock);
			close(sockfd);
			return -1;
		}

		ttl++;
	}

	// Wait for ACK packet to come
	std::this_thread::sleep_for(std::chrono::milliseconds(2 * connect_time));
	// Stop sniff thread
	flag.store(false);
	if(sniff_thread.joinable()) sniff_thread.join();

	close(sock);
	close(sockfd);

	// Check if it received any packet
	if(sniffed_ack_packet.empty())
		return -1;
	// Get ACK num from received packet to know on which packet server reply
        iphdr* ip_h = (iphdr*) &sniffed_ack_packet[0];
        tcphdr* tcp_h = (tcphdr*) (&sniffed_ack_packet[0] + ip_h->ihl * 4);
	unsigned int ack_2 = ntohl(tcp_h->ack_seq);
	// Get ACK from first packet received during handshake
	ip_h = (iphdr*) &sniffed_handshake_packet[0];
	tcp_h = (tcphdr*) (&sniffed_handshake_packet[0] + ip_h->ihl * 4);
	unsigned int ack_1 = ntohl(tcp_h->ack_seq);

	unsigned int hops = ack_2 - ack_1;
	if(hops < 1 || hops > 255)
		return -1;
	return hops;
}

int init_remote_server_socket(int & server_socket, std::string server_ip, int server_port) {
	// Init remote server socket
	server_socket = socket(AF_INET, SOCK_STREAM, 0);
	if(server_socket == -1) {
		std::cerr << "Can't create remote server socket. Errno " << std::strerror(errno) << std::endl;
		return -1;
	}

	// Add port and address
	struct sockaddr_in server_address;
	server_address.sin_family = AF_INET;
	server_address.sin_port = htons(server_port);

	if(inet_pton(AF_INET, server_ip.c_str(), &server_address.sin_addr) <= 0) {
		std::cerr << "Invalid remote server ip address" << std::endl;
		return -1;
	}

	// If window size specified by user, set maximum possible window scale to 128 to make server split Server Hello
	if(Profile.window_scale_factor != -1) {
		int buflen = 65536 << (Profile.window_scale_factor - 1);
		if(setsockopt(server_socket, SOL_SOCKET, SO_RCVBUFFORCE, &buflen, sizeof(buflen)) < 0) {
			std::cerr << "Can't setsockopt on socket. Errno: " << std::strerror(errno) << std::endl;
			return -1;
		}
	}

	// Connect to remote server
	if(connect(server_socket, (struct sockaddr *) &server_address, sizeof(server_address)) < 0) {
		std::cerr << "Can't connect to remote server. Errno: " << std::strerror(errno) << std::endl;
		return -1;
	}

	// Set timeouts
	struct timeval timeout;
	timeout.tv_sec = 0;
	timeout.tv_usec = 10;
	if(setsockopt(server_socket, SOL_SOCKET, SO_SNDTIMEO, (char *) &timeout, sizeof(timeout)) < 0 ||
		setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout, sizeof(timeout)) < 0) {
		std::cerr << "Can't setsockopt on socket. Errno: " << std::strerror(errno) << std::endl;
		return -1;
        }

	return 0;
}

int recv_string(int socket, std::string & message, unsigned int & last_char,
		struct timeval * timeout /*= NULL*/, unsigned int * recv_time /*= NULL*/) {

	std::chrono::time_point<std::chrono::high_resolution_clock> start, stop;
	if(recv_time != NULL)
		start = std::chrono::high_resolution_clock::now();

	ssize_t read_size;

	// Set receive timeout on socket
	struct timeval timeout_predef;
	timeout_predef.tv_sec = 0;
	timeout_predef.tv_usec = 10;
	if(timeout != NULL)
		if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO,
				(char *) timeout,
				sizeof(timeout_predef)) < 0) {
			std::cerr << "Can't setsockopt on socket. Errno: " << std::strerror(errno) << std::endl;
			return -1;
		}

	while(true) {
		read_size = recv(socket, &message[0], message.size(), 0);
		if(recv_time != NULL)
			stop = std::chrono::high_resolution_clock::now();
		if(read_size < 0) {
			if(errno == EWOULDBLOCK)	break;
			if(errno == EINTR)      continue; // All is good. It is just interrrupt
			else {
				std::cerr << "There is critical read error. Can't process client. Errno: "
					<< std::strerror(errno) << std::endl;
				return -1;
			}
		}
		else if(read_size == 0) {last_char = read_size; return -1;}

		if(recv_time != NULL && *recv_time != 0)
			*recv_time = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start).count();

		if(timeout != NULL) {
			if(setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (char *) &timeout_predef, sizeof(timeout_predef)) < 0) {
				std::cerr << "Can't setsockopt on socket. Errno: " << std::strerror(errno) << std::endl;
				return -1;
			}
		}

		break;
	}

	// Set position of last character
	last_char = read_size < 0 ? 0 : read_size;

	return 0;
}

int send_string(int socket, const std::string & string_to_send, unsigned int last_char, unsigned int split_position /*= 0*/) {

	// Check if string is empty
	if(last_char == 0)
		return 0;

	size_t offset = 0;

	while(last_char - offset != 0) {
		ssize_t send_size;
		if(split_position == 0)
			send_size = send(socket, string_to_send.c_str() + offset, last_char - offset, 0);
		else
			send_size = send(socket, string_to_send.c_str() + offset,
					last_char - offset < split_position ? last_char - offset < split_position : split_position, 0);

		if(send_size < 0) {
			if(errno == EINTR)      continue; // All is good. It is just interrrupt.
			else {
				std::cerr << "There is critical send error. Can't process client. Errno: "
                                        << std::strerror(errno) << std::endl;
				return -1;
			}
		}

		if(send_size == 0)
			return -1;

		offset += send_size;
	}

	return 0;
}

int send_string_raw(int socket, const std::string & string_to_send,
			unsigned int last_char, struct sockaddr* serv_addr, unsigned int serv_addr_size) {

	// Check if string is empty
	if(last_char == 0)
		return 0;

	if(sendto(socket, &string_to_send[0], last_char, 0, serv_addr, serv_addr_size) < 0) {
		std::cerr << "Failed to send packet from raw socket. Errno: "
			<< std::strerror(errno) << std::endl;
		return -1;
	}

	return 0;
}
