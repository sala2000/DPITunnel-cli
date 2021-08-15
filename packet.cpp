#include "packet.h"

#include <regex>

int parse_request(const std::string & request, std::string & method, std::string & host, int & port) {
	// Extract method
	size_t method_end_position = request.find(' ');
	if(method_end_position == std::string::npos)
		return -1;
	method = request.substr(0, method_end_position);

	// Extract hostname an port if exists
	std::string regex_string = "[-a-zA-Z0-9@:%._\\+~#=]{2,256}\\.[-a-z0-9]{1,16}(:[0-9]{1,5})?";
	std::regex url_find_regex(regex_string);
	std::smatch match;

	if(std::regex_search(request, match, url_find_regex) == 0)
		return -1;

	// Get string from regex output
	std::string found_url = match.str(0);

	// Remove "www." if exists
	size_t www = found_url.find("www.");
	if(www != std::string::npos)
		found_url.erase(www, 4);

	// Check if port exists
	size_t port_start_position = found_url.find(':');
	if(port_start_position == std::string::npos) {
		// If no set default port
		if(method == "CONNECT")	port = 443;
		else port = 80;
		host = found_url;
	} else {
		// If yes extract port
		port = std::stoi(found_url.substr(port_start_position + 1, found_url.size() - port_start_position));
		host = found_url.substr(0, port_start_position);
	}

	return 0;
}
