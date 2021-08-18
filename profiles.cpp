#include "dpitunnel-cli.h"

#include "profiles.h"
#include "netiface.h"

#include <iostream>

// Map contains net interface name to that apply profile and profile settings
std::map<std::string, struct Profile_s> Profiles;
extern struct Profile_s Profile;

void add_profile(std::string name, Profile_s profile) {
	Profiles[name] = profile;
}

int change_profile(std::string * choosen_profile_name /*= NULL*/) {
	if(Profiles.empty())
		return 0;

	std::string iface = get_current_iface_name();
	if(iface.empty()) {
		std::cerr << "Failed to find default route" << std::endl;
		return -1;
	}
	std::string wifi_point = get_current_wifi_name(iface);

	std::cout << "Netiface: " << iface;
	if(!wifi_point.empty())
		std::cout << ", Wi-Fi point name: " << wifi_point;
	std::cout << std::endl;

	auto search = Profiles.find(iface + (wifi_point.empty() ? "" : (':' + wifi_point)));
	if(search != Profiles.end())
		Profile = search->second;
	else {
		search = Profiles.find("default");
		if(search != Profiles.end())
			Profile = search->second;
		else {
			std::cerr << "Failed to find profile" << std::endl;
			return -1;
		}
	}

	if(choosen_profile_name != NULL)
		*choosen_profile_name = search->first;

	return 0;
}
