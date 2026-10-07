#ifndef FLOWRAY_SUPP_FUNCS_H
#define FLOWRAY_SUPP_FUNCS_H

#include <cstdint>
#include <string>

std::string state_to_string(std::uint8_t state);
std::string protocol_to_string(int protocol);
std::string family_to_string(int family);
std::string result_to_string(int result);
std::string dns_type_to_string(std::uint16_t type);

#endif //FLOWRAY_SUPP_FUNCS_H
