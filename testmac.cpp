#include <cstring>
#include <fstream>
#include <functional>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <vector>

#if defined(__linux__)
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#elif defined(_WIN32)
#include <Iphlpapi.h>
#include <windows.h>
#include <winsock2.h>
#endif

void trim(std::string &src) {
  int i = src.length() - 1;
  for (; i >= 0; --i) {
    if (src[i] != ' ' && src[i] != '\t' && src[i] != '\n' && src[i] != '\r') {
      break;
    }
  }
  src = src.substr(0, i + 1);

  i = 0;
  for (; i < src.length(); ++i) {
    if (src[i] != ' ' && src[i] != '\t' && src[i] != '\n' && src[i] != '\r') {
      break;
    }
  }
  src = src.substr(i);
}

void split(const std::string &line, std::vector<std::string> &pieces,
           const std::string del, const bool ignoreEmpty = true) {
  size_t begin = 0;
  size_t pos = 0;
  pieces.clear();
  std::string token;
  while ((pos = line.find(del, begin)) != std::string::npos) {
    if (pos > begin) {
      token = line.substr(begin, pos - begin);
      pieces.push_back(token);
    } else if (!ignoreEmpty) {
      pieces.push_back("");
    }
    begin = pos + del.size();
  }

  if (pos > begin) {
    token = line.substr(begin, pos - begin);
    pieces.push_back(token);
  } else if (!ignoreEmpty) {
    pieces.push_back("");
  }

  if (ignoreEmpty) {
    std::vector<std::string> tmp;
    tmp.clear();
    for (size_t i = 0; i < pieces.size(); ++i) {
      if (pieces[i] != "")
        tmp.push_back(pieces[i]);
    }
    pieces = tmp;
    tmp.clear();
  }
}

#if defined(__linux__)
std::string traverse_mac_addr(std::string &device_name) {
  std::string ret = "";
  ifreq ifr;
  ifconf ifc;
  char buf[1024];
  char local_mac[128] = {0};

  int sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
  if (sock == -1) {
    std::cout << "failed to get sock" << std::endl;
    return ret;
  }

  ifc.ifc_len = sizeof(buf);
  ifc.ifc_buf = buf;
  if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
    std::cout << "failed to get ifconf" << std::endl;
    return ret;
  }

  ifreq *it = ifc.ifc_req;
  const ifreq *const end = it + (ifc.ifc_len / sizeof(ifreq));

  for (; it != end; ++it) {
    strcpy(ifr.ifr_name, it->ifr_name);
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
      if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
          char temp_str[10] = {0};
          memcpy(temp_str, ifr.ifr_hwaddr.sa_data, 6);
          sprintf(local_mac, "%02X-%02X-%02X-%02X-%02X-%02X",
                  temp_str[0] & 0xff, temp_str[1] & 0xff, temp_str[2] & 0xff,
                  temp_str[3] & 0xff, temp_str[4] & 0xff, temp_str[5] & 0xff);
          ret = local_mac;
          device_name = it->ifr_name;
          break;
        }
      }
    }
  }

  return ret;
}
#endif

bool get_net_info(std::string &device_name, std::string &mac, std::string &ip,
                  const std::vector<std::string> target_device_name_list = {}) {
  bool find = false;
  device_name = "";
  mac = "";
  ip = "";

#if defined(__linux__)
  struct ifreq ifr;
  int fd = socket(AF_INET, SOCK_DGRAM, 0);

  char local_mac[128] = {0};

  // device name
  {
    for (size_t i = 0; i < target_device_name_list.size(); ++i) {
      strcpy(ifr.ifr_name, target_device_name_list[i].c_str());
      if (0 == ioctl(fd, SIOCGIFHWADDR, &ifr)) {
        char temp_str[10] = {0};
        memcpy(temp_str, ifr.ifr_hwaddr.sa_data, 6);
        sprintf(local_mac, "%02X-%02X-%02X-%02X-%02X-%02X", temp_str[0] & 0xff,
                temp_str[1] & 0xff, temp_str[2] & 0xff, temp_str[3] & 0xff,
                temp_str[4] & 0xff, temp_str[5] & 0xff);
        mac = local_mac;
        device_name = target_device_name_list[i];
        break;
      }
    }
    if ("" == device_name) {
      mac = traverse_mac_addr(device_name);
    }
  }

  // ip
  {
    if ("" != device_name) {
      int fd;
      struct ifreq ifr;
      fd = socket(AF_INET, SOCK_DGRAM, 0);
      // ip v4
      ifr.ifr_addr.sa_family = AF_INET;
      strncpy(ifr.ifr_name, device_name.c_str(), IFNAMSIZ - 1);
      ioctl(fd, SIOCGIFADDR, &ifr);

      ip = inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr);
      find = true;
    }
  }

#elif defined(_WIN32)
  PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
  unsigned long stSize = sizeof(IP_ADAPTER_INFO);
  int nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
  int netCardNum = 0;
  int IPnumPerNetCard = 0;
  if (ERROR_BUFFER_OVERFLOW == nRel) {
    delete pIpAdapterInfo;
    pIpAdapterInfo = (PIP_ADAPTER_INFO) new BYTE[stSize];
    nRel = GetAdaptersInfo(pIpAdapterInfo, &stSize);
  }

  if (ERROR_SUCCESS == nRel) {
    PIP_ADAPTER_INFO hIpAdapterInfo = pIpAdapterInfo;
    for (size_t i = 0; i < target_device_name_list.size(); ++i) {
      while (pIpAdapterInfo) {
        if (0 == strcmp(target_device_name_list[i].c_str(),
                        pIpAdapterInfo->Description)) {
          for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) {
            if (i < pIpAdapterInfo->AddressLength - 1) {
              char temp_str[10] = {0};
              sprintf(temp_str, "%02X-", pIpAdapterInfo->Address[i] & 0xff);
              mac += temp_str;
            } else {
              char temp_str[10] = {0};
              sprintf(temp_str, "%02X", pIpAdapterInfo->Address[i] & 0xff);
              mac += temp_str;
            }
          }
          device_name = target_device_name_list[i];
          IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
          ip = pIpAddrString->IpAddress.String;
          find = true;
          break;
        }
        pIpAdapterInfo = pIpAdapterInfo->Next;
      }
    }
    if (!find) {
      pIpAdapterInfo = hIpAdapterInfo;
      for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) {
        if (i < pIpAdapterInfo->AddressLength - 1) {
          char temp_str[10] = {0};
          sprintf(temp_str, "%02X-", pIpAdapterInfo->Address[i] & 0xff);
          mac += temp_str;
        } else {
          char temp_str[10] = {0};
          sprintf(temp_str, "%02X", pIpAdapterInfo->Address[i] & 0xff);
          mac += temp_str;
        }
      }
      device_name = pIpAdapterInfo->Description;
      IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
      ip = pIpAddrString->IpAddress.String;
      find = true;
    }

    /*
    while (pIpAdapterInfo) {
      std::cout << "net card number : " << ++netCardNum << std::endl;
      std::cout << "adapter name : " << pIpAdapterInfo->AdapterName
                << std::endl;
      std::cout << "description : " << pIpAdapterInfo->Description << std::endl;
      std::cout << "adapter tpye : ";
      switch (pIpAdapterInfo->Type) {
      case MIB_IF_TYPE_OTHER:
        std::cout << "OTHER" << std::endl;
        break;
      case MIB_IF_TYPE_ETHERNET:
        std::cout << "ETHERNET" << std::endl;
        break;
      case MIB_IF_TYPE_TOKENRING:
        std::cout << "TOKENRING" << std::endl;
        break;
      case MIB_IF_TYPE_FDDI:
        std::cout << "FDDI" << std::endl;
        break;
      case MIB_IF_TYPE_PPP:
        std::cout << "PPP" << std::endl;
        break;
      case MIB_IF_TYPE_LOOPBACK:
        std::cout << "LOOPBACK" << std::endl;
        break;
      case MIB_IF_TYPE_SLIP:
        std::cout << "SLIP" << std::endl;
      }
      std::cout << "MAC : ";
      for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) {
        if (i < pIpAdapterInfo->AddressLength - 1) {
          printf("%02X-", pIpAdapterInfo->Address[i]);
        } else {
          printf("%02X\n", pIpAdapterInfo->Address[i]);
        }
      }
      std::cout << "IP : " << std::endl;
      IP_ADDR_STRING *pIpAddrString = &(pIpAdapterInfo->IpAddressList);
      do {
        std::cout << "IP number per card : " << ++IPnumPerNetCard << std::endl;
        std::cout << "IP address : " << pIpAddrString->IpAddress.String
                  << std::endl;
        std::cout << "IP mask : " << pIpAddrString->IpMask.String << std::endl;
        std::cout << "gate way : "
                  << pIpAdapterInfo->GatewayList.IpAddress.String << std::endl;
        pIpAddrString = pIpAddrString->Next;
      } while (pIpAddrString);
      pIpAdapterInfo = pIpAdapterInfo->Next;
      std::cout
          << "----------------------------------------------------------------"
          << std::endl;
    }
    */
  }

  if (pIpAdapterInfo) {
    delete pIpAdapterInfo;
  }
#endif

  return find;
}

#if defined(__linux__)
std::string get_cpu_info() {
  std::string ret = "";

  std::string line = "";
  std::ifstream fs("/proc/cpuinfo");
  while (std::getline(fs, line)) {
    if (line.find("model name") != line.npos) {
      std::vector<std::string> arr;
      split(line, arr, ":");
      if (arr.size() != 2)
        continue;
      trim(arr[1]);

      ret = arr[1];
      break;
    }
  }
  return ret;
}
#endif

int main() {
  std::string device_name, mac_addr, ip;
  if (get_net_info(device_name, mac_addr, ip)) {
    std::cout << "device_name : " << device_name << std::endl;
    std::cout << "mac addr : " << mac_addr << std::endl;
    std::cout << "ip : " << ip << std::endl;
  }
#if defined(__linux__)
  std::cout << "cpu : " << get_cpu_info() << std::endl;
#endif
  return 0;
}