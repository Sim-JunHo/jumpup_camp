#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <pcap.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include "../header/protocol/all.h"
#include "../header/packet.h"

#define INTERFACE_PATH "/sys/class/net"

#define BUF_SIZE 18

dirent *getInterfaceDirList()
{
    char interfacePath[64];
    strcpy(interfacePath, INTERFACE_PATH);

    struct dirent *dir;
    DIR *d = opendir(interfacePath);
    if (d)
    {
        while ((dir = readdir(d)) != NULL)
        {
            if (dir->d_type == DT_LNK)
            {
                printf("%s\n", dir->d_name);
            }
        }
        closedir(d);
    }
    return dir;
}

bool getInterfaceIPAddress(char *interface, ip_addr *ipAddress)
{
    bool isFind = false;
    struct ifaddrs *interfaces = NULL;
    struct ifaddrs *temp_addr = NULL;
    int success = 0;
    success = getifaddrs(&interfaces);
    if (success == 0)
    {
        temp_addr = interfaces;
        while (temp_addr != NULL)
        {
            if (temp_addr->ifa_addr->sa_family == AF_INET)
            {
                if (strncmp(temp_addr->ifa_name, interface, sizeof(interface)) == 0)
                {
                    //ip_addr *temp_ip_addr = (struct ip_addr *)&(((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr);
                    //memcpy(ipAddress, temp_ip_addr, sizeof(ip_addr));
                    //printf("%s\n",inet_ntoa(((struct sockaddr_in*)temp_addr->ifa_addr)->sin_addr));
                    in_addr tempAddr = ((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr;
                    //printf("%s\n",inet_ntoa(tempAddr));
                    memcpy(ipAddress, &tempAddr, sizeof(ip_addr));
                    isFind = true;
                }
            }
            temp_addr = temp_addr->ifa_next;
        }
    }
    freeifaddrs(interfaces);
    return isFind;
}

void getInterfaceMacAddress(char *interface, mac_addr *mac)
{
    char buf[BUF_SIZE];
    int fd;
    char interfaceMacAddressPath[64];
    char *interfacePath = "/sys/class/net/";
    char *macPath = "/address";
    sprintf(interfaceMacAddressPath, "%s%s%s", interfacePath, interface, macPath);

    if (0 < (fd = open(interfaceMacAddressPath, O_RDONLY)))
    {
        read(fd, buf, BUF_SIZE);
        close(fd);
    }
    else
    {
        return;
    }
    uint8_t temp_macAddress[6];
    sscanf(buf, "%x:%x:%x:%x:%x:%x", &temp_macAddress[0], &temp_macAddress[1], &temp_macAddress[2], &temp_macAddress[3], &temp_macAddress[4], &temp_macAddress[5]);
    memcpy(mac, &temp_macAddress, sizeof(mac_addr));
}
