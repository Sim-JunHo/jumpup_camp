#pragma once
#include <dirent.h>
#include "../header/protocol/all.h"

dirent *getInterfaceDirList();
bool getInterfaceIPAddress(char *, ip_addr *);
void getInterfaceMacAddress(char *, mac_addr *);