#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <time.h>

#include "fcgi_stdio.h"
#define QUERY_STRING getenv("QUERY_STRING")
#define REMOTE_ADDR getenv("REMOTE_ADDR")
#define ToHex(Y) (Y>='0'&&Y<='9'?Y-'0':Y-'A'+10)

int checkIpList(char* ip) {
    struct sockaddr_in struct_ip;
    inet_aton(ip, &struct_ip.sin_addr);
    unsigned long lip = struct_ip.sin_addr.s_addr;

    FILE *fp;
    if(fp = fopen("/usr/local/oncenter/conf/iplist.txt", "r")) {
        char buffer[256] = {0};
        char *p = NULL;
        while(fgets(buffer, sizeof(buffer), fp) != NULL) {
            int field = 0, iflag = 0;
            int len = strlen(buffer);
            char* p = NULL;
            int i = 0, fieldLen = 0;
            for(i=0;i<len;i++) {
                if(buffer[i] != ' ' && iflag == 0) {
                    field += 1;
                    iflag = 1;
                }
                if(buffer[i] == ' ' && iflag == 1)
                    iflag = 0;
                if(p == NULL && field == 2 ) {
                    p = buffer + i;
                    fieldLen = i;
                }
                if(p != NULL && buffer[i] == ' ')
                    break;
            }
            fieldLen = i - fieldLen;
            p[fieldLen] = 0;
            struct sockaddr_in antelope;
            inet_aton(p, &antelope.sin_addr);
            unsigned long listip = antelope.sin_addr.s_addr;
            if(lip==listip) {
                return 1;
            }
        }
    }

    return 0;

}

int checkShutHost(char* host) {
    FILE *fp;
    if(fp = fopen("/usr/local/oncenter/conf/shut.list", "r")) {
        char buffer[256] = {0};
        char *p = NULL;
        while(fgets(buffer, sizeof(buffer), fp) != NULL) {
            buffer[strlen(buffer)-1] = 0;
            if(!strcmp(host,buffer)) {
                return 1;
            }
        }
    }

    return 0;
}

void getParam(const char *name, char *value) {
    char *pos = strstr(QUERY_STRING,name);
    if(pos) {
        pos += strlen(name);
        if(*pos == '=') {
            pos++;
            while (*pos && *pos != '&') {
                if (*pos == '%') {
                    *value++ = (char)ToHex(pos[1]) * 15 + ToHex(pos[2]);
                    pos += 3;
                } else if(*pos == '+'){
                    *value++ = ' ';
                    pos++;
                } else {
                    *value++ = *pos++;
                }
            }
                *value++ = '\0';
                return;
        }
    }

    strcpy(value, "undefine");
    return;
}

int main() {
    char *blank = "";
    char myhost[25] = "";
    while(FCGI_Accept() >= 0) {
        FCGI_printf("Content-type:text/html\r\n\r\n");
        if(!strcmp(QUERY_STRING,blank)) {
            FCGI_printf("param error");
            continue;
        }
        if(checkIpList(REMOTE_ADDR)) {
            //FCGI_printf("REMOTE_ADDR: %s allowed\n", REMOTE_ADDR);
            //FCGI_printf("QUERY_STRING: %s\n", QUERY_STRING);
            getParam("host", myhost);
            FILE *log;
            log = fopen("/dev/shm/shut.log","a+");
            time_t logtime;
            logtime = time((time_t *)0);
            if(checkShutHost(myhost)) {
                FCGI_printf("%s_schedule_allowed\n", myhost);
                fprintf(log, "[%ld] %s %s schedule_allowed\n", logtime, REMOTE_ADDR, myhost);
            } else {
                FCGI_printf("%s_schedule_forbidden\n", myhost);
                fprintf(log, "[%ld] %s %s schedule_forbidden\n", logtime, REMOTE_ADDR, myhost);
            }
           fclose(log);
        } else {
            FCGI_printf("%s deny\n", REMOTE_ADDR);
        }
    }
}
