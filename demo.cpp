#include <iostream>
#include<stdio.h>    //client
#include<stdlib.h>  
#include<unistd.h>  
#include<sys/types.h>  
#include<sys/socket.h>  
#include<netinet/in.h>  
#include<netdb.h> 
#include<stdint.h>
#include<chrono>
#include<iostream>
#include<thread>    
#include<functional>       
#include<sys/epoll.h>
#include <string>
#include <mutex>
#include <string.h>
#include "json.hpp"

enum ErrorStatus : int
{
	OK                  = 0,
    ERRR_IP             = 1,
    ERRR_SOCKET         = 2,
    ERRR_CONNECT        = 3,
    ERRR_EPOLLWAIT      = 4,
    ERRR_RECVJSON       = 5,
    ERRR_NOWAITRECV     = 5,
    ERRR_READ           = 6,
    ERRR_EPOLL          = 7,
    ERRR_OVERTIME       = 9
};

using namespace std;

//CRC-8 x8+x2+x+1
unsigned char crc8( const char *vptr, unsigned char len)
{
    const char *data = vptr;
    unsigned crc = 0;
    int i, j;
    for (j = len; j; j--, data++) {
        crc ^= (*data << 8);
        for (i = 8; i; i--) {
            if (crc & 0x8000)
                crc ^= (0x1070 << 3);
            crc <<= 1;
        }
    }
    return (unsigned char)(crc >> 8);
}

int SetTcpClient(uint8_t *send_data, int len)
{
	std::thread([&]()
    {
		int  m_sockfd;
		ErrorStatus m_status = OK;
		std::mutex  m_status_mtx;
		std::string m_ip = "192.168.1.200";
		uint16_t m_port = 2000;

		struct hostent *host;
		if((host=gethostbyname(m_ip.data()))==NULL)
		{
			m_status = ERRR_IP;
			return;
		}

		if((m_sockfd=socket(AF_INET, SOCK_STREAM, 0))==-1){ 
			m_status = ERRR_SOCKET;  
			return;
		} 

		struct sockaddr_in server;  
		bzero(&server,sizeof(server));  
		server.sin_family= AF_INET;  
		server.sin_port = htons(m_port);  
		server.sin_addr =*((struct in_addr *)host->h_addr); 
		
		int flag_check = connect(m_sockfd,(struct sockaddr *)&server,sizeof(server));

		if(flag_check == -1)
		{  
			m_status = ERRR_CONNECT;  
			if(m_sockfd != -1)
			{
				close(m_sockfd);
			}
			return;
		}
		
		bool barcode_update_flag = true;

		int count_read = 0;
		while(1)
		{
        	const int retry_times_limit = 10;

			if(barcode_update_flag)
        	{
				//4.发送数据到服务器
				//const char* sendBuf = "start";
				//write(m_sockfd,sendbuf,subscript);
				send(m_sockfd,send_data,len,0);

				for(int i=0; i < len; ++i)
				{
					printf("0x%02x ", *(send_data+i));
				}
				printf("\n");

			}

			uint8_t receiveBuf[50];
			memset(receiveBuf, 0, sizeof(receiveBuf));

			//接收服务器的消息
			if(recv(m_sockfd,receiveBuf,50,0) > 0)
			{
                std::cout << "recv response!, size of receiveBuf: " << sizeof(receiveBuf) << std::endl;
				for(int i=0; i < sizeof(receiveBuf); ++i)
                {
                    printf("0x%02x ", receiveBuf[i]);
					if(receiveBuf[i] == 0xd0)
					{
						break;
					}
                }
                printf("\n");
			}
			std::this_thread::sleep_for(std::chrono::microseconds(2000000));
		}
		//5.关闭套接字
		close(m_sockfd);
	}).detach();

	return 0;
}

int main(int argc, char** argv)
{
	//启动客户端
	nlohmann::json msg = nlohmann::json{{"name", "jessy"}, {"age", "3"}};
	std::string  msg_data = msg.dump();
	//unsigned char crc8_t_msg = 0xDC;
	const char * c = msg_data.c_str();
	uint8_t crc8_t_msg = crc8(c, strlen(msg_data.c_str()));
	printf("crc8_t_msg : 0x%02x\n", crc8_t_msg);
	std::cout << strlen(msg_data.c_str()) << std::endl;
	std::cout << msg_data.length() << std::endl;


	uint8_t sendbuf[1024]={0};
	int subscript = 0;
	sendbuf[subscript++] = 0xC0 & 0xFF;
	sendbuf[subscript++] = 0x26 & 0xFF;
	memcpy(&sendbuf[subscript],msg_data.c_str(),strlen(msg_data.c_str()));
	subscript += strlen(msg_data.c_str());
	sendbuf[subscript++] = crc8_t_msg & 0xFF;
	sendbuf[subscript++] = 0xD0 & 0xFF;
	for(int i=0; i < subscript; ++i)
	{
		printf("0x%02x ", sendbuf[i]);
	}
	printf("\n");
	std::cout << subscript << std::endl;
    SetTcpClient(sendbuf, subscript);
    while(1);
	return 0;
}

//1.使用16进制进行通信
//2.使用字符串进行通信
//3.使用json转字符串进行通信