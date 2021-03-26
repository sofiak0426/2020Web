#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>
#include <string>
#include <thread>
#include <mutex>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <iostream>
#include "ssl.cpp"

using namespace std;

//#define PORT 8000
#define BLEN 150
#define USERLEN 50

/*buffers*/
char buf[BLEN]; //buffer
char P2Pbuf[BLEN];
char req[BLEN]; //request for some port

/*sockets*/
int serv_socketfd = 0;
int client_socketfd = 0;
int listen_socketfd = 0;

/*SSL*/
SSL_CTX* toServerCtx;
SSL_CTX* othercCtx;
SSL_CTX* clientCtx;
SSL* toServerSSL;
SSL* othercSSL;
SSL* clientSSL;
EVP_PKEY* pKey;
X509* crt;

/*global var and mutex*/
int CPORT = 0;
int PORT = 0;
bool running = true; //whether this program is running
bool logged = false;
mutex mut;

/*current client information*/
char login_user[USERLEN]; // the user currently logged in
int balance = 0;

/*function for registration*/
//TO-DO: disconnect but not terminate the app after registration
void reg()
{
	cout << "------------------------" << endl;
	char username[USERLEN];
	char init_deposit[10];				
	cout << "Username:";
	cin >> username;
	cout << "First deposit:";
	do{
		cin >> init_deposit;
		if (atoi(init_deposit) == 0) //the initial deposit is not valid
		{
			cout << "Please enter a valid cash amount." << endl;
			cout << "First deposit:";
		}
	}while(atoi(init_deposit) == 0);

	strcat(strcat(strcat(strcat(req, "REGISTER#"),username),"#"),init_deposit);
	SSL_write(toServerSSL, req, strlen(req));
	if(SSL_read(toServerSSL, buf, sizeof(buf)) > 0)
	{
		if (strstr(buf,"100 OK"))
			cout << "Successfully registered as: " << username << endl;
		else
			cout << "This account name is already used!" << endl;
	}
	else
		cerr << "No connection..." << endl;
	cout << "------------------------" << endl;
}

/*function for login*/
void login()
{
	if(login_user[0] != '\0') //this connection has already logged in
	{
		cout << "Already logged in as:" << login_user << endl;
		return;
	}
	else
	{
		cout << "------------------------" << endl;
		cout << "Username:"; 
		cin >> login_user;
	}
	char port[7];
	sprintf(port, "%d", CPORT);
	strcat(strcat(strcat(req, login_user),"#"),port);
	SSL_write(toServerSSL, req, strlen(req));
	if(SSL_read(toServerSSL, buf, sizeof(buf)) > 0)
	{
		if (strstr(buf, "This account has been logged in!"))
			cerr << buf << endl;
		else if(strstr(buf,"220 AUTH_FAIL"))
		{
			cerr << "Login failed!" << endl;
			memset(login_user,'\0', sizeof(login_user));
		}
		else
		{
			cout << "Successfully logged in as: " << login_user << endl;
			logged = true;
			balance = atoi(strtok(buf, "\n"));
			cout << "Your current balance:" << balance << endl;
		}
	}
	else
		cerr << "No connection..." << endl;
	cout << "------------------------" << endl;
}

/*function for requiring info from server*/
void list()
{
	cout << "------------------------" << endl;
	if(logged)
	{
		strcpy(req,"List");
		SSL_write(toServerSSL, req, strlen(req));
		if(SSL_read(toServerSSL, buf, sizeof(buf)) > 0)
		{
			char same_as_buf[BLEN];
			strncpy(same_as_buf, buf, strlen(buf));
			char* balance = strtok(same_as_buf, "\n");
			char* online_num = strtok(NULL, "\n");
			//TO-DO: check if the balances correspond to each otther
			cout << "Your current account balance: " << balance << endl; 
			cout << "Number of clients online:" << online_num << endl;
			cout << "Online clients:" << endl;
			char* name[atoi(online_num)];
			for(int i = 0; i < stoi(online_num); i++)
				name[i] = strtok(NULL, "\n");
			for(int i = 0; i < stoi(online_num); i++)
			{
				name[i] = strtok(name[i], "#");
				cout << name[i] << endl;
			}
		}
		else
			cerr << "No connection...";
	}
	else
		cout << "You haven't logged in! Please log in first." << endl;

	cout << "------------------------" << endl;
}

/*function for connecting with another client and perform transaction*/
void trans()
{
	char dest[USERLEN];
	char pay[10];
	if(logged)
	{
		list();
		/*check user*/
		cout << "Specify user of transaction:" << endl;
		do{
			cin >> dest;
			if(!strstr(buf, dest))
			{
				cout << "User is not here...\n" << "------------------------" << endl;
				return;
			}
			else if(strstr(dest, login_user))
				cout << "You cannot transfer money to your own account! Specify user of transaction:" << endl;
		}while(!strstr(buf,dest) ||strstr(dest, login_user));

		cout << "How much are you going to pay? Enter cash amount or 0 to end transaction" << endl;
		do{
			cin >> pay;
			if(atoi(pay) > balance)
				cout << "You do not have enough money to transfer! Enter another cash amount or 0 to end transaction" << endl;
		}while(atoi(pay) > balance);
		if(atoi(pay) == 0) //end the transaction
		{
			cout << "------------------------" << endl;
			return;
		}
		
		/*get destination ip address*/
		char * ptr = strstr(buf, dest);
		ptr = strtok(ptr, "#");
		char * dest_ip = strtok(NULL, "#");
		char * dest_port = strtok(NULL, "#");

		/*specify destination ip*/
		struct sockaddr_in dest_addr;
		memset(&dest_addr, 0, sizeof(dest_addr));
		dest_addr.sin_family = AF_INET;
		if((dest_addr.sin_addr.s_addr = inet_addr(dest_ip)) == -1)
		{
			cerr << "Invalid IP Address";
			return;
		}
		dest_addr.sin_port = htons(atoi(dest_port));

		/*start connecting with destination client*/
		if(connect(client_socketfd, (struct sockaddr *) &dest_addr, sizeof(dest_addr)) < 0)
		{
			cerr << "Connection failed with: " << dest << endl;
			return;
		}
		else
		{
			/*SSL setup*/
			ctx_init(&clientCtx, SSLv23_client_method());
			if(load_certificates(&clientCtx, &crt, &pKey) == -1)
			{
				cerr << "Cannot load certificates!" << endl;
				return;
			}
			/*SSL connection*/
			clientSSL = SSL_new(clientCtx);
			SSL_set_fd(clientSSL, client_socketfd);
			if(SSL_connect(clientSSL) == -1)
				cout << "SSL_error" << endl;
			else
			{
				show_certs(clientSSL);
				memset(req, '\0', strlen(req));
				strcat(strcat(strcat(strcat(strcat(req, login_user),"#"), pay),"#"),dest);
				SSL_write(clientSSL, req, strlen(req));			
				memset(buf, '\0', sizeof(buf));
				/*Money transfer*/
				if(SSL_read(clientSSL, buf, sizeof(buf)) > 0)
				{
					cout << "Your money has successfully transferred!" << endl;
					mut.lock();
					balance -= atoi(pay);
					cout << "Current balance: " << balance << endl;
					mut.unlock();
				}
				close(client_socketfd);
				SSL_shutdown(clientSSL);
				SSL_free(clientSSL);
				SSL_CTX_free(clientCtx);
			}
		}
	}
	else
		cout << "You haven't logged in! Please log in first." << endl;

	cout << "------------------------" << endl;
	return;
}

bool logout()
{
	memset(req, '\0', strlen(req));
	if(login_user[0] == '\0')//the user is not logged in
	{
		cout << "You are not logged in!" << endl;
		return false;
	}
	strcpy(req,"Exit");
	SSL_write(toServerSSL, req, strlen(req));
	memset(buf, '\0', sizeof(buf));
	if(SSL_read(toServerSSL, buf, sizeof(buf)) > 0)
	{
		cout << "Logging out from: "<< login_user << endl;
		memset(login_user, '\0', sizeof(login_user));
		close(serv_socketfd);
		SSL_shutdown(toServerSSL);
		SSL_free(toServerSSL);
		SSL_CTX_free(toServerCtx);
		running = false;
	}
	else
	{
		cerr << "No connection...";
		return false;
	}
}

void *commanding() 
{	
	/*Specifying user commands*/
	int command = 0;
	while(running)
	{
		cout << "Do something: Press 1 to register | Press 2 to login | Press 3 to view info\n Press 4 to perform transaction | Press 5 to log out" << endl;
		scanf("%d", &command);
		memset(req, '\0', strlen(req));
		memset(buf, '\0', sizeof(buf));
		switch(command){
			case 1:{
				reg();	
				break;
			}
			case 2:{
				login();
				break;
			}
			case 3:{
				list();
				break;
			}
			case 4:{
				trans();
				break;
			}
			case 5:{
				logout();
				break;
			}
		}
	}
}

void *receiving()
{
	/*set listening socket to non-blocking*/
	int flags = fcntl(listen_socketfd, F_GETFL, 0);
	fcntl(listen_socketfd, F_SETFL, flags | O_NONBLOCK);

	/*SSL setup*/
	ctx_init(&othercCtx,SSLv23_server_method());
	if(load_certificates(&othercCtx, &crt, &pKey) == -1)
	{
		cerr << "Cannot load certificates!" << endl;
		abort();
	}
	
	/*specify host IP*/
	struct sockaddr_in this_addr;
	memset(&this_addr, 0, sizeof(this_addr));
	this_addr.sin_family = AF_INET;
	this_addr.sin_addr.s_addr = INADDR_ANY;
	this_addr.sin_port = htons(CPORT);

	/*binding and listening*/
	bind(listen_socketfd, (struct sockaddr*)&this_addr, sizeof(this_addr));
	listen(listen_socketfd, 5);
	fd_set rfd;
	timeval timeout = {2,0};
	while(running)
	{
		FD_ZERO(&rfd);
		FD_SET(listen_socketfd, &rfd);
		if(select(listen_socketfd + 1, &rfd, NULL, NULL, &timeout) == -1) //the listening socket is not connected
			continue;
		else // listening socket has some content
		{
			if(FD_ISSET(listen_socketfd, &rfd))
			{
				struct sockaddr_in otherc_addr;
				socklen_t otherc_len = sizeof(otherc_addr);
				int otherc_fd = accept(listen_socketfd, (struct sockaddr*) &otherc_addr, &otherc_len);
				/*SSL connection*/
				othercSSL = SSL_new(othercCtx);
				SSL_set_fd(othercSSL, otherc_fd);
				if(SSL_accept(othercSSL) == -1)
				{
					cout << "SSL_error" << endl;
					close(otherc_fd);
					SSL_shutdown(othercSSL);
					SSL_free(othercSSL);
				}
				else
				{
					/*deal with transcation*/
					if(SSL_read(othercSSL,P2Pbuf,sizeof(P2Pbuf)) > 0)
					{
						SSL_write(toServerSSL,P2Pbuf, strlen(P2Pbuf));
						char* from = strtok(P2Pbuf, "#");
						char* money = strtok(NULL, "#");
						mut.lock();
						balance += atoi(money);
						mut.unlock();
						cout << "------------------------" << endl; 
						cout << "Received $" << money << " from user " << from << endl;
						cout << "Current balance: " << balance << endl;
						cout << "------------------------" << endl;
						memset(req, '\0', strlen(req));
						strcpy(req, "100 OK");
						SSL_write(othercSSL, req, strlen(req));
						close(otherc_fd);
						SSL_shutdown(othercSSL);
						SSL_free(othercSSL);
						cout << "Do something: Press 1 to register | Press 2 to login | Press 3 to view info\n Press 4 to perform transaction | Press 5 to log out" << endl;
					}
				}
			}
		}
	}
}

//command line argument: the IP address for server
int main(int argc,  char*argv[])
{
	std::setbuf(stdout, NULL);
	memset(login_user, '\0', sizeof(login_user));

	/*create two socket: one for server and one for other clients*/
	serv_socketfd = socket(AF_INET, SOCK_STREAM, 0);
	client_socketfd = socket(AF_INET, SOCK_STREAM, 0);
	listen_socketfd = socket(AF_INET, SOCK_STREAM, 0);

	/*SSL initialization*/
	ctx_init(&toServerCtx, SSLv23_client_method());
	privateKey_gen(&pKey);
	cert_gen(&pKey,&crt);
	if(load_certificates(&toServerCtx, &crt, &pKey) == -1)
	{
		cerr << "Cannot load certificates!" << endl;
		return -1;
	}

	struct sockaddr_in serv_addr;
	PORT = atoi(argv[2]);

	/*specify host IP*/
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	if((serv_addr.sin_addr.s_addr = inet_addr(argv[1])) == -1)
	{
		cerr << "Invalid IP Address";
		return -1;
	}
	serv_addr.sin_port = htons(PORT);

	/*initiate socket*/
	serv_socketfd = socket(AF_INET,SOCK_STREAM,0);
	if(serv_socketfd == -1)
	{
		cerr << "Creating socket failed!" << endl;
		return -1;
	}

	/*connection*/
	if(connect(serv_socketfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		cerr << "Connection failed"<< endl;
		return -1;
	}
	else
	{
		toServerSSL = SSL_new(toServerCtx);
		SSL_set_fd(toServerSSL, serv_socketfd);
		if(SSL_connect(toServerSSL) == -1)
			cout << "SSL_error" << endl;
		else
		{
			show_certs(toServerSSL);
			SSL_read(toServerSSL, buf, sizeof(buf));
			cout << buf << endl;
			memset(buf, '\0', sizeof(buf));
		}
	}

	/*specifying port for client usage*/
	srand(time(NULL));
	CPORT = (rand() % 10000) + 1024;

	//note: when compiling add -lpthread
	thread com_thread(commanding);
	thread recv_thread(receiving);
	com_thread.join();
	recv_thread.join();
	EVP_PKEY_free(pKey);
	X509_free(crt);
	return 0;
}
