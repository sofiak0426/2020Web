#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <memory.h>
#include <unistd.h>
#include <fcntl.h>
#include <string>
#include <queue>
#include <thread>
#include <mutex>
#include <iostream>
#include "account.cpp"
#include "ssl.cpp"
using namespace std;

#define BLEN 150
#define MESLEN 1000

/*globals*/
int PORT = 0;
mutex mut;

/*buffers*/
char buf[BLEN];
char req[BLEN];

/*SSL*/
SSL_CTX* ctx;
SSL* ssl;
EVP_PKEY* pKey;
X509* crt;

/*Account Lists*/
AccountList accountList;

/*Register*/
void reg(string input)
{
	/*string processing*/
	input = input.substr(input.find("#") + 1);
	string username = input.substr(0,input.find("#"));
	input = input.substr(input.find("#") + 1);
	int init_balance = stoi(input.substr(0, input.length()));

	/*add acount to list*/
	if(accountList.add(username, init_balance) == 0)//Successfully registered
		strcpy(req, "100 OK\n");
	else//Username is already registered
		strcpy(req, "210 FAIL\n");
}

/*Login*/
void login(string input, struct sockaddr_in addr)
{
	/*specify username, ip address and port number*/
	string username = input.substr(0, input.find("#"));
	input = input.substr(input.find("#") + 1);
	int portNum = stoi(input.substr(0,input.length()));
	addr.sin_port = htons(portNum);

	/*set client to online*/
	int result = accountList.set_online(username, addr);
	if(result == 0)//successfuly set to online
	{
		string cur_balance = to_string(accountList.get_account(username) -> get_balance());
		string onlineNum = to_string(accountList.get_onlineNum());
		strcat(strcat(strcat(strcat(req,cur_balance.c_str()),"\n"),onlineNum.c_str()),"\n");
		strcat(req,accountList.get_onlineList().c_str());
	}
	else if (result == 1) //The user has already logged in
		strcpy(req,"This account has been logged in!\n");
	else //The user does not exist
		strcpy(req,"220 AUTH_FAIL\n");
}

/*List*/
void list(string username)
{
	string cur_balance = to_string(accountList.get_account(username)-> get_balance());
	string onlineNum = to_string(accountList.get_onlineNum());
	strcat(strcat(strcat(strcat(req,cur_balance.c_str()),"\n"),onlineNum.c_str()),"\n");
	strcat(req, accountList.get_onlineList().c_str());
}

/*Transaction*/
void trans(string input)
{
	/*process string*/
	string from_user = input.substr(0, input.find("#"));
	input = input.substr(input.find("#") + 1);
	int amount = stoi(input.substr(0, input.find("#")));
	input = input.substr(input.find("#") + 1);
	string to_user = input.substr(0, input.length());

	/*modify balance*/
	mut.lock();
	accountList.get_account(from_user)-> change_balance(amount * (-1));
	accountList.get_account(to_user) -> change_balance(amount);
	mut.unlock();
	accountList.print();
	cout << "\n";
}

/*Exit*/
void exit(string username)
{
	accountList.set_offline(username);
	strcpy(req, "Bye");
}

struct Task
{
	SSLConnection taskSSL;
	string taskUser;
	string taskStr;
};

class Threadpool
{
	private:
		thread* connectionPool[maxThread];
		thread* worker;
		queue <SSLConnection> connection_list;
		queue <Task> tasks;
	public:
		Threadpool();
		void add_con(struct SSLConnection ssl_con);
		void* do_connection();
		void* do_task();
};

Threadpool::Threadpool()
{
	for(int i = 0; i < maxThread; i++)
		connectionPool[i] = new thread(&Threadpool::do_connection, this);
	this-> worker = new thread(&Threadpool::do_task, this);
}

void Threadpool::add_con(struct SSLConnection ssl_con)
{
	mut.lock();
	this -> connection_list.push(ssl_con);
	mut.unlock();
}

/*for threads in the connection pool*/
void* Threadpool::do_connection()
{
	struct SSLConnection ssl_con;
	ssl_con.ssl = NULL;
	ssl_con.socketfd = -1;
	string cur_user;

	while(true)
	{
		mut.lock();
		if(connection_list.size() > 0 && ssl_con.socketfd == -1)//if there is a waiting user and there is no socket assigned
		{
			ssl_con = connection_list.front();
			connection_list.pop();
		}
		mut.unlock();

		if (ssl_con.socketfd != -1) //if a socket is assinged to thread
		{
			memset(buf, '\0', sizeof(buf));
			if(SSL_read(ssl_con.ssl, buf, sizeof(buf)) > 0)
			{
				string bstr(buf);
				struct Task t = {ssl_con, "", bstr};
				if((t.taskStr.substr(t.taskStr.find("#") + 1).find("#") == string::npos) &&
				t.taskStr.find("REGISTER") != 0 && t.taskStr.find("List") != 0 &&
				t.taskStr.find("Exit") != 0) // if login is called, set current login user
					cur_user = t.taskStr.substr(0, t.taskStr.find("#"));
				t.taskUser = cur_user; //Further calls are from current user
				tasks.push(t);
				if(t.taskStr.find("Exit") == 0) //if exit: reset current user
					cur_user = "";
			}
			else //if the client has suddenly disconnected
			{
				close(ssl_con.socketfd);
				SSL_shutdown(ssl_con.ssl);
				SSL_free(ssl_con.ssl);
				ssl_con.socketfd = -1;
			}
		}
	}
}

/*main functioning thread that checks the correct command and call correct function*/
void* Threadpool::do_task()
{
	struct SSLConnection ssl_con;
	struct Task t = {ssl_con,"",""};
	while(true)
	{
		t = {ssl_con,"",""};
		/*get task*/
		mut.lock();
		if(tasks.size() > 0) //if there is a task in the queue
		{
			t = tasks.front();
			tasks.pop();
			cout << t.taskStr << endl;
		}
		mut.unlock();
			
		/*deal with task*/
		if (t.taskStr != "")
		{
			memset(req, '\0', sizeof(req));
			/*Register*/
			if (t.taskStr.find("REGISTER") == 0)
				reg(t.taskStr);
			/*List*/
			else if(t.taskStr.find("List") == 0)
				list(t.taskUser);
			/*Exit*/
			else if(t.taskStr.find("Exit") == 0)
				exit(t.taskUser);
			/*Login*/
			else if (t.taskStr.substr(t.taskStr.find("#") + 1).find("#") == string::npos)
			{
				struct sockaddr_in addr;
				socklen_t addr_len = sizeof(addr);
				getpeername(t.taskSSL.socketfd, (struct sockaddr*) &addr, &addr_len);
				login(t.taskStr, addr);
			}
			/*Transaction*/
			else
			{
				trans(t.taskStr);
				continue;
			}
			cout << req << endl;
			SSL_write(t.taskSSL.ssl,req,strlen(req));
		}
	}
}

int main(int argc, char*argv[])
{
	std::setbuf(stdout, NULL);
	
	/*create socket for general use*/
	int listen_socketfd = socket(AF_INET, SOCK_STREAM, 0);
	int flags = fcntl(listen_socketfd, F_GETFL, 0);
	fcntl(listen_socketfd, F_SETFL, flags | O_NONBLOCK);
	struct sockaddr_in this_addr;
	PORT = atoi(argv[1]);

	/*SSL*/
	ctx_init(&ctx, SSLv23_server_method());
	privateKey_gen(&pKey);
	cert_gen(&pKey, &crt);
	if(load_certificates(&ctx, &crt, &pKey) == -1)
	{
		cerr << "Cannot load certificates!" << endl;
		return -1;
	}

	/*specify host IP*/
	memset(&this_addr, 0, sizeof(this_addr));
	this_addr.sin_family = AF_INET;
	this_addr.sin_addr.s_addr = INADDR_ANY;
	this_addr.sin_port = htons(PORT);

	/*bind and listen*/
	if(bind(listen_socketfd, (struct sockaddr*)&this_addr, sizeof(this_addr)) < 0){
		cout << "Binding Failed!" << endl;
		return -1;
	}
	cout << "Server is now listening..." << endl;
	listen(listen_socketfd, maxThread);

	/*create thread pool and accept clients*/
	Threadpool pool;
	int client_fd = -1;
	fd_set rfd;
	timeval timeout = {2,0};
	while(true)
	{
		FD_ZERO(&rfd);
		FD_SET(listen_socketfd, &rfd);
		if(select(listen_socketfd + 1, &rfd, NULL, NULL, &timeout) == -1) //the listening socket is not connected
			continue;
		else // listening socket has some content
		{
			if(FD_ISSET(listen_socketfd, &rfd))
			{
				struct sockaddr_in c_addr;
				socklen_t c_len = sizeof(c_addr);
				int client_fd = accept(listen_socketfd, (struct sockaddr*) &c_addr, &c_len);
				if(client_fd == -1)
					cout << "Connection failed" << endl;
				else
					cout << "Connection accepted" << endl;
				/*SSL connection*/
				ssl = SSL_new(ctx);
				SSL_set_fd(ssl, client_fd);
				if (SSL_accept(ssl) == -1)
				{
					cout << "SSL_error" << endl;
					close(client_fd);
					SSL_shutdown(ssl);
					SSL_free(ssl);
				}
				else
				{
					SSL_write(ssl, "Connected to Server!", strlen("Connected to Server!"));
					struct SSLConnection ssl_con;
					ssl_con.ssl = ssl;
					ssl_con.socketfd = client_fd;
					pool.add_con(ssl_con);
				}
			}
		}
	}
	SSL_CTX_free(ctx);
	EVP_PKEY_free(pKey);
	X509_free(crt);
	return 0;
}