#include <netinet/in.h>
#include <arpa/inet.h>
#include <string>
#include <vector>
#include <stdio.h>
#include <iostream>
using namespace std;

const int maxThread = 10;

/*Account*/
class Account
{
	private:
		string username;
		int balance;
		struct sockaddr_in addr;
		int portNum;
	public:
		Account(string username, int init_balance);
		void change_balance(int m);
		string get_username();
		int get_balance();
		in_addr get_ip();
		unsigned short get_port();
		void set_address(struct sockaddr_in addr);
};

Account::Account(string username, int init_balance):username(username), balance(init_balance),portNum(0){} 
void Account::change_balance(int m){this-> balance += m;}
string Account::get_username(){return this-> username;}
int Account::get_balance(){return this->balance;}
in_addr Account::get_ip(){return this->addr.sin_addr;}
unsigned short Account::get_port(){return this->addr.sin_port;}
void Account::set_address(struct sockaddr_in addr){this->addr = addr;}


/*AccountList*/
class AccountList
{
	private:
		vector<Account> list;
		vector<bool> online;
		int len;
	public:
		AccountList();
		void print(); //for testing
		int add(string username, int init_balance);
		int set_online(string username, struct sockaddr_in addr);
		void set_offline(string username);
		Account* get_account(string username);
		int get_onlineNum();
		string get_onlineList();
		bool is_online(string username); //for testing
};

AccountList::AccountList():len(0){}
void AccountList::print()
{
	for (int i = 0; i< len; i++)
		cout << list[i].get_username() << " " << list[i].get_balance() << endl;
}

int AccountList::add(string username, int init_balance)
{
	for(int i = 0; i < len; i++) //check if the current user is used
	{
		if(list[i].get_username() == username)
			return -1;
	}
	Account a(username, init_balance);
	list.push_back(a);
	online.push_back(false);
	len += 1;
	return 0;
}

int AccountList::set_online(string username, struct sockaddr_in addr)
{
	for(int i = 0; i < len; i++)
	{
		if(list[i].get_username() == username && online[i] == false) //successfully logged in
		{
			online[i] = true;
			list[i].set_address(addr);
			return 0;
		}
		else if(list[i].get_username() == username && online[i] == true) // already logged in
			return 1;
		else
			continue;
	}
	return -1; //username does not exist
}

void AccountList::set_offline(string username)
{
	for(int i = 0; i < len; i++)
	{
		if(list[i].get_username() == username)
			online[i] = false;
		sockaddr_in empty_addr;
		list[i].set_address(empty_addr);
	}
}

Account* AccountList::get_account(string username)
{
	for(int i = 0; i < len; i++)
	{
		if(list[i].get_username() == username)
			return &list[i];
	}
}

int AccountList::get_onlineNum()
{
	int cnt = 0;
	for(int i = 0; i < len; i++)
	{
		if (online[i] == true)
			cnt ++;
	}
	return cnt;
}

string AccountList::get_onlineList()
{
	string onlineList = "";
	for (int i = 0; i < len; i++)
	{
		if(online[i] == true)
		{
			onlineList = onlineList + list[i].get_username() + "#";
			onlineList += (string) inet_ntoa(list[i].get_ip()) + "#";
			onlineList += to_string(ntohs(list[i].get_port())) + "\n";
		}
	}
	return onlineList;
}

bool AccountList::is_online(string username)
{
	for(int i = 0; i < len; i++)
	{
		if(list[i].get_username() == username)
		{
			if(online[i] == true)
				return true;
			else
				return false;
		}
	}
}