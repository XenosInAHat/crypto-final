/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <vector>
#include <tuple>

void* client_thread(void* arg);
void* console_thread(void* arg);

typedef std::tuple<char*, unsigned short, int> tuple_list;
std::vector< tuple_list > users;
std::vector <char*> logged_in;

int main(int argc, char* argv[])
{
    // Check for proper command line arguments to start bank
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
    users.clear();
    logged_in.clear();
    // Keep track of bank port
	unsigned short ourport = atoi(argv[1]);
	
	// Create socket for communication between bank and proxy
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	// Create socket's address information
	sockaddr_in addr_l;
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);

    // Set IP address to localhost
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}

    // Create the three users defined by the assignment. PINs are arbitrary and can be changed
    users.push_back( std::tuple<char*, unsigned short, int>("Alice", 1111, 100) );
    users.push_back( std::tuple<char*, unsigned short, int>("Bob", 2222, 50) );
    users.push_back( std::tuple<char*, unsigned short, int>("Eve", 3333, 50) );
	
    // Create the console thread (i.e. the one that handles command line arguments)
	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);
	
	//loop forever accepting new connections
	while(1)
	{
        // Create sockets for connections
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
			
        // Create a thread for the incoming connection
		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)csock);
	}
}

// Functionality to handle clients
void* client_thread(void* arg)
{
    // Keep track of socket information
	int csock = (int)arg;

    // Keep track of the user for this connection
    char *current_user;
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	int length;
	char packet[1024];
	while(1)
	{
        // Clear the packet before receiving packets
        memset(packet, 0, sizeof(packet));

		//read the packet from the ATM
		if(sizeof(int) != recv(csock, &length, sizeof(int), 0))
			break;
        // Check if the packet is too long
		if(length >= 1024)
		{
			printf("packet too long");
			break;
		}
        // Check if recv fails for some reason (like, if it doesn't read the whole packet)
		if(length != recv(csock, packet, length, 0))
		{
			printf("[bank] fail to read packet");
			break;
		}
		
        // Handle login request from ATM client
        if(strstr(packet, "login"))
        {
            // toks: used for tokenizing packet message
            // username: keep track of the username for the login request
            // message: used to prepare a message that will be sent back to the ATM
            // temp: used to hold a temporary copy of the packet to prevent changes
            //       while tokenizing
            char *toks, username[80], message[80];
            char temp[1024];

            // Copy the packet's data into temp
            strncpy(temp, packet, strlen(packet));
            memset(message, 0, sizeof(message));

            // Grab the first token in the string (should be 'login')
            toks = strtok(temp, " ");

            // Grab the next token in the string (should be 'username')
            toks = strtok(NULL, " ");

            // See if there isn't a second token
            if(toks == NULL)
            {
                strncpy(message, "Error: Usage: login [username].", 32);
            }
            // Otherwise, take the (assumed) username and compare it to the list of valid
            // users (defined in the main function)
            else
            {
                // Copy the data from toks into username
                strncpy(username, toks, strlen(toks));

                // Check if user is currently logged on via another ATM client
                if(!(std::find(logged_in.begin(), logged_in.end(), username) == logged_in.end()))
                {
                    printf("Error: User is already logged on.\n");
                    printf("bank> ");
                }
                else
                {
                    // exists: keeps track of the existence of the username in the users list
                    int exists = 0;

                    // Loop through the users list and compare the given username to each name
                    // in the list. If it exists, flip the exists flag
                    for(tuple_list t: users)
                    {
                        if(!strcmp(std::get<0>(t), username))
                        {
                            exists = 1;
                            break;
                        }
                    }

                    // If the username exists, prepare a message to request the user's PIN
                    if(exists == 1)
                    {
                        strncpy(message, "PIN", 4);
                        current_user = username;
                        logged_in.push_back(username); 
                    }
                    // Otherwise, prepare a message stating that the username is invalid
                    else
                    {
                        strncpy(message, "Error: Invalid username.", 25);
                    }
                }
            }

            // Clear the packet before writing to it
            memset(packet, 0, sizeof(packet));
            // Copy the message data into the packet
            strncpy(packet, message, strlen(message));
        }
        // Handle a client request that provides the user's PIN
        else if(strstr(packet, "PIN"))
        {
            // toks: keep track of each token in the packet
            // message: used to prepare messages to be sent
            // temp: stores a copy of the packet for tokenizing
            // pin: stores the PIN provided by the client
            char *toks, message[80];
            char temp[1024];
            unsigned short pin = 0;
            memset(message, 0, sizeof(message));

            // Copy the packet's data into temp
            strncpy(temp, packet, strlen(packet));

            // Grab the first token (should be 'PIN')
            toks = strtok(temp, " ");

            // Grab the second token (should be the user's PIN)
            toks = strtok(NULL, " ");
            // Check if there is no second token
            if(toks == NULL)
            {
                strncpy(message, "Error: Invalid PIN message.", 28);
            }
            // Otherwise, handle the PIN
            else
            {
                // Convert the string to an integer
                pin = atoi(toks);

                // Flag to check if the PIN is valid
                int success = 0;

                // Loop through the users list, find the entry with the current user's 
                // username, and compare the PINs. If the PINs are the same, prepare a
                // message indicating success.
                for(tuple_list t: users)
                {
                    if(!strcmp(current_user, std::get<0>(t)))
                    {
                        if(pin == std::get<1>(t))
                        {
                            memset(message, 0, sizeof(message));
                            strncpy(message, "Login successful.", 18);
                            success = 1;
                        }
                    }
                }

                // Prepare a message if PINs are not the same.
                if(success == 0)
                {
                    strncpy(message, "Error: Invalid PIN.", 20);
                }
            }

            // Clear the packet before setting the data
            memset(packet, 0, sizeof(packet));
            // Copy the message data into the packet
            strncpy(packet, message, strlen(message));
        }
        // Handle a balance request
        else if(!strcmp(packet, "balance"))
        {
            // balance: keep track of user's balance
            // message: used to prepare a message to be sent
            int balance = 0;
            char message[80];
            memset(message, 0, sizeof(message));

            // Loop through the users list and grab the user's current balance
            for(tuple_list t: users)
            {
                if(!strcmp(std::get<0>(t), current_user))
                {
                    balance = std::get<2>(t);
                }
            }
            
            // Clear the packet to prepare for new data
            memset(packet, 0, sizeof(packet));
            // Write the balance to a character array
            snprintf(message, sizeof(message), "Balance: $%d", balance);
            // Copy the message data into the packet
            strncpy(packet, message, strlen(message));
        }
        // Handle a withdraw request
        else if(strstr(packet, "withdraw"))
        {
            // toks: keep track of tokens in packet
            // message: used to prepare message to be sent
            // temp: local copy of packet for tokenizing
            char *toks, message[80];
            char temp[1024];

            // Copy packet data into temp
            strncpy(temp, packet, strlen(packet));

            // Grab first token (should be 'withdraw')
            toks = strtok(temp, " ");

            // Grab second token (should be amount)
            toks = strtok(NULL, " ");
            // Check if second token exists
            if(toks == NULL)
            {
                strncpy(message, "Error: Usage: withdraw [amount].", 33);
            }
            // If it does, handle it
            else
            {
                // Convert the amount to an integer
                int amount = atoi(toks);
                // Keep track of user's balance
                int balance = 0;

                // Loop through users list and find the current user. Write his balance to balance var
                for(tuple_list t: users)
                {
                    if(!strcmp(std::get<0>(t), current_user))
                    {
                        balance = std::get<2>(t);
                        break;
                    }
                }

                // Check if user's balance is below the requested withdrawal amount
                if(balance < amount)
                {
                    strncpy(message, "Error: Balance too low.", 24);
                }
                // If it's not, handle it
                else
                {
                    // Reduce balance by amount specified
                    balance -= amount;
                    // Loop through users list, find the current user, and set his balance
                    // to the new balance
                    for(tuple_list t: users)
                    {
                        if(!strcmp(std::get<0>(t), current_user))
                        {
                            char *temp_user = std::get<0>(t);
                            unsigned short temp_pin = std::get<1>(t);
                            int temp_balance = balance;
                            auto t_new = std::tuple<char*, unsigned short, int>(temp_user, temp_pin, temp_balance);
                            users.push_back(t_new);
                            users.erase(std::remove(users.begin(), users.end(), t), users.end());
                            break;
                        }
                    }

                    // Prepare message for sending
                    snprintf(message, sizeof(message), "$%s withdrawn", toks);
                }
            }

            // Clear packet to prepare for data
            memset(packet, 0, sizeof(packet));
            // Copy message data into packet
            strncpy(packet, message, strlen(message));
        }
        // Handle transfer request
        else if(strstr(packet, "transfer"))
        {
            // toks: Keep track of tokens in packet
            // message: used to prepare messages for sending
            // username: used to keep track of transfer destination
            // temp: local copy of packet for tokenization
            // amount: keep track of transfer amount
            char *toks, message[80], *username;
            char temp[1024];
            int amount = 0;

            // Copy packet data into temp
            strncpy(temp, packet, strlen(packet));

            // Grab the first token (should be 'transfer')
            toks = strtok(temp, " ");

            // Grab the second token (should be amount)
            toks = strtok(NULL, " ");
            // Check if second token exists
            if(toks == NULL)
            {
                strncpy(message, "Error: Usage: transfer [amount] [username]", 43);
            }
            // If it does, keep going
            else
            {
                // Store amount as integer (convert token)
                amount = atoi(toks);
                // Keep track of user's initial balance
                int balance = 0;
                
                // Loop through users list, find the current users, and read his balance
                for(tuple_list t: users)
                {
                    if(!strcmp(std::get<0>(t), current_user))
                    {
                        balance = std::get<2>(t);
                    }
                }

                // Check if the user's balance is too low
                if(balance < amount)
                {
                    strncpy(message, "Error: Balance too low", 23);
                }
                // If it's not, keep going
                else
                {
                    // Grab the third token (should be destination user)
                    toks = strtok(NULL, " ");
                    // Check if third token exists
                    if(toks == NULL)
                    {
                        strncpy(message, "Error: Usage: transfer [amount] [username]", 43);
                    }
                    // If it does, keep going
                    else
                    {
                        // Store destination user
                        username = toks;
                        // Check if the destination is the same as the source (we won't let
                        // this kind of transfer happen)
                        if(!strcmp(username, current_user))
                        {
                            strncpy(message, "Error: Cannot transfer to yourself", 35);
                        }
                        // If it's not, keep going
                        else
                        {
                            // Flag to check if the destination exists
                            int exists = 0;
                            // Loop through the users list, check if the destination exists. If it does,
                            // flip the flag
                            for(tuple_list t: users)
                            {
                                if(!strcmp(std::get<0>(t), username))
                                {
                                    exists = 1;
                                    break;
                                }
                            }

                            // If the destination exists, keep going
                            if(exists == 1)
                            {
                                // Loop through the users list, decrease the user's balance and increase
                                // the destination's balance
                                for(tuple_list t: users)
                                {
                                    if(!strcmp(std::get<0>(t), current_user))
                                    {
                                        char *temp_user = std::get<0>(t);
                                        unsigned short temp_pin = std::get<1>(t);
                                        int temp_balance = balance - amount;
                                        auto t_new = std::tuple<char*, unsigned short, int>(temp_user, temp_pin, temp_balance);
                                        users.erase(std::remove(users.begin(), users.end(), t), users.end());
                                        users.push_back(t_new);
                                        continue;
                                    }

                                    if(!strcmp(std::get<0>(t), username))
                                    {
                                        char *temp_user = std::get<0>(t);
                                        unsigned short temp_pin = std::get<1>(t);
                                        int temp_balance = balance + amount;
                                        auto t_new = std::tuple<char*, unsigned short, int>(temp_user, temp_pin, temp_balance);
                                        users.erase(std::remove(users.begin(), users.end(), t), users.end());
                                        users.push_back(t_new);
                                        continue;
                                    }
                                }

                                // Prepare a success message
                                snprintf(message, sizeof(message), "$%d transferred", amount);
                            }
                            // Otherwise, prepare a failure message
                            else
                            {
                                strncpy(message, "Error: Destination user does not exist.", 40);
                            }
                        }
                    }
                }
            }

            // Clear the packet to prepare for new data
            memset(packet, 0, sizeof(packet));
            // Copy the message data into the packet
            strncpy(packet, message, strlen(message));
        }
        // Handle invalid commands
        else
        {
            // Prepare error message
            char message[80] = "Error: Invalid command.\n";
            // Clear packet for message data
            memset(packet, 0, sizeof(packet));
            // Copy message data into packet
            strncpy(packet, message, strlen(message));
        }
		
		//send the new packet back to the client
        length = strlen(packet);
		if(sizeof(int) != send(csock, &length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}

	}

	printf("[bank] client ID #%d disconnected\n", csock);

	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80];
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
        if(strstr(buf, "deposit"))
        {
            char *toks;
            char temp[80], username[80], amount[80];
            int amt = 0;

            strncpy(temp, buf, strlen(buf));
            toks = strtok(temp, " ");

            toks = strtok(NULL, " ");
            if(toks == NULL)
            {
                printf("Error: Usage: deposit [username] [amount]\n");
            }
            else
            {
                strncpy(username, toks, strlen(toks));

                int exists = 0;
                for(tuple_list t: users)
                {
                    if(!strcmp(std::get<0>(t), username))
                    {
                        exists = 1;
                        break;
                    }
                }

                if(exists == 0)
                {
                    printf("Error: User does not exist.\n");
                }
                else
                {
                    toks = strtok(NULL, " ");
                    if(toks == NULL)
                    {
                        printf("Error: Usage: deposit [username] [amount]\n");
                    }
                    else
                    {
                        strncpy(amount, toks, strlen(toks));
                        amt = atoi(amount);

                        for(tuple_list t: users)
                        {
                            if(!strcmp(std::get<0>(t), username))
                            {
                                char *temp_user = std::get<0>(t);
                                unsigned short temp_pin = std::get<1>(t);
                                int temp_balance = std::get<2>(t) + amt;
                                auto t_new = std::tuple<char*, unsigned short, int>(temp_user, temp_pin, temp_balance);

                                users.erase(std::remove(users.begin(), users.end(), t), users.end());
                                users.push_back(t_new);
                                break;
                            }
                        }

                        printf("Deposit successful.\n");
                    }
                }
            }
        }
        else if(strstr(buf, "balance"))
        {
            char *toks, username[80], temp[80];

            strncpy(temp, buf, strlen(buf));

            toks = strtok(temp, " ");
            
            toks = strtok(NULL, " ");
            if(toks == NULL)
            {
                printf("Error: Usage: balance [username]\n");
            }
            else
            {
                strncpy(username, toks, strlen(toks));
                int exists = 0;

                for(tuple_list t: users)
                {
                    if(!strcmp(std::get<0>(t), username))
                    {
                        printf("Balance: %d\n", std::get<2>(t));
                        exists = 1;
                    }
                }

                if(exists == 0)
                {
                    printf("Error: User does not exist.\n");
                }
            }
        }
	}
}
