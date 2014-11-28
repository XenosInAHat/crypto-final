/**
	@file atm.cpp
	@brief Top level ATM implementation file

    Usage: atm [port #]
 */
#include <iostream>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

// Port range to prevent using reserved ports
#define MINIMUM_PORT 1024
#define MAXIMUM_PORT 49151

int main(int argc, char* argv[])
{
    // Make sure user provides proper number of arguments
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}

    // RSA key generation (same as the process in bank.cpp)
    RSA *rsa;
    int num_bits = 1024;
    BIGNUM *e = BN_new();
    BN_set_word(e, RSA_F4);

    char *pub_key, *pri_key;
    int pub_len, pri_len;

    rsa = RSA_new();

    RSA_generate_key_ex(rsa, num_bits, e, 0);
    BIO *pri = BIO_new(BIO_s_mem());
    BIO *pub = BIO_new(BIO_s_mem());

    PEM_write_bio_RSAPrivateKey(pri, rsa, NULL, NULL, 0, NULL, NULL);
    PEM_write_bio_RSAPublicKey(pub, rsa);

    pri_len = BIO_pending(pri);
    pub_len = BIO_pending(pub);

    BIO_read(pri, pri_key, pri_len);
    BIO_read(pub, pub_key, pub_len);
    
    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';
    // -------------- End RSA key generation --------------- //
    // =========
    // Variables
    // =========
    // temp:     temporary variable used to make sure the port number argument
    //           provided is a valid port number
    // proxport: the port on which the proxy server will listen for 
    //           messages by the atm client (i.e. this file)

    unsigned short temp, proxport;

    // Check if atoi is successful. If not, the provided argument isn't a
    // valid port number.
    if(!(temp = atoi(argv[1])))
    {
        printf("Error: Please provide a valid port number.\n");
        return -1;
    }

    // Check if the port number is above or below the minimum threshold. 
    // Meant to prevent the user from trying to use a port that is already 
    // reserved by other processes/protocols.
    if(temp < MINIMUM_PORT || temp > MAXIMUM_PORT)
    {
        printf("Error: Please use a port number above 1023.\n");
        return -1;
    }

    // Once the argument has passed the checks, store it in the proper location
    proxport = temp;

    // Create the socket
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

    // Check if the socket was properly created.
	if(!sock)
	{
		printf("Error: Failed to create socket.\n");
		return -1;
	}

    // Create an IP socket address
	sockaddr_in addr;

    // Set the address family to AF_INET (required)
	addr.sin_family = AF_INET;

    // Set the address port (in network byte order as defined by the definition)
	addr.sin_port = htons(proxport);

    // Basically, set the address to localhost
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;

    // Attempt to make a connection
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}
	
	//input loop
	char buf[80];
	while(1)
	{
        // Flag to determine if the ATM should even attempt to send a
        // message to the bank
        int sending = 0;
		char packet[1024];
		int length = 1;

        // Empty the buffer and packet for each command
        memset(buf, 0, sizeof(buf));
        memset(packet, 0, sizeof(packet));

        // Print to the console to give the user a visible prompt
		printf("atm> ");
        // Read user input from stdin (typically, the command line)
		fgets(buf, 79, stdin);

		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		// Parse user input (via command line into ATM shell)
        // --------------------------------------------------
        //
        // Check if 'login' is in command
        if(strstr(buf, "login"))
        {
            memset(packet, 0, sizeof(packet));
            // Compare full command with only three options because laziness
            if(!strcmp(buf, "login Alice") || 
               !strcmp(buf, "login Bob") || 
               !strcmp(buf, "login Eve"))
            {
                // Copy the input buffer (buf) to the packet buffer (packet)
                strncpy(packet, buf, strlen(buf));
                sending = 1;
            }
            else
            {
                printf("Error: Usage: login [username].\n");
            }
        }
        // Compare the full command to 'balance'
        else if(!strcmp(buf, "balance"))
        {
            // Copy the input buffer (buf) to the packet buffer (packet)
            strncpy(packet, buf, strlen(buf));
            sending = 1;
        }
        // Check if 'withdraw' exists in the command
        else if(strstr(buf, "withdraw"))
        {
            // Variable to keep track of tokens;
            char *toks;
            // Variable to keep buf unchanged after using strtok
            char temp[80];
            // Variable to keep track of arguments for withdraw command
            unsigned short count = 0;

            // Copy buf's data into temp
            strncpy(temp, buf, strlen(buf));

            // Get the first token 
            toks = strtok(temp, " ");

            // Tokenize the input and keep track of the number of arguments
            while(toks != NULL)
            {
                toks = strtok(NULL, " ");
                ++count;
            }

            // Decrease count to account for last, extraneous loop
            --count;

            // If the number of arguments isn't 1, the command is faulty (the
            // assignment specified that the usage is "withdraw [amount]")
            if(count != 1)
            {
                printf("Error: Usage: withdraw [amount].\n");
            }
            else
            {
                // Copy the input buffer (buf) to the packet buffer (packet)
                strncpy(packet, buf, strlen(buf));
                sending = 1;
            }
        }
        // Compare the command to 'logout'
        else if(!strcmp(buf, "logout"))
        {
            // If the user logs out, we want to close the connection, so we
            // break from the while loop
			break;
        }
        else if(strstr(buf, "transfer"))
        {
            // Variable to keep track of tokens;
            char *toks;
            
            // Variable to keep buf unchanged after using strtok
            char temp[80];
            // Variable to keep track of arguments for withdraw command
            unsigned short count = 0;

            // Copy buf's data into temp
            strncpy(temp, buf, strlen(buf));

            // Get the first token 
            toks = strtok(temp, " ");

            // Tokenize the input and keep track of the number of arguments
            while(toks)
            {
                toks = strtok(NULL, " ");
                ++count;
            }

            // Decrease count to account for last, extraneous loop
            --count; 

            if(count != 2)
            {
                printf("Error: Usage: transfer [amount] [username].\n");
            }
            else
            {
                // Copy the input buffer (buf) to the packet buffer (packet)
                strncpy(packet, buf, strlen(buf));
                sending = 1;
            }
        }
		
		// Send the packet through the proxy to the bank.
        if(sending == 1)
        {
            // First, send the packet length
            length = strlen(buf);
            if(sizeof(int) != send(sock, &length, sizeof(int), 0))
            {
                printf("Error: Failed to send packet length.\n");
                break;
            }

            // Then, send the packet itself
            if(length != send(sock, (void*)packet, length, 0))
            {
                printf("Error: Failed to send packet.\n");
                break;
            }
        }
		
        // Handle receiving messages from the bank (via the proxy)
        // -------------------------------------------------------
        // 
        // Attempt to receive the packet length
        memset(packet, 0, sizeof(packet));
		if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
		{
			printf("Error: Failed to read packet length.\n");
			break;
		}
        // Check if the packet is too long for the purposes of this assignment
		if(length >= 1024)
		{
			printf("Error: Packet is too long.\n");
			break;
		}
        // Attempt to read the packet itself
		if(length != recv(sock, packet, length, 0))
		{
			printf("Error: Failed to read packet.\n");
			break;
		}

        // Handle the response from the bank asking for a PIN
        printf("%s\n", packet);
        int sent_pin = 0;
        if(!strcmp(packet, "PIN") && sent_pin == 0)
        {
            // temp: used to format the buffer

            char temp[80];
            printf("atm> PIN: ");

            // Clear the buffer before writing data to it
            memset(buf, 0, sizeof(buf));
            memset(temp, 0, sizeof(temp));
            // Get user input
            fgets(buf, 79, stdin);
            // Clear off last newline
            buf[strlen(buf)-1] = '\0';
            // Clear packet before writing data to it
            memset(packet, 0, sizeof(packet));

            // Start creating message (prefix it with 'PIN')
            strncpy(temp, "PIN ", 4);
            // Add user's PIN to message
            strncat(temp, buf, strlen(buf));
            // Write message to the packet
            strncpy(packet, temp, strlen(temp));

            // length: packet length
            length = strlen(temp);
            if(sizeof(int) != send(sock, &length, sizeof(int), 0))
            {
                printf("Error: Failed to send packet length.\n");
                break;
            }

            // Then, send the packet itself
            if(length != send(sock, (void*)packet, length, 0))
            {
                printf("Error: Failed to send packet.\n");
                break;
            }

            sent_pin = 1;
            memset(packet, 0, sizeof(packet));
            if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
            {
                printf("Error: Failed to read packet length.\n");
                break;
            }
            // Check if the packet is too long for the purposes of this assignment
            if(length >= 1024)
            {
                printf("Error: Packet is too long.\n");
                break;
            }
            // Attempt to read the packet itself
            if(length != recv(sock, packet, length, 0))
            {
                printf("Error: Failed to read packet.\n");
                break;
            }
        }
	}
	
	// Close the socket before exiting the program
	close(sock);
	return 0;
}
