/*

anerd: Asynchronous Network Exchange Randomness Daemon

Copyright 2012 Dustin Kirkland <kirkland@ubuntu.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*/

#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_SIZE 64
#define DEFAULT_DEVICE "/dev/urandom"
#define DEFAULT_PORT 26373
#define DEFAULT_INTERVAL 60
#define DEFAULT_TIMEOUT 250

/*
anerd salt:
*/
uint64_t anerd_salt(uint64_t salt) {
	struct timeval tv;
	struct timezone tz;
	uint64_t this_usec;
	/* Update local timestamp, generate new salt */
	gettimeofday(&tv, &tz);
	this_usec = 1000000 * tv.tv_usec + tv.tv_usec;
	if (salt == 0) {
		srand((unsigned int)time(NULL));
		salt = rand();
	}
	/* Let it wrap */
	salt = salt ^ this_usec;
	return salt;
}

/*
anerd crc:
*/
int anerd_crc(char *data, int len) {
	int i = 0;
	int crc = 0;
	for (i=0; i<len; i++) {
		crc += (unsigned char)data[i];
	}
	return crc;
}

/*
anerd server:
 - Listen for communications on a UDP socket.
 - Take any received input, salt with a bit of local randomness (perhaps the
   time in microseconds between transmissions), and add to the entropy pool.
 - Transmit back to the initiator the same number of bytes of randomness.
*/
int anerd_server(char *device, int size, int port) {
	int sock;
	int addr_len, bytes_read;
	uint64_t salt;
	char *data;
	struct sockaddr_in server_addr, client_addr;
	FILE *fp;
	/* Open the UDP socket */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("Socket");
		exit(1);
	}
	/* Open the random device */
	if ((fp = fopen(device, "a+")) == NULL) {
		perror("fopen");
		exit(1);
	}
	/* Allocate and zero a data buffer to the chosen size */
	if ((data = calloc(size, sizeof(char))) == NULL) {
		perror("calloc");
		exit(1);
	}
	/* Set up and bind the socket */
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = INADDR_ANY;
	bzero(&(server_addr.sin_zero),8);
	if (bind(sock,(struct sockaddr *)&server_addr, sizeof(struct sockaddr)) == -1) {
		perror("bind");
		exit(1);
	}
	addr_len = sizeof(struct sockaddr);
	while (1) {
		/* Receive data over our UDP socket */
		bytes_read = recvfrom(sock, data, size, 0, (struct sockaddr *)&client_addr, &addr_len);
		data[bytes_read] = '\0';
		/* Logging/debug message */
		syslog(LOG_INFO, "Server recv bcast [%d] bytes [%d] from [%s:%d]\n", bytes_read, anerd_crc(data, bytes_read), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		fflush(stdout);
		/* Mix incoming entropy + salt into pool */
		salt = anerd_salt(salt);
		fwrite(data, bytes_read, 1, fp);
		fwrite(&salt, sizeof(uint64_t), 1, fp);
		fflush(fp);
		/* Obtain some entropy for transmission */
		if (fread(data, bytes_read, sizeof(char), fp) > 0) {
			/* Return the favor, sending entropy back to the initiator */
			sendto(sock, data, bytes_read, 0, (struct sockaddr *)&client_addr, sizeof(struct sockaddr));
			syslog(LOG_INFO, "Server sent direct [%d] bytes [%d] to [%s:%d]\n", bytes_read, anerd_crc(data, bytes_read), inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
		} else {
			perror("fread");
		}
	}
	/* Should never get here; clean up if we do */
	free(data);
	close(sock);
	fclose(fp);
	return 0;
}

/*
anerd client:
 - broadcast some randomness to the local network on the anerd UDP port
 - this is intended to "stir the pot", kicking up some randomness
 - it trigger anerd exchanges with any anerd servers on the network
*/
int anerd_client(char *device, int size, int port, int interval) {
	int sock;
	int addr_len, bytes_read;
	struct sockaddr_in server_addr;
	char *data;
	FILE *fp;
	int broadcast = 1;
	struct pollfd ufds;
	uint64_t salt = 0;
	addr_len = sizeof(struct sockaddr);
	/* Allocate and zero a data buffer to the chosen size */
	if ((data = calloc(size, sizeof(char))) == NULL) {
		perror("calloc");
		exit(1);
	}
	/* Setup the UDP socket */
	if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
		perror("socket");
	}
	ufds.fd = sock;
	ufds.events = POLLIN | POLLPRI;
	/* Configure the socket for broadcast */
	if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcast, sizeof broadcast) == -1) {
		perror("setsockopt (SO_BROADCAST)");
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(port);
	server_addr.sin_addr.s_addr = htonl(INADDR_BROADCAST);
	bzero(&(server_addr.sin_zero),8);
	if ((fp = fopen(device, "a+")) == NULL) {
		/* Error reading entropy; skip this round */
		perror("fopen");
		close(sock);
		exit(1);
	}
	/* Periodically trigger a network entropy exchange */
	while (interval > 0) {
		/* Donate some entropy to the local networks */
		if (fread(data, size, sizeof(char), fp) > 0) {
			syslog(LOG_INFO, "Client sent bcast [%d] bytes [%d] to [%s:%d]\n", size, anerd_crc(data, size), inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
			sendto(sock, data, size, 0, (struct sockaddr *)&server_addr, sizeof(struct sockaddr));
		} else {
			perror("fread");
		}
		/* Poll for responses */
		while (poll(&ufds, 1, interval*1000) > 0) {
			/* Accept data over our UDP socket */
			bytes_read = recvfrom(sock, data, size, 0, (struct sockaddr *)&server_addr, &addr_len);
			data[bytes_read] = '\0';
			/* Logging/debug message */
			syslog(LOG_INFO, "Client recv direct [%d] bytes [%d] from [%s:%d]\n", bytes_read, anerd_crc(data, bytes_read), inet_ntoa(server_addr.sin_addr), ntohs(server_addr.sin_port));
			/* Mix incoming entropy + salt into pool */
			salt = anerd_salt(salt);
			fwrite(data, size, 1, fp);
			fwrite(&salt, sizeof(salt), 1, fp);
			fflush(fp);
		}
	}
	/* Should never get here; clean up if we do */
	close(sock);
	free(data);
	fclose(fp);
	return 0;
}

int main(int argc, char *argv[]) {
	int i;
	int interval = DEFAULT_INTERVAL;
	int size = DEFAULT_SIZE;
	int port = DEFAULT_PORT;
	char *device = DEFAULT_DEVICE;
	/* Very naive command-line argument handling */
	for (i=0; i<argc; i++) {
		if (strncmp(argv[i], "-d", 2) == 0) {
			device = argv[++i];
		} else if (strncmp(argv[i], "-i", 2) == 0) {
			interval = atoi(argv[++i]);
		} else if (strncmp(argv[i], "-p", 2) == 0) {
			port = atoi(argv[++i]);
		} else if (strncmp(argv[i], "-s", 2) == 0) {
			size = atoi(argv[++i]);
		}
	}
	/* Set up syslog */
	openlog ("anerd", LOG_PERROR | LOG_CONS | LOG_PID | LOG_NDELAY, LOG_DAEMON);
	if (fork() == 0) {
		/* Fork a client process */
		anerd_client(device, size, port, interval);
	} else {
		/* Fork a server process */
		anerd_server(device, size, port);
	}
}
