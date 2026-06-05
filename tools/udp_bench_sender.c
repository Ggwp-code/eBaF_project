#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define EBAF_MAGIC 0x45424146u
#define EBAF_VERSION 1
#define EBAF_ACTION_ENCRYPT 1
#define EBAF_IV_BYTES 16
#define EBAF_BLOCK_BYTES 16
#define EBAF_HEADER_BYTES 24
#define MAX_UDP_PAYLOAD 65507

static uint64_t monotonic_ns(void)
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
		return 0;
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static int parse_uint(const char *text, unsigned int min, unsigned int max,
		      unsigned int *out)
{
	char *end = NULL;
	unsigned long value;

	errno = 0;
	value = strtoul(text, &end, 10);
	if (errno != 0 || end == text || *end != '\0' || value < min || value > max)
		return -1;
	*out = (unsigned int)value;
	return 0;
}

int main(int argc, char **argv)
{
	unsigned int payload_bytes = 32;
	unsigned int duration_sec;
	unsigned int port;
	struct sockaddr_in dst = {};
	uint64_t deadline;
	uint64_t sent = 0;
	uint8_t packet[MAX_UDP_PAYLOAD];
	uint16_t body_len;
	int fd;

	if (argc < 4 || argc > 5) {
		fprintf(stderr, "usage: %s HOST PORT DURATION_SEC [PAYLOAD_BYTES]\n", argv[0]);
		return 2;
	}
	if (parse_uint(argv[2], 1, 65535, &port) != 0 ||
	    parse_uint(argv[3], 1, 3600, &duration_sec) != 0 ||
	    (argc == 5 && parse_uint(argv[4], 16, MAX_UDP_PAYLOAD - EBAF_HEADER_BYTES,
				     &payload_bytes) != 0)) {
		fprintf(stderr, "invalid numeric argument\n");
		return 2;
	}
	if ((payload_bytes % EBAF_BLOCK_BYTES) != 0 ||
	    payload_bytes + EBAF_HEADER_BYTES > MAX_UDP_PAYLOAD) {
		fprintf(stderr, "payload bytes must be 16-byte aligned and fit UDP\n");
		return 2;
	}

	memset(packet, 0, sizeof(packet));
	packet[0] = (uint8_t)(EBAF_MAGIC >> 24);
	packet[1] = (uint8_t)(EBAF_MAGIC >> 16);
	packet[2] = (uint8_t)(EBAF_MAGIC >> 8);
	packet[3] = (uint8_t)EBAF_MAGIC;
	packet[4] = EBAF_VERSION;
	packet[5] = EBAF_ACTION_ENCRYPT;
	body_len = htons((uint16_t)payload_bytes);
	memcpy(packet + 6, &body_len, sizeof(body_len));
	for (unsigned int i = 0; i < EBAF_IV_BYTES; i++)
		packet[8 + i] = (uint8_t)i;
	memset(packet + EBAF_HEADER_BYTES, 'A', payload_bytes);
	packet[EBAF_HEADER_BYTES + payload_bytes - 1] = 1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		perror("socket");
		return 1;
	}

	dst.sin_family = AF_INET;
	dst.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, argv[1], &dst.sin_addr) != 1) {
		fprintf(stderr, "invalid host: %s\n", argv[1]);
		close(fd);
		return 2;
	}

	deadline = monotonic_ns() + (uint64_t)duration_sec * 1000000000ull;
	while (monotonic_ns() < deadline) {
		ssize_t rc = sendto(fd, packet, EBAF_HEADER_BYTES + payload_bytes, 0,
				    (struct sockaddr *)&dst, sizeof(dst));

		if (rc < 0) {
			perror("sendto");
			close(fd);
			return 1;
		}
		sent++;
	}

	close(fd);
	printf("%llu\n", (unsigned long long)sent);
	return 0;
}
