#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define strcasecmp _stricmp
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment (lib, "Ws2_32.lib")
#else
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#endif
#include <iostream>
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <functional>
#include <thread>
#include <vector>
#include <string>

#include "Constants.h"
#include "ecdh.h"

#define IS_LITTLE_ENDIAN char (0x0001)
#define _CRT_SECURE_NO_WARNINGS

#define DEFAULT_BUFLEN 2048
#define DEFAULT_PORT "27015"
#define DEFAULT_SERVER_IP "localhost"

/// <summary>
/// Creates the socket.
/// </summary>
/// <returns></returns>
static int createSocket();

/// <summary>
/// Closes the socket.
/// </summary>
static void closeSocket();

/// <summary>
/// Determines if the socket is valid.
/// </summary>
/// <returns></returns>
static int isSocketValid();

/// <summary>
/// Sends the data through the socket.
/// </summary>
/// <param name="data">The data to be sent.</param>
/// /// <param name="dataSize">The size of the data.</param>
/// <returns>The number of bytes sent.</returns>
static size_t sendData(const char* data, size_t dataSize);

/// <summary>
/// Transmits two packets of information to the other side;
/// First, the size of the data (in big-endian).
/// Second, the data itself.
/// </summary>
/// <param name="data">The data to be sent.</param>
/// <param name="dataSize">The size of the data.</param>
/// <returns></returns>
static size_t sendDataWithSize(const char* data, size_t dataSize);

/// <summary>
/// Receives the data through the socket.
/// </summary>
/// <param name="data">The data to be received.</data>
/// <param name="dataSize">The size of the data to retrieve.</param>
/// <returns></returns>
static size_t recvData(char* data, size_t dataSize);

/// <summary>
/// Receives two packets of information from the other side;
/// First, the size of the data (in big-endian).
/// Second, the data itself.
/// </summary>
/// <param name="data">The data to be received.</data>
/// <param name="dataSize">The size of the data to retrieve.</param>
/// <returns></returns>
static bool receiveDataWithSize(char** data, size_t* dataSize);

/// <summary>
/// Connects to the socket.
/// </summary>
/// <param name="host"></param>
/// <param name="port"></param>
/// <returns></returns>
static int connectSocket(const char* host, uint16_t port);

int32_t m_sock = -1;
struct sockaddr_in m_addr;
struct sockaddr_in rm_addr;
struct hostent* hp;

// -------------------------------------------------------------------------
// This simple program demonstrates Diffie-Hellman key exchange with server.
// -------------------------------------------------------------------------
// The purpose of the handshake is to create unique entropy for MTE
// in a secure manner for the Encoder and Decoder.
// The "client" creates the personalization string or ConversationIdentifier.
// the "server" creates the nonce in the form of a timestamp.
// -------------------------------------------------------------------------
int main(int argc, char** argv)
{
	// Connect to the socket.
	int socket_creation = createSocket();
	if (socket_creation == 0)
	{
		std::cerr << "Unable to create socket." << std::endl;
		return socket_creation;
	}

	int socket_connection = connectSocket(REST_API_NAME, PORT);
	if (socket_connection == 0)
	{
		std::cerr << "Unable to connect to socket." << std::endl;
		return socket_connection;
	}

	// Set up the ECDH variables
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* kctx;

	// Generate our public key.
	char* our_public_key = getPublicKey(&kctx, &pkey);
	if (our_public_key == NULL)
	{
		fprintf(stderr, "Error with getPublicKey(): NULL\n");
		return 1;
	}

	// Prepend "pk~" to our public key.
	char pk[4] = "pk~";
	char public_key_pk[strlen(our_public_key) + sizeof(pk)];
	strcpy(public_key_pk, pk);
	strcat(public_key_pk + strlen(pk), our_public_key);

	std::cout << "C++ Public Key: " << public_key_pk << std::endl;

	sendDataWithSize(public_key_pk, strlen(public_key_pk));

	// Receive the response from the server.
	char* peerPublicKey = NULL;
	size_t peerPublicKeySize = 0;
	receiveDataWithSize(&peerPublicKey, &peerPublicKeySize);
	std::cout << "Socket Public Key: " << peerPublicKey << std::endl;

	// Create the ECDH shared secret.
	char* ourSharedSecret = createSharedSecret(peerPublicKey + 3, pkey, kctx);

	// Prepend "ss~" to our shared secret.
	char ss[4] = "ss~";
	char shared_secret_ss[strlen(ourSharedSecret) + sizeof(ss)];
	strcpy(shared_secret_ss, ss);
	strcat(shared_secret_ss + strlen(ss), ourSharedSecret);

	std::cout << "C++ Shared Secret: " << shared_secret_ss << std::endl;

	// Send shared secret to server.
	sendDataWithSize(shared_secret_ss, strlen(shared_secret_ss));

	// Receive the server's shared secret.
	char* peerSharedSecret = NULL;
	size_t peerSharedSecretSize = 0;
	receiveDataWithSize(&peerSharedSecret, &peerSharedSecretSize);

	std::cout << "Socket Shared Secret: " << peerSharedSecret << std::endl;

	// Free the public key and shared secret received from the other side.
	if (peerPublicKey != NULL)
	{
		free(peerPublicKey);
	}
	if (peerSharedSecret != NULL)
	{
		free(peerSharedSecret);
	}

	// Shutdown the connection since no more data will be sent.
	closeSocket();

	std::cout << "Program stopped." << std::endl;

	return 0;
}

static int createSocket()
{
#ifdef _WIN32
	long RESPONSE;
	struct WSAData WinSockData;
	WORD DLLVERSION = MAKEWORD(2, 1);
	RESPONSE = WSAStartup(DLLVERSION, &WinSockData);
#endif
	m_sock = socket(AF_INET, SOCK_STREAM, 0);

	if (!isSocketValid())
	{
		return 0;
	}

	int32_t on = 1;
	if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, (const char*)&on, sizeof(on)) == -1)
	{
		return 0;
	}

	return 1;
}

static void closeSocket()
{
	if (isSocketValid())
	{
#ifdef _WIN32
		closesocket(m_sock);
#else
		close(m_sock);
#endif

	}
}

static int isSocketValid()
{
	return m_sock != -1;
}

static size_t sendData(const char* data, size_t dataSize)
{
	size_t status = send(m_sock, data, dataSize, 0);
	if (status == -1)
	{
		return 0;
	}
	else
	{
		return status;
	}
}

static size_t sendDataWithSize(const char* data, size_t dataSize)
{
	// Create a union to be able to set the length as a simple size.
	// Then the char array will automatically be set and 
	// ready to be sent to the other side, possibly needing to reverse
	// depending on Endianess.
	union bytesLength
	{
		uint32_t length;
		char byteArray[4];
	};

	// Get the length of the packet to send.
	union bytesLength to_send_len_bytes;
	to_send_len_bytes.length = dataSize;

	// Check if little Endian and reverse if no - all sent in Big Endian.
#if defined IS_LITTLE_ENDIAN
		int size = sizeof(to_send_len_bytes.byteArray);
		for (int i = 0; i < size / 2; i++)
		{
			char temp = to_send_len_bytes.byteArray[i];
			to_send_len_bytes.byteArray[i] = to_send_len_bytes.byteArray[size - 1 - i];
			to_send_len_bytes.byteArray[size - 1 - i] = temp;
		}
#endif	

	// Send the data size as big-endian.
	size_t res = sendData(to_send_len_bytes.byteArray, 4);
	if (res <= 0)
	{
		printf("Send failed.");
		closeSocket();
		return 0;
	}

	// Send the actual data.
	res = sendData(data, dataSize);
	if (res <= 0)
	{
		printf("Send failed.");
		closeSocket();
		return 0;
	}

	return res;
}

static size_t recvData(char* data, size_t dataSize)
{
	size_t charCount = (size_t)recv(m_sock, data, dataSize, 0);

	return charCount;
}

static bool receiveDataWithSize(char** data, size_t* dataSize)
{
	// Create a union to be able to get the char array from the Client.
	// It may need to be reversed depending on Endianess.
	// Then the length will have already been set.
	union bytesLength
	{
		uint32_t length;
		char byteArray[4];
	};

	// Create an array to hold the data size coming in.
	union bytesLength toRecvLenBytes;
	size_t res = recvData(toRecvLenBytes.byteArray, 4);
	if (res <= 0)
	{
		return false;
	}

	// Check if little Endian and reverse if no - all received in Big Endian.
#if defined IS_LITTLE_ENDIAN
		int size = sizeof(toRecvLenBytes.byteArray);
		for (int i = 0; i < size / 2; i++)
		{
			char temp = toRecvLenBytes.byteArray[i];
			toRecvLenBytes.byteArray[i] = toRecvLenBytes.byteArray[size - 1 - i];
			toRecvLenBytes.byteArray[size - 1 - i] = temp;
		}
#endif

	// Get the size of the data.
	size_t rcv_len = toRecvLenBytes.length;

	// Receive the data from the Client.
	*data = (char*)malloc(sizeof(char) * rcv_len + 1);
	memset(*data, '\0', rcv_len + 1);
	*dataSize = recvData(*data, rcv_len);
	return true;
}

static int connectSocket(const char* host, uint16_t port)
{
	if (!isSocketValid())
	{
		return 0;
	}

	m_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	m_addr.sin_family = AF_INET;
	m_addr.sin_port = htons(port);

	int32_t status = inet_pton(AF_INET, host, &m_addr.sin_addr);

	status = connect(m_sock, (struct sockaddr*)&m_addr, sizeof(m_addr));
	if (status == 0)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}