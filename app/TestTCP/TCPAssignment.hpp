/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2018. 10. 21.
 *      Author: Viet Do, Dung Nguyen
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Packet.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#define BUFSIZE 65536


#include <E/E_TimerModule.hpp>

namespace E
{

typedef std::pair<int, int> ii;
typedef std::pair<int, unsigned short> is;

enum socketState
{
  S_CLOSED, S_BOUND, S_LISTEN, S_SYN_RCVD, S_SYN_SENT, S_ESTABLISHED, S_CLOSE_WAIT, 
  S_FIN_WAIT_1, S_FIN_WAIT_2, S_LAST_ACK, S_TIME_WAIT, S_CLOSING, S_ANY
};

class Buffer {
  void *buf;
  Buffer() {
    buf = malloc(BUFSIZE);
  }
};

struct Candidate{
  int clientIP;
  unsigned short clientPort;
  int serverIP;
  unsigned short serverPort;
  int seqNum;
  int ackNum;
};

struct Socket{
  int pid;
  int sockfd;

  int sourceIP; // network order
  unsigned short sourcePort; // network order
  int destIP = -1; // network order
  unsigned short destPort = -1; // network order

  int seqNum = 0; // host order
  int ackNum = 0; // host order

  // Their receive window
  int rwnd = 51200;
  Time estimatedRTT = TimeUtil::makeTime(1000, TimeUtil::USEC);
  Time devRTT = TimeUtil::makeTime(20, TimeUtil::USEC);
  Time packetSentTime;

  UUID returnUUID;
  UUID resendUUID;
  int readLength;
  char *readBuf;
  int writeLength;
  char *writeBuf;

  // 3 duplicate ACKs.
  int lastAck = -1;
  int lastAckCount = 0;

  socketState state = S_BOUND;
  
  int backlog;
  bool isWaitingAccept = false;
  bool isWaitingClose = false;
  bool isWaitingRead = false;
  bool isWaitingWrite = false;

  sockaddr *acceptAddr;
  socklen_t *acceptAddrLen;
  std::vector<Candidate> waitingList;
  std::vector<int> establishedList;
  // Sender's write queue
  std::queue<Packet*> writeQueue;
  // Data queue
  std::queue<char> dataQueue;
  // Received queue
  std::map<int, char> receivedQueue;
};

struct TcpHeader{
  unsigned short sourcePort; 
  unsigned short destPort; 
  int seqNum;
  int ackNum; 
  uint8_t dataOffsetAndReserved;
  uint8_t flags;
  unsigned short window;
  unsigned short checksum = 0;
  unsigned short urgentPointer = 0;
};

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:
  std::unordered_set<ii> openSet; // (pid, sockfd)
  std::unordered_map<ii, sockaddr> bindMap; // (pid, sockfd) -> sockaddr
  std::unordered_set<is> bindSet; // (ip, port)
  int bindPortCnt[65536];
  std::vector<Socket> bindSockets; // (pid, sockfd) -> Socket

private:
  int findBoundSocketByIPAndPort(
    int sourceIP, unsigned short sourcePort, 
    int destIP, unsigned short destPort, 
    socketState state, bool checkDestAddr
  );
  int findBoundSocketByPidAndSockfd(int pid, int sockfd);
  void sendIPv4Packet(TcpHeader tcpHeader, int sourceIP, int destIP, char *buf, int len, int sockIndex);

  void syscall_socket(UUID syscallUUID, int pid, int domain, int type);
  void syscall_close(UUID syscallUUID, int pid, int sockfd);
  void syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrLen);
  void syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrLen);
  void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrLen);
  void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
  void syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t addrLen);
  void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t* addrLen);
  void syscall_read(UUID syscallUUID, int pid, int sockfd, char *buf, size_t len);
  void syscall_write(UUID syscallUUID, int pid, int sockfd, char *buf, size_t len);


private:
  virtual void timerCallback(void* payload) final;

public:
  TCPAssignment(Host* host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
protected:
  virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
  virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}
public:
  static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
