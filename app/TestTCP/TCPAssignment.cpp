/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2018. 10. 21.
 *      Author: Viet Do, Dung Nguyen
 */


#include <cerrno>
#include <E/E_Common.hpp>
#include <E/E_TimeUtil.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/TCP/E_TCPApplication.hpp>
#include <unistd.h>
#include "TCPAssignment.hpp"

#define MSS 512

namespace E
{

// Return a pair of <int, unsigned short> corresponding to (ip, port) from the address.
is getAddrPort(sockaddr *addr) {
  sockaddr_in *addr_in = (sockaddr_in *) addr;
  return is(*(int *) &addr_in->sin_addr.s_addr, *(unsigned short *) &addr_in->sin_port);
}

// Return the given ip address as string (i.e. 192.168.0.1) for debugging purpose.
// ip address is in network order.
std::string IPAsString(int ip) {
  char str[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &ip, str, INET_ADDRSTRLEN);
  std::string tmp = str;
  return tmp;
}

// Creates a sockaddr_in struct from given ip and port.
struct sockaddr_in createSockaddr_in (int IP, unsigned short port) {
  struct sockaddr_in myAddr;
  socklen_t len = sizeof(myAddr);
  memset(&myAddr, 0, len);
  myAddr.sin_family = AF_INET;
  myAddr.sin_addr.s_addr = IP;
  myAddr.sin_port = port;
  return myAddr;    
}

// From the list of bound sockets, find the one that has given TCPContext and socket state.
int TCPAssignment::findBoundSocketByIPAndPort(
  int sourceIP, unsigned short sourcePort, 
  int destIP = -1, unsigned short destPort = -1, 
  socketState state = S_ANY, bool checkDestAddr = false) {
  for(int i = 0; i < (int)bindSockets.size(); i++) {
    if(!checkDestAddr) {
      if((bindSockets[i].sourceIP == sourceIP || bindSockets[i].sourceIP == INADDR_ANY) 
        && bindSockets[i].sourcePort == sourcePort
        && (state == S_ANY || state == bindSockets[i].state))
        return i;
    }
    else {
      if((bindSockets[i].sourceIP == sourceIP || bindSockets[i].sourceIP == INADDR_ANY) 
        && bindSockets[i].sourcePort == sourcePort
        && bindSockets[i].destIP == destIP
        && bindSockets[i].destPort == destPort
        && (state == S_ANY || state == bindSockets[i].state))
        return i;
    }
  }
  return -1;
}

// From the list of bound sockets, find the one with (pid, sockfd).
int TCPAssignment::findBoundSocketByPidAndSockfd(int pid, int sockfd) {
  for(int i = 0; i < (int)bindSockets.size(); i++){
    if(bindSockets[i].pid == pid && bindSockets[i].sockfd == sockfd)
      return i;
  }
  return -1;
}

// Calculate tcp checksum.
unsigned short calTcpChecksum(int sourceIP, int destIP, uint8_t* buf, unsigned short len, uint8_t* data = NULL, unsigned short dataLen = 0){
  int res = 0;
  uint8_t* tempBuf;
  tempBuf = (uint8_t*) &sourceIP; for(int i = 0; i < 4; i++) res += tempBuf[i] << (8*((i+1)%2));
  tempBuf = (uint8_t*) &destIP; for(int i = 0; i < 4; i++) res += tempBuf[i] << (8*((i+1)%2));
  unsigned short protocol = htons(6);
  tempBuf = (uint8_t*) &protocol; for(int i = 0; i < 2; i++) res += tempBuf[i] << (8*((i+1)%2));
  unsigned short totalLen = len + dataLen;
  totalLen = htons(totalLen);
  tempBuf = (uint8_t*) &totalLen; for(int i = 0; i < 2; i++) res += tempBuf[i] << (8*((i+1)%2));
  tempBuf = buf; for(int i = 0; i < len; i++) res += tempBuf[i] << (8*((i+1)%2));
  tempBuf = data; for(int i = 0; i < dataLen; i++) res += tempBuf[i] << (8*((i+1)%2));
  while (res>>16) res = (res & 0xffff) + (res >> 16);

  res = ~res;
  return (unsigned short) res;
}

void TCPAssignment::sendIPv4Packet(TcpHeader tcpHeader, int sourceIP, int destIP, char *buf = NULL, int len = 0, int sockIndex = -1){
  int FIN = tcpHeader.flags & 1;
  int SYN = (tcpHeader.flags >> 1) & 1;
  int ACK = (tcpHeader.flags >> 4) & 1;
  // printf("Send packet from %s to %s with flag (%d%d%d)\n", IPAsString(sourceIP).c_str(), IPAsString(destIP).c_str(), FIN, SYN, ACK);
  int seqNum = ntohl(tcpHeader.seqNum);
  bool firstTime = true;
  for(int i=0; i<len || firstTime; i+=MSS) {
    firstTime = false;
    int packetLen = std::min(MSS, len - i);

    TcpHeader header = tcpHeader;
    header.seqNum = htonl(seqNum + i);
    header.checksum = 0;
    header.checksum = htons(calTcpChecksum(sourceIP, destIP, (uint8_t*) &header, 20, (unsigned char *) buf+i, packetLen));
    Packet *newPacket = this->allocatePacket(34 + 20 + packetLen);
    newPacket->writeData(26, &sourceIP, 4);
    newPacket->writeData(30, &destIP, 4);
    newPacket->writeData(34, &header, 20);
    newPacket->writeData(54, buf + i, packetLen);
    if(sockIndex != -1) {
      Packet *clone = this->clonePacket(newPacket);
      bindSockets[sockIndex].writeQueue.push(clone);
      bindSockets[sockIndex].rwnd -= packetLen;
    }
    this->sendPacket("IPv4", newPacket);
  }
}

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
    NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
    SystemCallInterface(AF_INET, IPPROTO_TCP, host),
    NetworkLog(host->getNetworkSystem()),
    TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{
  srand(time(0));
}

void TCPAssignment::finalize()
{
  openSet.clear();
  bindMap.clear();
  bindSet.clear();
  memset(bindPortCnt, 0, sizeof bindPortCnt);
  bindSockets.clear();
}

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type)
{
  int ret = SystemCallInterface::createFileDescriptor(pid);
  openSet.insert(ii(pid, ret));
  SystemCallInterface::returnSystemCall(syscallUUID, ret);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd)
{
  if(openSet.find(ii(pid, sockfd)) == openSet.end()) {
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }

  if(bindMap.find(ii(pid, sockfd)) != bindMap.end())
  {
    int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
    if(bindSockets[sockIndex].state == S_ESTABLISHED) {
  		// Initiate close.
      bindSockets[sockIndex].state = S_FIN_WAIT_1;
      bindSockets[sockIndex].returnUUID = syscallUUID;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(0);
      header.dataOffsetAndReserved = 80;
      header.flags = 1;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));
      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
  	}
    else if(bindSockets[sockIndex].state == S_CLOSE_WAIT){
      bindSockets[sockIndex].state = S_LAST_ACK;
      bindSockets[sockIndex].returnUUID = syscallUUID;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(bindSockets[sockIndex].seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 1;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));
      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
    }
    else if(bindSockets[sockIndex].state == S_BOUND || bindSockets[sockIndex].state == S_LISTEN) {
      sockaddr addr = bindMap.find(ii(pid, sockfd))->second;
      bindSet.erase(getAddrPort(&addr));
      bindPortCnt[getAddrPort(&addr).second]--;

      openSet.erase(ii(pid, sockfd));
      bindMap.erase(ii(pid, sockfd));
      bindSockets.erase(bindSockets.begin() + sockIndex);
      SystemCallInterface::removeFileDescriptor(pid, sockfd);
      SystemCallInterface::returnSystemCall(syscallUUID, 0);
    }
  }
  else {
    openSet.erase(ii(pid, sockfd));
    SystemCallInterface::removeFileDescriptor(pid, sockfd);
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t addrLen)
{
  sockaddr_in *addr_in = (sockaddr_in *) addr;
  if(bindMap.find(ii(pid, sockfd)) != bindMap.end()
    || bindSet.find(getAddrPort(addr)) != bindSet.end()
    || bindSet.find(is(INADDR_ANY, *(unsigned short *) &addr_in->sin_port)) != bindSet.end()
    || (*(int *) &addr_in->sin_addr.s_addr == INADDR_ANY && bindPortCnt[*(unsigned short *) &addr_in->sin_port] != 0))
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
  else
  {
    bindMap.insert({ii(pid, sockfd), *addr});
    bindSet.insert(getAddrPort(addr));

    Socket newSocket;
    newSocket.pid = pid;
    newSocket.sockfd = sockfd;
    newSocket.sourceIP = *(int *) &addr_in->sin_addr.s_addr;
    newSocket.sourcePort = *(unsigned short *) &addr_in->sin_port;
    bindSockets.push_back(newSocket);

    bindPortCnt[*(unsigned short *) &addr_in->sin_port]++;
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrLen)
{
  if(bindMap.find(ii(pid, sockfd)) == bindMap.end())
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
  else
  {
    *addr = bindMap.find(ii(pid, sockfd))->second;
    *((int *) addrLen) = sizeof (*addr);
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrLen)
{
  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex == -1
    || bindSockets[sockIndex].state == S_BOUND
    || bindSockets[sockIndex].state == S_LISTEN)
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
  else
  {
    struct sockaddr_in addr_in;
    memset(&addr_in, 0, sizeof(addr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_addr.s_addr = bindSockets[sockIndex].destIP;
    addr_in.sin_port = bindSockets[sockIndex].destPort;
    *((sockaddr_in*) addr) = addr_in;
    *((int *) addrLen) = sizeof (addr_in);
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex == -1 || bindSockets[sockIndex].state != S_BOUND)
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
  else {
    bindSockets[sockIndex].state = S_LISTEN;
    bindSockets[sockIndex].backlog = backlog;
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
  }
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t addrLen)
{
  if(openSet.find(ii(pid, sockfd)) == openSet.end()){
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }

  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex != -1 && bindSockets[sockIndex].state != S_BOUND){
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }
  
  int clientIP;
  unsigned short clientPort;
  if(sockIndex != -1) {
    clientIP = getAddrPort(&bindMap.find(ii(pid, sockfd))->second).first;
    clientPort = getAddrPort(&bindMap.find(ii(pid, sockfd))->second).second;
  }
  else {
    // Find a random port if not bound
    this->getHost()->getIPAddr((uint8_t *) &clientIP , this->getHost()->getRoutingTable((uint8_t *) &clientIP));

    bool newPortAvailable = false;
    for(int p = 0; p < 65536; p++){
      unsigned short newPort = htons(p);
      if(bindSet.find(is(clientIP, newPort)) == bindSet.end()
        && bindSet.find(is(INADDR_ANY, newPort)) == bindSet.end()
        && (clientIP != INADDR_ANY || bindPortCnt[newPort] == 0)){
        newPortAvailable = true;
        clientPort = newPort;
        break;
      }
    }
    if(!newPortAvailable){
      SystemCallInterface::returnSystemCall(syscallUUID, -1);
      return;
    }
    // Bind if found a new random port
    struct sockaddr_in clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_addr.s_addr = clientIP;
    clientAddr.sin_port = clientPort;

    bindMap.insert({ii(pid, sockfd), *(struct sockaddr*)&clientAddr});
    bindSet.insert(getAddrPort((struct sockaddr*)&clientAddr));

    Socket newSocket;
    newSocket.pid = pid;
    newSocket.sockfd = sockfd;
    newSocket.sourceIP = clientIP;
    newSocket.sourcePort = clientPort;
    bindSockets.push_back(newSocket);
    sockIndex = bindSockets.size() - 1;

    bindPortCnt[clientPort]++;
  }

  sockaddr_in *serverAddr_in = (sockaddr_in *) addr;
  int serverIP = *(int *) &serverAddr_in->sin_addr.s_addr;
  unsigned short serverPort = *(unsigned short *) &serverAddr_in->sin_port;

  bindSockets[sockIndex].destIP = serverIP;
  bindSockets[sockIndex].destPort = serverPort;
  bindSockets[sockIndex].state = S_SYN_SENT;
  bindSockets[sockIndex].seqNum = rand()%65536;
  bindSockets[sockIndex].returnUUID = syscallUUID;

  TcpHeader synHeader;
  synHeader.sourcePort = clientPort;
  synHeader.destPort = serverPort;
  synHeader.seqNum = htonl(bindSockets[sockIndex].seqNum);
  synHeader.ackNum = 0;
  synHeader.dataOffsetAndReserved = 80;
  synHeader.flags = 2;
	synHeader.window = htons(51200);
  synHeader.checksum = htons(calTcpChecksum(clientIP, serverIP, (uint8_t*) &synHeader, 20));

  sendIPv4Packet(synHeader, clientIP, serverIP);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr* addr, socklen_t *addrLen)
{
  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex == -1 || bindSockets[sockIndex].state != S_LISTEN){
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }

  // There are established connection already.
  if(bindSockets[sockIndex].establishedList.size() > 0) {
    int sockId = bindSockets[sockIndex].establishedList[0];
    bindSockets[sockIndex].establishedList.erase(bindSockets[sockIndex].establishedList.begin());

    struct sockaddr_in tempAddr = createSockaddr_in(bindSockets[sockId].destIP, bindSockets[sockId].destPort);
    *((sockaddr_in*)addr) = tempAddr;
    *((int *)addrLen) = sizeof (tempAddr);
    SystemCallInterface::returnSystemCall(syscallUUID, bindSockets[sockId].sockfd);
  }
  else{
    bindSockets[sockIndex].isWaitingAccept = true;
    bindSockets[sockIndex].returnUUID = syscallUUID;
    bindSockets[sockIndex].acceptAddr = addr;
    bindSockets[sockIndex].acceptAddrLen = addrLen;
  }
}

// Read up to len bytes from file descriptor sockfd into the buffer starting at buf.
// Return the number of bytes read.
void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int sockfd, char *buf, size_t len) {
  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex == -1 || bindSockets[sockIndex].state < S_ESTABLISHED) {
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }

  if(len == 0) {
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
    return;
  }

  if(bindSockets[sockIndex].dataQueue.empty()) { // blocking read
    bindSockets[sockIndex].returnUUID = syscallUUID;
    bindSockets[sockIndex].isWaitingRead = true;
    bindSockets[sockIndex].readLength = len;
    bindSockets[sockIndex].readBuf = buf;
    return;
  }
  else {
    // std::cerr<<"Here\n";
    int readLength = std::min(bindSockets[sockIndex].dataQueue.size(), len);
    // char *retbuf = (char *) malloc(readLength);
    for(int i=0; i<readLength; i++) {
      buf[i] = bindSockets[sockIndex].dataQueue.front();
      bindSockets[sockIndex].dataQueue.pop();
    }
    SystemCallInterface::returnSystemCall(syscallUUID, readLength);
  }
}

// Write up to len bytes from the buffer starting at buf into file descriptor sockfd.
// Return the number of bytes written.
void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int sockfd, char *buf, size_t len) {
  int sockIndex = findBoundSocketByPidAndSockfd(pid, sockfd);
  if(sockIndex == -1 || bindSockets[sockIndex].state < S_ESTABLISHED) {
    SystemCallInterface::returnSystemCall(syscallUUID, -1);
    return;
  }

  if(len == 0) {
    SystemCallInterface::returnSystemCall(syscallUUID, 0);
    return;
  }
  if((int) len > bindSockets[sockIndex].rwnd) {
    bindSockets[sockIndex].returnUUID = syscallUUID;
    bindSockets[sockIndex].isWaitingWrite = true;
    bindSockets[sockIndex].writeLength = len;
    bindSockets[sockIndex].writeBuf = buf;
  }
  else {
    // Create a packet and send

    TcpHeader header;
    header.sourcePort = bindSockets[sockIndex].sourcePort;
    header.destPort = bindSockets[sockIndex].destPort;
    header.seqNum = htonl(bindSockets[sockIndex].seqNum);
    header.ackNum = htonl(bindSockets[sockIndex].ackNum);
    header.dataOffsetAndReserved = 80;
    header.flags = 16;
    header.window = htons(51200 - bindSockets[sockIndex].receivedQueue.size());
    // header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20, (unsigned char *) buf, len));
    sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, buf, len, sockIndex);
    bindSockets[sockIndex].seqNum += len;
    SystemCallInterface::returnSystemCall(syscallUUID, len);
    return;
  }
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
  switch(param.syscallNumber)
  {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, (char *) param.param2_ptr, param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, (char *) param.param2_ptr, param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr*>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
        static_cast<struct sockaddr *>(param.param2_ptr),
        static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
  uint8_t flag;
  int sourceIP;
  int destIP;
  unsigned short sourcePort;
  unsigned short destPort;
  int seqNum;
  int ackNum;

  packet->readData(26, &sourceIP, 4);
  packet->readData(30, &destIP, 4);
  packet->readData(34, &sourcePort, 2);
  packet->readData(36, &destPort, 2);

  packet->readData(47, &flag, 1);
  bool ACK = (flag >> 4) & 1;
  bool SYN = (flag >> 1) & 1;
  bool FIN = flag & 1;

  packet->readData(38, &seqNum, 4);
  packet->readData(42, &ackNum, 4);
  seqNum = ntohl(seqNum);
  ackNum = ntohl(ackNum);

  uint8_t data[packet->getSize() - 34];
  packet->readData(34, data, packet->getSize() - 34);

  int checksum = htons(calTcpChecksum(sourceIP, destIP, data, packet->getSize() - 34));
  if(checksum != 0) {
    printf("Checksum error.\n");
    return;
  }


  // printf("Packet with flag (%d%d%d) received. From %s to %s\n", FIN, SYN, ACK, IPAsString(sourceIP).c_str(), IPAsString(destIP).c_str());

  // Server side: Receive SYN
  if(SYN && !ACK) {
    int sockIndex = findBoundSocketByIPAndPort(destIP, destPort, 0, 0, S_LISTEN, false);
    if(sockIndex != -1){
      // Attempt to connect.
      if(bindSockets[sockIndex].backlog > (int)bindSockets[sockIndex].waitingList.size()) {

        Candidate candidate;
        candidate.clientIP = sourceIP;
        candidate.clientPort = sourcePort;
        candidate.serverIP = destIP;
        candidate.serverPort = destPort;
        candidate.seqNum = rand()%65536;
        candidate.ackNum = seqNum + 1;
        bindSockets[sockIndex].waitingList.push_back(candidate);

        // Send SYNACK message back.
        TcpHeader header;
        header.sourcePort = destPort;
        header.destPort = sourcePort;
        header.seqNum = htonl(candidate.seqNum);
        header.ackNum = htonl(candidate.ackNum);
        header.dataOffsetAndReserved = 80;
        header.flags = 18;
        header.window = htons(51200);
        header.checksum = htons(calTcpChecksum(destIP, sourceIP, (uint8_t*) &header, 20));

        sendIPv4Packet(header, destIP, sourceIP);
      }
    }
    this->freePacket(packet);
    return;
  }

  // Client side: Receive SYNACK
  if(SYN && ACK) {
    int sockIndex = findBoundSocketByIPAndPort(destIP, destPort, 0, 0, S_SYN_SENT, false);
    if(sockIndex != -1){
      if(bindSockets[sockIndex].seqNum + 1 == ackNum) {
        bindSockets[sockIndex].seqNum = ackNum;
        bindSockets[sockIndex].ackNum = seqNum + 1;
        // Send ACK message back.
        TcpHeader header;
        header.sourcePort = destPort;
        header.destPort = sourcePort;
        header.seqNum = htonl(bindSockets[sockIndex].seqNum);
        header.ackNum = htonl(bindSockets[sockIndex].ackNum);
        header.dataOffsetAndReserved = 80;
        header.flags = 16;
        header.window = htons(51200);
        header.checksum = htons(calTcpChecksum(destIP, sourceIP, (uint8_t*) &header, 20));

        sendIPv4Packet(header, destIP, sourceIP);

        // Establish connection
        bindSockets[sockIndex].state = S_ESTABLISHED;
        bindSockets[sockIndex].destIP = sourceIP;
        bindSockets[sockIndex].destPort = sourcePort;
        SystemCallInterface::returnSystemCall(bindSockets[sockIndex].returnUUID, 0);
      }
    }
    this->freePacket(packet);
    return;
  }

  // Receive ACK only
  if(!SYN && ACK) {
    // Case 1: Receives ACK when in FIN_WAIT_1
    int sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_FIN_WAIT_1, true);
    if(sockIndex != -1){
      if(bindSockets[sockIndex].seqNum + 1 == ackNum) {
        bindSockets[sockIndex].seqNum = ackNum;
        bindSockets[sockIndex].ackNum = seqNum + 1;

        bindSockets[sockIndex].state = S_FIN_WAIT_2;
      }
      this->freePacket(packet);
      return;
    }

    // Case 2: Receives ACK when in CLOSING
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_CLOSING, true);
    if(sockIndex != -1){
      if(bindSockets[sockIndex].seqNum + 1 == ackNum) {
        bindSockets[sockIndex].state = S_TIME_WAIT;

          Time currentTime = this->getHost()->getSystem()->getCurrentTime();
          Time waitTime = TimeUtil::makeTime(5, TimeUtil::SEC);
          int *savedIndex = (int*) malloc(4);
          *savedIndex = sockIndex;
          addTimer(savedIndex, currentTime + waitTime);
      }
      this->freePacket(packet);
      return;
    }

    // Case 3: Receives ACK when in LAST_ACK
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_LAST_ACK, true);
    if(sockIndex != -1){
      if(bindSockets[sockIndex].seqNum + 1 == ackNum) {
        openSet.erase(ii(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd));
        bindMap.erase(ii(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd));
        SystemCallInterface::removeFileDescriptor(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd);
        UUID closeUUID = bindSockets[sockIndex].returnUUID;
        bindSockets.erase(bindSockets.begin() + sockIndex);
        SystemCallInterface::returnSystemCall(closeUUID, 0);
      }
      this->freePacket(packet);
      return;
    }

    // Case 4: Server side, establish connection.
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, 0, 0, S_LISTEN, false);
    if(sockIndex != -1) {
      for(int i=0; i<(int)bindSockets[sockIndex].waitingList.size(); i++) {
        Candidate candidate = bindSockets[sockIndex].waitingList[i];
        if(candidate.clientIP == sourceIP && candidate.clientPort == sourcePort
          && candidate.seqNum + 1 == ackNum) {
          bindSockets[sockIndex].waitingList.erase(bindSockets[sockIndex].waitingList.begin() + i);
          
          candidate.seqNum = ackNum;
          candidate.ackNum = seqNum + 1;

          Socket newSock;
          newSock.pid = bindSockets[sockIndex].pid;
          newSock.sockfd = SystemCallInterface::createFileDescriptor(newSock.pid); openSet.insert(is(newSock.pid, newSock.sockfd));
          newSock.sourceIP = candidate.serverIP;
          newSock.sourcePort = candidate.serverPort;
          newSock.destIP = candidate.clientIP;
          newSock.destPort = candidate.clientPort;
          newSock.seqNum = candidate.seqNum;
          newSock.ackNum = candidate.ackNum;
          newSock.state = S_ESTABLISHED;
          bindSockets.push_back(newSock);
          bindMap[ii(newSock.pid, newSock.sockfd)] = bindMap[ii(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd)];
          bindSockets[sockIndex].establishedList.push_back(bindSockets.size() - 1);

          if(bindSockets[sockIndex].isWaitingAccept) {
            bindSockets[sockIndex].isWaitingAccept = false;

            int newSockId = bindSockets[sockIndex].establishedList[0];
            bindSockets[sockIndex].establishedList.erase(bindSockets[sockIndex].establishedList.begin());

            struct sockaddr_in tempAddr = createSockaddr_in(bindSockets[newSockId].destIP, bindSockets[newSockId].destPort);
            *((sockaddr_in*)bindSockets[sockIndex].acceptAddr) = tempAddr;
            *((int *)bindSockets[sockIndex].acceptAddrLen) = sizeof (tempAddr);

            SystemCallInterface::returnSystemCall(bindSockets[sockIndex].returnUUID, bindSockets[newSockId].sockfd);
          }

          break;
        }
      }
      this->freePacket(packet);
      return;
    }
    // Case 5: Receive data.
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_ANY, true);
    if(sockIndex != -1) {
      Packet *writePacket;
      int writeSeqNum;
      // Free the writeQueue.
      while(!bindSockets[sockIndex].writeQueue.empty()) {
        writePacket = bindSockets[sockIndex].writeQueue.front();
        writePacket->readData(38, &writeSeqNum, 4);
        writeSeqNum = ntohl(writeSeqNum);
        if(writeSeqNum < ackNum) {
          bindSockets[sockIndex].rwnd += writePacket->getSize() - 54;
          this->freePacket(writePacket);
          bindSockets[sockIndex].writeQueue.pop();
        }
        else break;
      }
      // Read data.
      if(bindSockets[sockIndex].receivedQueue.size() + packet->getSize() - 54 <= 51200 && packet->getSize() > 54) {
        for(int i=20; i<(int)packet->getSize()-34; i++) {
          bindSockets[sockIndex].receivedQueue[seqNum + i - 20] = data[i];
        }
        while(bindSockets[sockIndex].receivedQueue.find(bindSockets[sockIndex].ackNum) != bindSockets[sockIndex].receivedQueue.end()) {
          bindSockets[sockIndex].dataQueue.push(bindSockets[sockIndex].receivedQueue[bindSockets[sockIndex].ackNum]);
          bindSockets[sockIndex].receivedQueue.erase(bindSockets[sockIndex].receivedQueue.begin());
          bindSockets[sockIndex].ackNum++;
        }
        // Send the ACK message asking for more data.
        TcpHeader header;
        header.sourcePort = bindSockets[sockIndex].sourcePort;
        header.destPort = bindSockets[sockIndex].destPort;
        header.seqNum = htonl(bindSockets[sockIndex].seqNum);
        header.ackNum = htonl(bindSockets[sockIndex].ackNum);
        header.dataOffsetAndReserved = 80;
        header.flags = 16;
        header.window = htons(51200 - bindSockets[sockIndex].receivedQueue.size());
        // header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));
        sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
      }
      // Unblock write() if possible.
      if(bindSockets[sockIndex].isWaitingWrite && bindSockets[sockIndex].writeLength <= bindSockets[sockIndex].rwnd) {
        bindSockets[sockIndex].isWaitingWrite = false;
        // Create a packet and send

        TcpHeader header;
        header.sourcePort = bindSockets[sockIndex].sourcePort;
        header.destPort = bindSockets[sockIndex].destPort;
        header.seqNum = htonl(bindSockets[sockIndex].seqNum);
        header.ackNum = htonl(bindSockets[sockIndex].ackNum);
        header.dataOffsetAndReserved = 80;
        header.flags = 16;
        header.window = htons(51200 - bindSockets[sockIndex].receivedQueue.size());
        header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20,
                                               (unsigned char *) bindSockets[sockIndex].writeBuf, bindSockets[sockIndex].writeLength));
        sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP,
                       bindSockets[sockIndex].writeBuf, bindSockets[sockIndex].writeLength, sockIndex);

        bindSockets[sockIndex].seqNum += bindSockets[sockIndex].writeLength;
        SystemCallInterface::returnSystemCall(bindSockets[sockIndex].returnUUID, bindSockets[sockIndex].writeLength);
      }
      // Unblock read() if possible.
      if(!bindSockets[sockIndex].dataQueue.empty() && bindSockets[sockIndex].isWaitingRead) {
        bindSockets[sockIndex].isWaitingRead = false;
        int readLength = std::min((int) bindSockets[sockIndex].dataQueue.size(), bindSockets[sockIndex].readLength);
        for(int i=0; i<readLength; i++) {
          bindSockets[sockIndex].readBuf[i] = bindSockets[sockIndex].dataQueue.front();
          bindSockets[sockIndex].dataQueue.pop();
        }
        SystemCallInterface::returnSystemCall(bindSockets[sockIndex].returnUUID, readLength);
      }
    }
    this->freePacket(packet);
    return;
  }

  // Receive FIN only
  if(FIN && !ACK) {
    int sockIndex;

    // Case 1: Receives FIN when in ESTABLISHED state
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_ESTABLISHED, true);
    if(sockIndex != -1) {
      bindSockets[sockIndex].state = S_CLOSE_WAIT;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 16;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));

      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
      this->freePacket(packet);
      return;
    }

    // Case 1: Receives FIN when in FIN_WAIT_1 state
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_FIN_WAIT_1, true);
    if(sockIndex != -1) {
      bindSockets[sockIndex].state = S_CLOSING;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum + 1);
      header.ackNum = htonl(seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 16;
      header.window = htons(10000);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));

      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
      this->freePacket(packet);
      return;
    }

    // Case 2: receives FIN when in FIN_WAIT_2 state
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_FIN_WAIT_2, true);
    if(sockIndex != -1){
      bindSockets[sockIndex].state = S_TIME_WAIT;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 16;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));

      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);

      Time currentTime = this->getHost()->getSystem()->getCurrentTime();
      Time waitTime = TimeUtil::makeTime(5, TimeUtil::SEC);
      int *savedIndex = (int*) malloc(4);
      *savedIndex = sockIndex;
      addTimer(savedIndex, currentTime + waitTime);
      this->freePacket(packet);
      return;
    }

    // Case 3: Receives FIN when in TIMED_WAIT state
    sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_TIME_WAIT, true);
    if(sockIndex != -1){
      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 16;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));

      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);
    }
    this->freePacket(packet);
    return;
  }

  if(FIN && ACK) {
    // Receives FIN ACK when in FIN_WAIT_1 state
    int sockIndex = findBoundSocketByIPAndPort(destIP, destPort, sourceIP, sourcePort, S_FIN_WAIT_1, true);
    if(sockIndex != -1){
      bindSockets[sockIndex].state = S_TIME_WAIT;

      TcpHeader header;
      header.sourcePort = bindSockets[sockIndex].sourcePort;
      header.destPort = bindSockets[sockIndex].destPort;
      header.seqNum = htonl(bindSockets[sockIndex].seqNum);
      header.ackNum = htonl(seqNum + 1);
      header.dataOffsetAndReserved = 80;
      header.flags = 16;
      header.window = htons(51200);
      header.checksum = htons(calTcpChecksum(bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP, (uint8_t*) &header, 20));

      sendIPv4Packet(header, bindSockets[sockIndex].sourceIP, bindSockets[sockIndex].destIP);

      Time currentTime = this->getHost()->getSystem()->getCurrentTime();
      Time waitTime = TimeUtil::makeTime(5, TimeUtil::SEC);
      int *savedIndex = (int*) malloc(4);
      *savedIndex = sockIndex;
      addTimer(savedIndex, currentTime + waitTime);
    }
    this->freePacket(packet);
    return;
  }
  this->freePacket(packet);
}

void TCPAssignment::timerCallback(void* payload)
{
  int sockIndex = *(int*) payload;
  free(payload);

  openSet.erase(ii(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd));
  bindMap.erase(ii(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd));
  SystemCallInterface::removeFileDescriptor(bindSockets[sockIndex].pid, bindSockets[sockIndex].sockfd);
  UUID closeUUID = bindSockets[sockIndex].returnUUID;
  bindSockets.erase(bindSockets.begin() + sockIndex);
  SystemCallInterface::returnSystemCall(closeUUID, 0);
}


}
