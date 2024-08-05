---
date:
  created: 2023-12-31
---

# Socket read syscalls

## recv, recvfrom, recvmsg, recvmmsg. recvfrom(), recvmsg() and recvmmsg()

These are all system calls used to receive messages from a socket. They can be used to receive data on a socket, whether or not it is connection-orientated. These system calls are blocking calls; if no messages are available at the socket, the receive calls wait for a message to arrive. If the socket is set to non-blocking, then the value -1 is returned and errno is set to EAGAIN or EWOULDBLOCK. Passing the flag MSG_DONTWAIT to the system call enables non-blocking operation. This provides behaviour similar to setting O_NONBLOCK with fcntl except MSG_DONTWAIT is per operation. The recv() call is normally used only on a connected socket and is identical to recvfrom() with a nil from parameter. recv(), recvfrom() and recvmsg() calls return the number of bytes received, or -1 if an error occurred. For connected sockets whose remote peer was shut down, 0 is returned when no more data is available. The recvmmsg() call returns the number of messages received, or -1 if an error occurred.

--8<-- "docs/results/grouped_systypes_on_Receive_count.html"

--8<-- "docs/results/grouped_systypes_on_Receive_latency.html"

--8<-- "docs/results/core_network_on_recvmsg_count.html"

--8<-- "docs/results/core_network_on_recvfrom_count.html"