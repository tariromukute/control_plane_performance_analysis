---
date:
  created: 2023-12-31
---

# Socket write syscalls

## send, sendto, sendmsg, sendmmsg

The send() call may only be used when the socket is in a connected state (so that the intended recipient is known). The send() is similar to write() with the difference of flags. The sendto and sendmsg work on both connected and unconnected sockets. The sendmsg() call also allows sending ancillary data (also known as control information). The sendmmsg() system call is an extension of sendmsg that allows the caller to transmit multiple messages on a socket using a single system call. The approaches to optimise the send(s) system calls are similar to the discussed approaches for the recv(s) system calls. These include I/O multiplexing, using the system calls in non-blocking mode, and sending multiple messages in a single system call where possible.

--8<-- "docs/results/grouped_systypes_on_Send_count.html"

--8<-- "docs/results/grouped_systypes_on_Send_latency.html"

--8<-- "docs/results/core_network_on_sendmsg_count.html"

--8<-- "docs/results/core_network_on_sendto_count.html"