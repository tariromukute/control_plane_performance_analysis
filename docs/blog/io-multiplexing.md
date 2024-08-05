---
date:
  created: 2023-12-31
---

# I/O Multiplexing syscalls

The system calls epoll/poll/select implement I/O multiplexing, which enables the simultaneous monitoring of multiple input and output sources in a single operation. These system calls are based on the Linux design principle, which considers everything as a file and operates by monitoring files to determine if they are ready for the requested operation. The main advantage of multiplexing I/O operations is that it avoids blocking read and write where a process will wait for data while on the CPU. Instead, one waits for the multiplexing I/O system calls to determine which files are ready for read or write.


--8<-- "docs/results/grouped_systypes_on_IO Multiplexing_count.html"

--8<-- "docs/results/grouped_systypes_on_IO Multiplexing_latency.html"

--8<-- "docs/results/core_network_on_epoll_pwait_count.html"

--8<-- "docs/results/core_network_on_epoll_wait_count.html"

--8<-- "docs/results/core_network_on_poll_count.html"