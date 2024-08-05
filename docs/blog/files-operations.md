---
date:
  created: 2023-12-31
---

# File operations syscalls

## read/write

The read() system call is used to retrieve data from a file stored in the file system, while the write() system call is used to write data from a buffer to a file. Both system calls take into account the "count", which represents the number of bytes to read or write. Upon successful execution, these system calls return the number of bytes that were successfully read or written. By default, these system calls are blocking but can be changed to non-blocking using the fnctl system call. Blocking is a problem for programs that should operate concurrently, since blocked processes are suspended. There are two different, complementary ways to solve this problem. They are nonblocking mode and I/O multiplexing system calls, such as select and epoll. The architectural decision to use a combination of multiplexing I/O operations and non-blocking system calls offers advantages depending on the use cases. Some scenarios where this approach is beneficial include situations where small buffers would result in repeated system calls, when the system is dedicated to one function, or when multiple I/O system calls return an error.

--8<-- "docs/results/grouped_systypes_on_Files_count.html"

--8<-- "docs/results/grouped_systypes_on_Files_latency.html"

--8<-- "docs/results/core_network_on_read_count.html"

--8<-- "docs/results/core_network_on_write_count.html"