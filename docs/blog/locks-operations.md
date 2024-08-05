---
date:
  created: 2023-12-31
---

# Locks operations syscalls

## futex

The futex() system call offers a mechanism to wait until a specific condition becomes true. It is typically used as a blocking construct in the context of shared-memory synchronisation. Additionally, futex() operations can be employed to wake up processes or threads that are waiting for a particular condition. The main design goal of futex is to manage the mutex keys in the user space to avoid context switches when handling mutex in kernel space. In the futex design, the kernel is involved only when a thread needs to sleep or the system needs to wake up another thread. Essentially, the futex system call can be described as providing a kernel side wait queue indexed by a user space address, allowing threads to be added or removed from user space. A high frequency of calls to the futex system may indicate a high degree of concurrent access to shared resources or data structures by multiple threads or processes.

--8<-- "docs/results/grouped_systypes_on_Locks_count.html"

--8<-- "docs/results/grouped_systypes_on_Locks_latency.html"

--8<-- "docs/results/core_network_on_futex_count.html"

--8<-- "docs/results/core_network_on_futex_avg.html"
