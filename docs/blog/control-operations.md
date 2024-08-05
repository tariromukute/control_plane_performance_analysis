---
date:
  created: 2023-12-31
---

# Control operations syscalls

The sched_yield system call is used by a thread to allow other threads a chance to run, and \
the calling thread relinquishes the CPU. Strategic calls to sched_yield() can improve performance by giving \
other threads or processes an opportunity to run when (heavily) contended resources, such as mutexes, have been \
released by the caller. The authors of were able to improve the throughput of their system by employing \
the sched_yield system call after a process processes each batch of packets before calling the poll. On the other \
hand, sched_yield can result in unnecessary context switches, which will degrade system performance if not used \
appropriately. The latter is mainly true in generic Linux systems, as the scheduler is responsible for deciding \
which process runs. In most cases, when a process yields, the scheduler may perceive it as a higher priority and \
still put it back into execution, where it yields again in a loop. This behaviour is mainly due to the algorithm and \
logic used by Linux’s default scheduler to determine the process with the higher prior

--8<-- "docs/results/grouped_systypes_on_Control operations_count.html"

--8<-- "docs/results/grouped_systypes_on_Control operations_latency.html"

--8<-- "docs/results/core_network_on_sched_yield_count.html"

--8<-- "docs/results/core_network_on_sched_yield_avg.html"