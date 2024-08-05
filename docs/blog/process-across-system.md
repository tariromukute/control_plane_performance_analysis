---
date:
  created: 2023-12-31
---

# Processes making syscalls

The information about the processes that make system calls provides valuable insights into the most active processes during the registration procedure. By observing the changes in latency and frequency of the system calls made by a process as the number of UEs increases, we can identify processes that have a high probability of becoming bottlenecks. The information can be used to make several mitigation decisions, such as allocating more resources or dedicated resources to a given process or Network Function (NF), optimising the usage by the NF or process, and examining the configuration of the process, among other things.

--8<-- "docs/results/grouped_sysprocess_count.html"

--8<-- "docs/results/grouped_sysprocess_latency.html"

--8<-- "docs/results/core_network_sum_sysprocess_count.html"

--8<-- "docs/results/free5gc_sysprocess_count.html"

--8<-- "docs/results/open5gs_sysprocess_count.html"

--8<-- "docs/results/oai_sysprocess_count.html"