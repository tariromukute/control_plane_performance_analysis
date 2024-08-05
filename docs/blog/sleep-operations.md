---
date:
  created: 2023-12-31
---

# Sleep operations syscalls

## nanosleep/clock_nanosleep

The nanosleep and clock_nanosleep system calls are used to allow the calling thread to sleep for a specific interval with nanosecond precision. The clock_nanosleep differs from nanosleep in two ways. Firstly, it allows the caller to select the clock against which the sleep interval is to be measured. Secondly, it enables the specification of the sleep interval as either an absolute or a relative value. Using an absolute timer is useful to prevent timer drift issues mentioned about nanosleep.

--8<-- "docs/results/grouped_systypes_on_Time_count.html"

--8<-- "docs/results/grouped_systypes_on_Time_latency.html"

--8<-- "docs/results/core_network_on_clock_nanosleep_count.html"

--8<-- "docs/results/core_network_on_nanosleep_count.html"