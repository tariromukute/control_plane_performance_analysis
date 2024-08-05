
# This script is used to execute the commands in to run ansible ad hoc commands
# and playbooks.

# Set $COMM and $PID string
COMM='$COMM'
PID='$PID'
entry='$entry'
retval='$retval'


# List of syscalls to inspect
NX="0 200 400"
for N_UES in $NX; do
# SYSCALLS="futex epoll_wait recvmsg clock_nanosleep poll select ppoll read openat sendto sched_yield recvfrom fdatasync write nanosleep io_getevents epoll_pwait rt_sigtimedwait"
SYSCALLS="io_getevents epoll_pwait rt_sigtimedwait"
# Loop through the syscalls and run the ansible ad hoc commands with syscall as parameter
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/oai-1.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: '$N_UES' }'

# ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/oai-1.yml \
#     -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -P -m -j", tool: sysprocess, ues: '$N_UES' }'

# for SYSCALL in $SYSCALLS; do
#     ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/oai-1.yml \
#     -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall '$SYSCALL' -d 20 -L -P -m -j", tool: sysprocess_'$SYSCALL', ues: '$N_UES' }'
# done

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 'r::do_epoll_wait(int epfd, struct epoll_event __user *events,int maxevents, int timeout):char*,int,int:$COMM,$entry(timeout),$retval' -i 20 -d 20\", tool: do_epoll_wait_timeout, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 'r::do_epoll_wait(int epfd, struct epoll_event __user *events,int maxevents, int timeout):char*,int,int:$COMM,$entry(maxevents),$retval' -i 20 -d 20\", tool: do_epoll_wait_timeout_maxevents, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_nanosleep():char*,u16:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_nanosleep, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_clock_nanosleep():char*,u16:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_clock_nanosleep, ues: "$N_UES" }"

# ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
#     -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"trace.py -U -a -A -M 10 'r::__x64_sys_futex "%d", retval' -i 20 -d 20\", tool: __x64_sys_futex, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"klockstat.py -d 20\", tool: klockstat, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -c -C 't:syscalls:sys_enter_socket():char*,int,int:$COMM,args->protocol,args->family&00004000' -i 20 -d 20\", tool: sys_enter_socket, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -c -C 't:syscalls:sys_enter_accept4():char*,int,int:$COMM,args->fd,args->flags&00004000' -i 20 -d 20\", tool: sys_enter_accept4, ues: "$N_UES" }"

# recvfrom/recvmsg/recvmmsg
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_recvmsg():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_recvmsg, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_recvmmsg():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_recvmmsg, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_recvfrom():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_recvfrom, ues: "$N_UES" }"

# sendto, sendmsg, sendmmsg
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_sendto():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_sendto, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_sendmsg():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_sendmsg, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_sendmmsg():char*,long:$COMM,args->ret' -i 20 -d 20\", tool: sys_exit_sendmmsg, ues: "$N_UES" }"

# open
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/open5gs.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_enter_open():char*,char*,int:$COMM,args->filename,args->flags&00004000' -i 20 -d 20\", tool: sys_enter_open, ues: "$N_UES" }"
done
