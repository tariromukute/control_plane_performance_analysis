
# This script is used to execute the commands in to run ansible ad hoc commands
# and playbooks.

# List of syscalls to inspect
NX="80"
for N_UES in $NX; do
# Loop through the syscalls and run the ansible ad hoc commands with syscall as parameter
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -m -j", tool: syscount, ues: '$N_UES' }'

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py -d 20 -L -P -m -j", tool: sysprocess, ues: '$N_UES' }'

for SYSCALL in $SYSCALLS; do
    ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: "syscount.py --syscall '$SYSCALL' -d 20 -L -P -m -j", tool: sysprocess_'$SYSCALL', ues: '$N_UES' }'
done

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_enter_epoll_wait():u16:args->timeout' -i 20 -d 20\", tool: sysprocess_enter_epoll_wait_timeout, ues: "$N_UES" }"

ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e "{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: \"argdist.py -C 't:syscalls:sys_exit_epoll_wait():u16:args->ret' -i 20 -d 20\", tool: sysprocess_exit_epoll_wait, ues: "$N_UES" }"
done

ETOOL="bpftrace -e '
t:syscalls:sys_enter_write 
{
    @bytes_count[tid] = args->count;
}
t:syscalls:sys_exit_write
/@bytes_count[tid]/
{
    $b = @bytes_count[tid];
    if(args->ret < 0) {
        @err[-args->ret] = count();
    } else {
        @timeout[comm, $b, args->ret] = count();
    }
    delete(@bytes_count[tid]);
}

END
{
    clear(@bytes_count);
}
'"
ansible all -i inventory.ini -u ubuntu -m include_tasks -a file=plays/free5gc.yml \
    -e '{ user: ubuntu,  duration: 20, aduration: 35, interval: 0, tool_cmd: '$ETOOL', tool: syscount, ues: '$N_UES' }'
