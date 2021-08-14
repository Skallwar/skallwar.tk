+++
title = "The unkillable process"
date = "2021-04-22"
author = "Skallwar"
cover = ""
tags = ["eBPF", "linux"]
keywords = ["", ""]
description = "Tired of having your process getting killed? Catching SIGINT and SIGTERM is not enough for you? What if you could catch **all** signals sent to your process..."
showFullContent = false
+++

# A word on signals
If you have already played with signals, chances are you might have tried to
catch signals using the 
[``signal``](https://man7.org/linux/man-pages/man2/signal.2.html) or 
[``sigaction``](https://man7.org/linux/man-pages/man2/sigaction.2.html) syscalls.
All signals can be caught except ``SIGKILL`` and ``SIGSTOP``.

> The SIGKILL signal is used to cause immediate program termination. It cannot be handled or ignored, and is therefore always fatal. It is also not possible to block this signal. [...] if SIGKILL fails to terminate a process, that by itself constitutes an operating system bug which you should report.
>
> -- <cite>[Termination Signals](https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html)</cite>

> The SIGSTOP signal stops the process. It cannot be handled, ignored, or blocked.
>
> -- <cite>[Job Control Signals](https://www.gnu.org/software/libc/manual/html_node/Job-Control-Signals.html)</cite>

This seems to be two strong affirmations so this should be true. But I don't 
want my process to die, I heard you say. Well if I can't catch them, what do 
you want me to do? Kill the sender?

Actually I can't kill the sender, but I could try to intercept and drop the 
message...

# Meet eBPF
> The Linux kernel has always been an ideal place to implement monitoring/observability, networking, and security. Unfortunately this was often impractical as it required changing kernel source code or loading kernel modules, and resulted in layers of abstractions stacked on top of each other. eBPF is a revolutionary technology that can run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.
>
>By making the Linux kernel programmable, infrastructure software can leverage existing layers, making them more intelligent and feature-rich without continuing to add additional layers of complexity to the system or compromising execution efficiency and safety.
>
> -- <cite> [eBPF](https://ebpf.io/) </cite>

# Blocking some signals
My idea was as simple as blocking the signal so that it will never reach our
process. In order to do so, I tried to catch the signal as early as possible in
the kernel: when a process uses the [``kill``](https://man7.org/linux/man-pages/man2/kill.2.html) syscall.

Fortunately, all syscall have a [``kprobe``](https://www.kernel.org/doc/Documentation/kprobes.txt) hook point. The goal here is to filter signals for our process and discard them.
In order to discard them, I will use the ``override()`` which will abort the probed function an will return the return code provided in argument. This functionality require that your kernel is compiled with ``CONFIG_BPF_KPROBE_OVERRIDE`` and only works on function with the``ALLOW_ERROR_INJECTION`` tag. Fortunately Arch Linux kernel already come with ``CONFIG_BPF_KPROBE_OVERRIDE`` and every syscall handler seems to have the ``ALLOW_ERROR_INJECTION`` tag on them.

So using bpftrace, here is a [script](https://github.com/Skallwar/blocksig/blob/main/blocksig.sh) to block all signals to your process:
{{<highlight bash>}}
#!/bin/sh

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 pid"
    exit 1
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

bpftrace -e "kprobe:__x64_sys_kill { if (arg1 == $1) { printf(\"Signal blocked for $1\n\"); override(0); } }" --unsafe
{{</highlight>}}

Let's take an example:
{{<highlight terminal>}}
$ # Without blocksig.sh
$ ping skallwar.fr > /dev/null &
[1] 371628
$ kill -9 371628
[1]+  Killed                  ping skallwar.fr > /dev/null

$ # With blocksig.sh
$ ping skallwar.fr > /dev/null &
[1] 315629
$ sudo ./blocksig.sh 315629 &
Attaching 1 probe...
$ kill -9 315629
Signal blocked for 315629
{{</highlight>}}

As you can see, the second time around, our ping did not get killed. We actually 
blocked a ``SIGKILL``.

As a side note, the first time I launched ``blocksig.sh``, I did not filter on the 
pid before doing the override. As a side effect, ``systemctl`` refused to either 
``poweroff`` or ``reboot`` my machine.

This technique works fine but we just move the problem elsewhere. Now our process
is protected but our blocksig.sh is not. If someone kills ``blocksig.sh``, our
process is defenseless and we are back to square one. You might think that using
``$$``, the shell special variable for pid will do the trick but remember, this
is the pid of the shell **not** the pid of the ``bpftrace`` command.

{{<figure src="images/blocksig_sh_block_shell_pid_problem.png">}}

We need to setup the "fence" from the inside...

# BCC to the rescue
To fix our problem I used [BCC](https://github.com/iovisor/bcc). BCC is a 
toolkit for creating efficient kernel tracing and manipulation programs using 
eBPF and Python.

Here is what a basic [hello world](https://github.com/iovisor/bcc/blob/master/examples/hello_world.py) looks like:
{{<highlight python>}}
#!/usr/bin/python
# sudo ./hello_world.py

from bcc import BPF

BPF(text='int kprobe__sys_clone(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
{{</highlight>}}

So we write some C code as a string inside your Python script... Weird but why not ?
You can also load from a file like so:
{{<highlight c>}}
int kprobe__sys_clone(void *ctx) {
    bpf_trace_printk("Hello, World!\\n"); 
    return 0;
}
{{</highlight>}}

{{<highlight python>}}
#!/usr/bin/python
# sudo ./hello_world.py

from bcc import BPF

BPF(src_file = "hello_world.c")
{{</highlight>}}

In order to prevent our script to be killed, it needs to be able to block signals for multiples pids. I also want to block multiple signals. But how do we provide this arguments to our eBPF program?
This is done using eBPF maps. Maps are data structures used to share data between userland and our eBPF program.
There is a lot of different [kinds of maps](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps), going from arrays to hashmaps.
To create a new map with BCC you use the ``BPF_YOURTYPEHERE`` macro in your C stub like so:
{{<highlight c>}}
BPF_HASH(pids, int, u8); // Syntax: BPF_HASH(name, key_type, value_type)
{{</highlight>}}

So my implementation is quite simple:
- Parse the arguments to retrieve signals to block and the pids that need to be protected
- Put the pids to block inside a map of type hashmap and the signals in a map of type array
- Hook the kill syscall and check override the return value if kill is called on a protected pids with a signal that needs to be blocked

But a new problem arise now. If we protect our script how can we stop it? So 
I've implemented a system of ticket (a simple file with a unique name) in the 
tmpfs where the script is pooling wether our ticket has been deleted or not.

<!-- So here the final result: -->
<!-- {{<highlight c>}} -->
<!-- #include <uapi/linux/ptrace.h> -->
<!-- #include <linux/sched.h> -->
<!--  -->
<!-- BPF_HASH(pids, int, u8); -->
<!-- BPF_ARRAY(sigs, u8, 65); -->
<!--  -->
<!-- static u8 needs_block(u8 protected_pid, u8 protected_sig) { -->
<!--     return protected_pid != 0 && protected_sig != 0; -->
<!-- } -->
<!--  -->
<!-- int syscall__kill(struct pt_regs *ctx, int pid, int sig) -->
<!-- { -->
<!--     u8 *protected_pid = pids.lookup(&pid); -->
<!--     u8 *protected_sig = sigs.lookup(&sig); -->
<!--     if (!protected_pid || !protected_sig) -->
<!--         return 0; -->
<!--     if (needs_block(*protected_pid, *protected_sig)) { -->
<!--         bpf_trace_printk("Blockeg signal %d for %d\\n", sig, pid); -->
<!--         bpf_override_return(ctx, 0); -->
<!--     } -->
<!--     return 0; -->
<!-- } -->
<!-- {{</highlight>}} -->
<!--  -->
<!--  -->
<!-- {{<highlight python>}} -->
<!-- #!/usr/bin/python -->
<!--  -->
<!-- from bcc import BPF -->
<!-- from bcc.utils import ArgString, printb -->
<!-- from ctypes import * -->
<!-- import argparse -->
<!-- import tempfile -->
<!-- import time -->
<!-- import os -->
<!--  -->
<!-- def parse_args(): -->
<!--     parser = argparse.ArgumentParser(description='Blocksig is a tool to block certain or all signal to be recived by given pids') -->
<!--     parser.add_argument('-p', dest='pids', nargs='+', default=[], metavar='pid', help='List of pid to protect') -->
<!--     parser.add_argument('-s', dest='sigs', nargs='+', default=[], metavar='signal_num', help='List of signal to block. If no signal is specified, they are all blocked') -->
<!--     parser.add_argument('--auto-protect', action=argparse.BooleanOptionalAction, default=True, help='Whether to protect blocksig itself or not') -->
<!--     args = parser.parse_args() -->
<!--  -->
<!--     return args -->
<!--  -->
<!--  -->
<!-- def initialize_bpf(args): -->
<!--     b = BPF(src_file = "blocksig.c") -->
<!--     kill_fnname = b.get_syscall_fnname('kill') -->
<!--     b.attach_kprobe(event=kill_fnname, fn_name='syscall__kill') -->
<!--     pids_map = b.get_table('pids') -->
<!--     sigs_map = b.get_table('sigs') -->
<!--  -->
<!--     if args.auto_protect == True: -->
<!--         args.pids.append(str(os.getpid())) -->
<!--     for pid in args.pids: -->
<!--         pids_map[c_int(int(pid))] = c_int(1) -->
<!--  -->
<!--     sig_array = [int(sig) for sig in args.sigs] if len(args.sigs) else range(1, 64) -->
<!--     for sig in sig_array: -->
<!--         sigs_map[sig] = c_int(1) -->
<!--  -->
<!-- def wait_for_close(): -->
<!-- # Create a tempfile and wait for its deletion -->
<!--     tf = tempfile.NamedTemporaryFile(delete = False) -->
<!--     print(f"This script might not be killable anymore. To stop it run ``rm {tf.name}``") -->
<!--  -->
<!--     try: -->
<!--         while os.path.isfile(tf.name): -->
<!--             time.sleep(0.5) -->
<!--             continue -->
<!--     except KeyboardInterrupt: -->
<!--         tf.close() -->
<!--         os.remove(tf.name) -->
<!--         print('') -->
<!--  -->
<!-- args = parse_args() -->
<!-- initialize_bpf(args) -->
<!-- wait_for_close() -->
<!-- {{</highlight>}} -->
