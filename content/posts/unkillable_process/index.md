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

But I don't want my process to die, I heard you say. Well if I can't catch them,
what do you want me to do? Kill the sender?

Actually I can't kill the sender, but what if I could intercept and drop the 
message...

# Meet eBPF
> The Linux kernel has always been an ideal place to implement 
> monitoring/observability, networking, and security. Unfortunately this was 
> often impractical as it required changing kernel source code or loading kernel
> modules, and resulted in layers of abstractions stacked on top of each other. 
> eBPF is a revolutionary technology that can run sandboxed programs in the 
> Linux kernel without changing kernel source code or loading kernel modules.
>
> By making the Linux kernel programmable, infrastructure software can leverage 
> existing layers, making them more intelligent and feature-rich without 
> continuing to add additional layers of complexity to the system or 
> compromising execution efficiency and safety.
>
> -- <cite> [eBPF](https://ebpf.io/) </cite>

eBPF is used to expand the Linux kernel by allowing user space program to 
inject some code into hook points. The code is JIT compiled and executed if 
there is no error raised by the verification engine.

# Blocking some signals
My idea was as simple as blocking the signal, this way it will never reach our
protected process. In order to do so, I tried to catch the signal as early as 
possible in the kernel: when a process uses the [``kill``](https://man7.org/linux/man-pages/man2/kill.2.html)
syscall.

To quickly see if the idea was really possible, I used [bpftrace](https://github.com/iovisor/bpftrace),
a high-level tracing language for eBPF.

Fortunately, all syscall have a [``kprobe``](https://www.kernel.org/doc/Documentation/kprobes.txt)
hook point for eBPF. The goal here is to filter out signals for our protected
process and discard them. In order to discard them, I will use the
``override()`` ``bpftrace`` method which will abort the probed function an will return the return
code provided in argument. This functionality requires that your kernel was
compiled with ``CONFIG_BPF_KPROBE_OVERRIDE`` and only works on functions with the
``ALLOW_ERROR_INJECTION`` tag. Fortunately Arch Linux's kernel already comes
with ``CONFIG_BPF_KPROBE_OVERRIDE`` enabled, and every syscall handler seems to
have the ``ALLOW_ERROR_INJECTION`` tag on them.

So here is a [script](https://github.com/Skallwar/blocksig/blob/main/blocksig.sh)
to block all signals to your process:
```bash
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
```

Let's take an example:
```terminal
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
```

As you can see, the second time around, our ping did not get killed. We actually 
blocked a ``SIGKILL``.

As a side note, the first time I launched ``blocksig.sh``, I did not filter on the 
pid before calling ``override()``. As a side effect, ``systemctl`` refused to either 
``poweroff`` or ``reboot`` my machine.

This technique works fine but we just moved the problem elsewhere. Now our process
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
```python
#!/usr/bin/python
# sudo ./hello_world.py

from bcc import BPF

BPF(text='int syscall__kill(void *ctx) { bpf_trace_printk("Hello, World!\\n"); return 0; }').trace_print()
```

So we write some C code as a string inside our Python script... Weird but why not ?
You can also load from a file like so:
```c
int syscall_kill(void *ctx) {
    bpf_trace_printk("Hello, World!\\n"); 
    return 0;
}
```

```python
#!/usr/bin/python
# sudo ./hello_world.py

from bcc import BPF

BPF(src_file = "hello_world.c")
```

In order to prevent our script to be killed, it needs to be able to block 
signals for multiples pids. I also want to block multiple signals. But how do 
we provide this arguments to our eBPF program? This is done using eBPF maps. 
Maps are data structures used to share data between userland and our eBPF 
program.
There are a lot of different [kinds of maps](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#maps),
going from arrays to hashmaps. To create a new map with BCC you use the 
``BPF_YOURTYPEHERE`` macro in your C stub like so:
```c
BPF_HASH(pids, int, u8); // Syntax: BPF_HASH(name, key_type, value_type)
```

For the eBPF hook, the logic is quite simple: if the given pid is inside the
pids hashmap and the signal is in the signal array, then we need to return early
from the syscall.

Here is the C code corresponding to this algorithm:
```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(pids, int, u8);
BPF_ARRAY(sigs, u8, 65);

static u8 needs_block(u8 protected_pid, u8 protected_sig) {
    return protected_pid != 0 && protected_sig != 0;
}

int syscall__kill(struct pt_regs *ctx, int pid, int sig)
{

    u8 *protected_pid = pids.lookup(&pid);
    u8 *protected_sig = sigs.lookup(&sig);
    if (!protected_pid || !protected_sig)
        return 0;

    if (needs_block(*protected_pid, *protected_sig)) {
        bpf_trace_printk("Blockeg signal %d for %d\\n", sig, pid);
        bpf_override_return(ctx, 0);
    }

    return 0;
}
```

The Python part needs a bit more logic to work:
- Parse the arguments to retrieve signals to block and the pids that need to be
protected
- Add the pid of the Python script
- Put the pids to block inside the corresponding maps

Here is the Python code (without the argument parsing because that's boring):
```python
# Args is the resulting object of parse_args() method of argparse
def initialize_bpf(args):
    b = BPF(src_file="blocksig.c")
    kill_fnname = b.get_syscall_fnname('kill')
    b.attach_kprobe(event=kill_fnname, fn_name='syscall__kill')
    pids_map = b.get_table('pids')
    sigs_map = b.get_table('sigs')

    args.pids.append(str(os.getpid()))
    for pid in args.pids:
        pids_map[c_int(int(pid))] = c_int(1)

    for sig in args.sig_array:
        sigs_map[sig] = c_int(1)
```

Time for a demo:
```terminal
$ ping skallwar.fr > /dev/null &
[1] 315629
$ sudo ./blocksig.py 315629 &
$ kill -9 315629
$ # Nothing happened
$ kill -9 $(pidof python) # Pid of the blocksig
$ # Nothing append
```

But a new problem arises. If we protect our script and we close the terminal,
how can we stop it? So I've implemented a system of ticket (a simple file with 
a unique name) in the tmpfs where the script is pooling whether our ticket has 
been deleted or not:
```python
def wait_for_close():
# Create a tempfile and wait for its deletion
    tf = tempfile.NamedTemporaryFile(delete = False)
    print(f"This script might not be killable anymore. To stop it run ``rm {tf.name}``")

    try:
        while os.path.isfile(tf.name):
            time.sleep(0.5)
            continue
    except KeyboardInterrupt:
        tf.close()
        os.remove(tf.name)
        print('')
```

So there is are 2 use cases:
- Keep it running in the shell and you can use ``CTRL+C`` to stop it (SIGINT 
can still be blocked)
- Run it in the background and use the unique ticket in order to stop it

After all of this we should be good, we can protect ourself and our targeted pids.
Let's see what it looks like in htop, just to make sure.

{{<figure src="images/blocksig_py_sudo_pid_problem.png">}}
{{<figure src="images/here_we_go_again.png">}}

At this stage I was quite frustrated. Yes you could make it work by logging as 
root and not using ``sudo`` but that's not convenient at all. Fortunately I 
found a [post on stack overflow](https://stackoverflow.com/questions/47284045/switch-user-without-creating-an-intermediate-process)
about forcing sudo not to fork, suggesting me to use ``exec`` before ``sudo``.
And for once, "it works on my machine"™ out of the box, nice.


So here is the final result:
```c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

BPF_HASH(pids, int, u8);
BPF_ARRAY(sigs, u8, 65);

static u8 needs_block(u8 protected_pid, u8 protected_sig) {
    return protected_pid != 0 && protected_sig != 0;
}

int syscall__kill(struct pt_regs *ctx, int pid, int sig)
{
    u8 *protected_pid = pids.lookup(&pid);
    u8 *protected_sig = sigs.lookup(&sig);
    if (!protected_pid || !protected_sig)
        return 0;
    if (needs_block(*protected_pid, *protected_sig)) {
        bpf_trace_printk("Blockeg signal %d for %d\\n", sig, pid);
        bpf_override_return(ctx, 0);
    }
    return 0;
}
```

```python
#!/usr/bin/python

from bcc import BPF
from bcc.utils import ArgString, printb
from ctypes import *
import argparse
import tempfile
import time
import os

def parse_args():
    parser = argparse.ArgumentParser(description='Blocksig is a tool to block certain or all signal to be recived by given pids')
    parser.add_argument('-p', dest='pids', nargs='+', default=[], metavar='pid', help='List of pid to protect')
    parser.add_argument('-s', dest='sigs', nargs='+', default=[], metavar='signal_num', help='List of signal to block. If no signal is specified, they are all blocked')
    parser.add_argument('--auto-protect', action=argparse.BooleanOptionalAction, default=True, help='Whether to protect blocksig itself or not')
    args = parser.parse_args()

    return args


def initialize_bpf(args):
    b = BPF(src_file = "blocksig.c")
    kill_fnname = b.get_syscall_fnname('kill')
    b.attach_kprobe(event=kill_fnname, fn_name='syscall__kill')
    pids_map = b.get_table('pids')
    sigs_map = b.get_table('sigs')

    if args.auto_protect == True:
        args.pids.append(str(os.getpid()))
    for pid in args.pids:
        pids_map[c_int(int(pid))] = c_int(1)

    sig_array = [int(sig) for sig in args.sigs] if len(args.sigs) else range(1, 64)
    for sig in sig_array:
        sigs_map[sig] = c_int(1)

def wait_for_close():
# Create a tempfile and wait for its deletion
    tf = tempfile.NamedTemporaryFile(delete = False)
    print(f"This script might not be killable anymore. To stop it run ``rm {tf.name}``")

    try:
        while os.path.isfile(tf.name):
            time.sleep(0.5)
            continue
    except KeyboardInterrupt:
        tf.close()
        os.remove(tf.name)
        print('')

args = parse_args()
initialize_bpf(args)
wait_for_close()
```

You can find all the code (and maybe future updates 👀) on [Github](https://github.com/Skallwar/blocksig)

# Libbpf
Before using BCC, I tried to use[``libbpf``](https://github.com/libbpf/libbpf)
but it did not worked well. Using almost the same C code for the actual eBPF part,
all the syscall arguments had strange values and thus, nothing worked. You can 
see what I tried to do on the [libbpf branch on Github](https://github.com/Skallwar/blocksig/tree/libbpf)
