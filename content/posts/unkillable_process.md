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
All signals can be catched except ``SIGKILL`` and ``SIGSTOP``.

> The SIGKILL signal is used to cause immediate program termination. It cannot be handled or ignored, and is therefore always fatal. It is also not possible to block this signal. [...] if SIGKILL fails to terminate a process, that by itself constitutes an operating system bug which you should report.
>
> -- <cite>[Termination Signals](https://www.gnu.org/software/libc/manual/html_node/Termination-Signals.html)</cite>

> The SIGSTOP signal stops the process. It cannot be handled, ignored, or blocked.
>
> -- <cite>[Job Control Signals](https://www.gnu.org/software/libc/manual/html_node/Job-Control-Signals.html)</cite>

This seems to be two strong afirmations so this should be true. But I don't 
want my process to die, I heard you say. Well if I can't catch them, what do 
you want me to do? Kill the sender?

Actualy I can't kill the sender, but I could try to stop the message...

# Meet eBPF
> The Linux kernel has always been an ideal place to implement monitoring/observability, networking, and security. Unfortunately this was often impractical as it required changing kernel source code or loading kernel modules, and resulted in layers of abstractions stacked on top of each other. eBPF is a revolutionary technology that can run sandboxed programs in the Linux kernel without changing kernel source code or loading kernel modules.
>
>By making the Linux kernel programmable, infrastructure software can leverage existing layers, making them more intelligent and feature-rich without continuing to add additional layers of complexity to the system or compromising execution efficiency and safety.
>
> -- <cite> [eBPF](https://ebpf.io/) </cite>

My idea was as simple as blocking the signal so that it will never reach our
process. In order to do so, I tried to catch the signal as early as posible in
the kernel: when a process uses the [``kill``](https://man7.org/linux/man-pages/man2/kill.2.html) syscall.

Fortunatly, all syscall have a [``kprobe``](https://www.kernel.org/doc/Documentation/kprobes.txt) hook point. The goal here is to filter signals for our process and discard them.
In order to discard them, I will use the ``override()`` which will abort the probed function an will return the return code provided in argument. This fonctionality require that your kernel is compiled with ``CONFIG_BPF_KPROBE_OVERRIDE`` and only works on function with the``ALLOW_ERROR_INJECTION`` tag. Fortunatly ArchLinux kernel already come with ``CONFIG_BPF_KPROBE_OVERRIDE`` and every syscall handler seems to have the ``ALLOW_ERROR_INJECTION`` tag on them.

So using bpftrace, here is a script to block all signals to your process:
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

Let's take an exemple:
{{<highlight terminal>}}
$ # Without blocksig.sh
$ ping skallwar.fr > /dev/null &
[1] 371628
$ kill -9 371628
[1]+  Killed                  ping skallwar.fr > /dev/null

$ # With blocksig.sh
$ ping skallwar.fr > /dev/null &
[1] 315629
$ sudo ./blocksig.sh 315629
$ kill -9 371628
{{</highlight>}}

As you can see, the second time around, our ping did not stop and the ``SIGKILL`` was
avoided.

As a side note, the first time I launched blocksig.sh, I did not filter on the pid before doing the override. As a side effect, systemctl refused to either poweroff or reboot my machine
