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
[signal](https://man7.org/linux/man-pages/man2/signal.2.html) or 
[sigaction](https://man7.org/linux/man-pages/man2/sigaction.2.html) syscalls.
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
