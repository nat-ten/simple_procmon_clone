# simple_procmon_clone
A simple procmon clone for Linux

Run using sudo
This program traces each process in /proc to monitor all system calls made by each process.
Utilizes multi-threading by creating a thread for each process, tracing each process in its own thread.
Translates each system call value to its actual name using a jump table for fast performance.
