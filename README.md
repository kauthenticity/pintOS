# Pintos

Pintos project for Sogang Univ. Operating System(CSE4070)

## Project Description

### Project1

> All Pass

Project1 will enable programs to interact with the OS via system calls. We do argument passing and load them in stacks for system calls. Also implement exception handling to prevent user programs from invading kernel regions. And the goal is to implement the details of the system call so that the system call can operate.

### Project2

> All Pass

Implement system calls related with file systems on user program. Make file descriptor table for each thread to enable system calls such as filesize, seek and tell. Also, "race condition" can be happen when two threads attemp to access same file at the same time. So we need to synchronize file system to protect the file from concurrent access.

### Project3

> All Pass

In project3, we implement complex scheduler which considers thread's priority. We need knowledge of threads and synchronization techniques are needed to improve scheduler. Threads are the objects of scheduling. Synchronization such as semaphores or locks should be used in the scheduler to organize order of thread execution.

### Project4

> 12 / 16 Pass

In this project, we will make the pintos to be more reliable from page faults and to run the programs properly. First, we create a page table that maps the virtual address to a physical address. If the process no longer has a page to assign, it is possible to allocate a new page by validating one page table entry in the page table and swapping out to disk by implementing disk swapping. If the page fault occurs, system checks if the address occured error is stack area and grow the stack if it is right.

## Command Files Usage

### Description

<image src="https://velog.velcdn.com/images/kauthenticity/post/c1b68068-d13b-44d4-bfc6-4e938d4182b8/image.png" width="300px" />

- "Name" means the name of the test case.
- you can copy and paste "Command" in the build directory.

### Usage

1. cd build
2. copy and paste commands in excel files
3. execute
