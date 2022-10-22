#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include <string.h>

static void syscall_handler (struct intr_frame *);

void verify_addr(int *addr){
	if(!is_user_vaddr(addr)){
		exit(-1);
	}
}

void halt(void){
	shutdown_power_off();
}

void exit(int status){
	struct thread *cur = thread_current();
	cur->exit_status = status;
	printf("%s: exit(%d)\n", thread_name(), status);	
	thread_exit();
}

pid_t exec(const char *cmd_line){
	return process_execute(cmd_line);
}

int wait(pid_t pid){
	return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size){
	int input_size = 0;
	if(fd==0){
		for(unsigned i=0; i<size; i++){
			char key = input_getc();
			*((char *)(buffer)+i) = key;
			if(key == '\0'){
				break;
			}
			input_size++;
		}
	}

	return input_size;
}

int write(int fd, const void *buffer, unsigned size){
	/* STDOUT */
	if(fd == 1){
		putbuf((char *)buffer, (size_t)size);
	}

	return size;
}

int fibonacci(int n){
	if (n==1 || n==2){
		return 1;
	}
	
	int pre1 = 1;
	int pre2 = 1;
	int sum = 0;
	for(int i=3; i<=n; i++){
		sum = pre1+pre2;
		pre1 = pre2;
		pre2 = sum;
	}

	return sum;
}

int max_of_four_int(int a, int b, int c, int d){
	int arr[4];
	arr[0] = a; arr[1] = b; arr[2] = c; arr[3] = d;

	for(int i=0; i<4; i++){
		for(int j=i+1; j<4; j++){
			if(arr[i] < arr[j]){
				int t = arr[i];
				arr[i] = arr[j];
				arr[j] = t;
			}
		}
	}

	return arr[0];
}

void
syscall_init (void) {
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t syscall_num = *(uint32_t *)(f->esp);
	verify_addr((f->esp));

	switch (syscall_num){
		case SYS_HALT :
		{
			halt();
			break;
		}
		case SYS_EXIT : 
		{
			verify_addr((f->esp)+4);
			uint32_t status = *(int *)((f->esp)+4);
			exit(status);
			break;
		}
		case SYS_EXEC : 
		{	
			verify_addr((f->esp)+4);

			const char *cmd_line = (const char *)*(uint32_t *)((f->esp)+4);

			pid_t status = exec(cmd_line);
	
			f->eax = status;
			break;
		}
		case SYS_WAIT : 
		{
			verify_addr((f->esp)+4);

			pid_t pid = *(pid_t *)((f->esp)+4);
			uint32_t status = wait(pid);
			f->eax = status;

			break;
		}
		case SYS_WRITE : 
		{
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			const void *buffer = (const void *)*(uint32_t *)((f->esp)+8);
			unsigned size = *(uint32_t *)((f->esp)+12);
			int status = write(fd, buffer, size);
			f->eax = status;
			break;
		}
		case SYS_READ : 
		{
			verify_addr((f->esp)+4);
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			void *buffer = (void *)*(uint32_t *)((f->esp)+8);
			unsigned size = *(uint32_t *)((f->esp)+12);
			int status = read(fd, buffer, size);
			
			f->eax = status;	
			break;
		}
		case SYS_FIBONACCI : 
		{
			verify_addr((f->esp)+4);
			int n = *(uint32_t *)((f->esp)+4);
			int res = fibonacci(n);
			f->eax = res;
			break;
		}
		case SYS_MAX_OF_FOUR_INT : 
		{
			verify_addr((f->esp)+4);
			int a = *(uint32_t *)((f->esp)+4);
			int b = *(uint32_t *)((f->esp)+8);
			int c = *(uint32_t *)((f->esp)+12);
			int d = *(uint32_t *)((f->esp)+16);
			int res = max_of_four_int(a, b, c, d);
			f->eax = res;
			break;
		}
	}
	return;
}
