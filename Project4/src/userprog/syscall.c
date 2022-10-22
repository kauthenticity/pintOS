#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/palloc.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "userprog/exception.h"
#include <string.h>

struct file{
	struct inode *inode;
	int pos;
	bool deny_write;
};

struct lock file_syn_lock;

static void syscall_handler (struct intr_frame *);


struct vm_entry *verify_addr(void *addr, void *esp){
	struct vm_entry *vme;

	if(!is_user_vaddr(addr)){
	//if(addr < (void *)0x08048000 || addr >= (void *)0xc0000000){
		exit(-1);
	}
	
	vme = find_vme(addr);
	if(!vme){
		if (!verify_stack (addr, esp)){
			exit (-1);
		}
		expand_stack (addr);
		//exit(-1);
	}

	return vme;
}

void verify_NULL(void *pointer){
	if(pointer==NULL){
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
/*
	tid_t tid = process_execute(cmd_line);

	if(tid == TID_ERROR){
		return TID_ERROR;
	}
	struct thread *child = thread_get_child(tid);

	sema_down(&child->load);

	if(!child->load_success){
		return -1;
	}
	return tid;
*/
	return process_execute(cmd_line);
}

int wait(pid_t pid){
	return process_wait(pid);
}

int read(int fd, void *buffer, unsigned size){
	//pin_string(buffer, buffer+size, true);
	lock_acquire(&file_syn_lock);		
	int bytes = 0;
	/* stdin */
	if(fd==0){
		for(unsigned i=0; i<size; i++){
			char key = input_getc();
			*((char *)(buffer)+i) = key;
			if(key == '\0'){
				break;
			}
			bytes++;
		}
	}
	else if(fd>=3 && fd<128){
		struct thread *cur = thread_current();
		struct file *f = cur->fd[fd];
		
		/* fd에 해당하는 파일이 존재하지 않는 경우 */
		if(f == NULL || buffer == NULL){
			bytes = -1;
		}
		else{
			if(!is_user_vaddr(buffer)){
				lock_release(&file_syn_lock);
				//unpin_string(buffer, buffer+size);
				exit(-1);
			}
			bytes = file_read(f, buffer, size);
		}
	}
	else{
		bytes = -1;
	}
	lock_release(&file_syn_lock);
	//unpin_string(buffer, buffer+size);
	return bytes;
}

int write(int fd, const void *buffer, unsigned size){
	lock_acquire(&file_syn_lock);
	int bytes = -1;
	/* STDOUT */
	if(fd == 1){
		putbuf((char *)buffer, (size_t)size);
		bytes = size;
	}
	else if(fd >=3 && fd <128){
		struct thread *cur = thread_current();
		struct file *f = cur->fd[fd];
		if(f == NULL || buffer == NULL){
			bytes= -1;
		}
		else{
			if(!is_user_vaddr(buffer))	{
				lock_release(&file_syn_lock);
				exit(-1);
			}
		/* 현재 해당 파일이 실행중이라 write가 거부된 경우 */
			if(f->deny_write){
				bytes = 0;
			}
			else{/* write가 allow인 경우에는 write를 합니다 */	
				bytes = file_write(f, buffer, size);
			}
		}
	}
	else{
		bytes = -1;
	}

	lock_release(&file_syn_lock);
	return bytes;
}

bool create(const char *file, unsigned initial_size){
	verify_NULL((void *)file);
	return filesys_create(file, initial_size);
}

bool remove(const char *file){
	verify_NULL((void *)file);

	/* 파일이 remove돼도 그 파일을 참조하는 File descriptor가 close되거나 핀토스가 종료되기 전까지는 file descriptor에 살아있게 됨
	따라서 항상 그 파일이 존재하는지 확인해야 함.*/
	return filesys_remove(file);
}

int open(const char *file){
	verify_NULL((void *)file);

	lock_acquire(&file_syn_lock);
	struct thread *cur = thread_current();
	struct file *f = filesys_open(file);
	
	/* no such file */
	if(f==NULL){
		lock_release(&file_syn_lock);
		return -1;
	}
	uint32_t fd_idx = cur->fd_idx;
	cur->fd[fd_idx] = f;
	cur->fd_idx++;


	/* 현재 실행중인 스레드와 파일이 같은 경우에는 */
		if(!strcmp(cur->name, file)){
			file_deny_write(f);
			// 그 파일에 작성하지 못하게 함
		}
	lock_release(&file_syn_lock);
	return fd_idx;
}

int filesize(int fd){
	struct thread *cur = thread_current();

	// fd에 해당하는 파일이 존재하지 않는 경우 exit(-1)
	if(cur->fd[fd]==NULL){
		exit(-1);
	}
	return file_length(cur->fd[fd]);
}

void seek(int fd, unsigned position){
	struct thread *cur = thread_current();

	if(cur->fd[fd]==NULL){
		exit(-1);
	}

	file_seek(cur->fd[fd], position);
}

unsigned tell(int fd){
	struct thread *cur = thread_current();
	if(cur->fd[fd]==NULL){
		exit(-1);
	}

	return (unsigned)file_tell(cur->fd[fd]);
}

void close(int fd){
	lock_acquire(&file_syn_lock);
	struct thread *cur = thread_current();
	if(cur->fd[fd]==NULL){
		lock_release(&file_syn_lock);
		exit(-1);
	}


	file_close(cur->fd[fd]);
	cur->fd[fd] = NULL;
	lock_release(&file_syn_lock);
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
/*
void pin_address(void *addr, bool write){
	struct vm_entry *vme = find_vme(addr);
	if(write && vme->writable){
		exit(-1);
	}
	//vme->pinned = true;
	if(vme->is_loaded == false){
		handle_mm_fault(vme);
	}
}

void unpin_address(void *vaddr){
	struct vm_entry *vme;
	vme = find_vme(vaddr);
	if(vme!=NULL){
		vme->pinned = false;
	}
}

void pin_string(const char *begin, const char *end, bool write){
	for (; begin < end; begin += PGSIZE){
    pin_address ((void *)begin, (void *)write);
	}
}

void unpin_string(const char *begin, const char *end){
	for (; begin < end; begin += PGSIZE){
    unpin_address ((void *)begin);
	}
}

*/
void
syscall_init (void) {
	lock_init(&file_syn_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	uint32_t syscall_num = *(uint32_t *)(f->esp);
	verify_addr((f->esp), f->esp);

	switch (syscall_num){
		case SYS_HALT :
		{
			halt();
			break;
		}
		case SYS_EXIT : 
		{
			verify_addr((f->esp)+4, f->esp);
			uint32_t status = *(int *)((f->esp)+4);
			exit(status);
			break;
		}
		case SYS_EXEC : 
		{	
			//verify_addr((f->esp)+4, f->esp);
			char *cmd_line = (char *)*(uint32_t *)((f->esp)+4);

			check_valid_string((const void *)cmd_line, f->esp);
			pid_t status = exec(cmd_line);
			
			//unpin_string((void *)cmd_line);

			f->eax = status;
			break;
		}
		case SYS_WAIT : 
		{
			verify_addr((f->esp)+4, f->esp);

			pid_t pid = *(pid_t *)((f->esp)+4);
			uint32_t status = wait(pid);
			f->eax = status;

			break;
		}
		case SYS_WRITE : 
		{
			//verify_addr((f->esp)+4, f->esp);
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			void *buffer = (void *)*(uint32_t *)((f->esp)+8);
			unsigned size = *(uint32_t *)((f->esp)+12);
			check_valid_buffer(buffer, size, f->esp, false);
			int status = write(fd, buffer, size);
			f->eax = status;

			//unpin_buffer(buffer, size);
			break;
		}
		case SYS_READ : 
		{
			//verify_addr((f->esp)+4, f->esp);
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			void *buffer = (void *)*(uint32_t *)((f->esp)+8);
			unsigned size = *(uint32_t *)((f->esp)+12);
			check_valid_buffer(buffer, size, f->esp, true);
			int status = read(fd, buffer, size);
			
			f->eax = status;	

			//unpin_buffer(buffer, size);

			break;
		}
		case SYS_CREATE : 
		{
			//verify_addr((f->esp)+4, f->esp);
			//verify_addr((f->esp)+8, f->esp);
			const char *file = (const char *)*(uint32_t *)((f->esp)+4);
			unsigned size = *(uint32_t *)((f->esp)+8);

			check_valid_string((const void *)file, f->esp);

			bool status = create(file, size);
			f->eax = status;

			//unpin_string((void *)file);

			break;
		}
		case SYS_REMOVE :
		{
			//verify_addr((f->esp)+4, f->esp);
			//verify_addr((f->esp)+8, f->esp);
			const char *file = (const char *)*(uint32_t *)((f->esp)+4);
			check_valid_string((const void *)file, f->esp);
			bool status = remove(file);
			f->eax = status;
			break;
		}
		case SYS_OPEN : 
		{
			verify_addr((f->esp)+4, f->esp);
			const char *file = (const char *)*(uint32_t *)((f->esp)+4);
			check_valid_string((const void *)file, f->esp);
			int status = open(file);
			f->eax = status;

			//unpin_string((void *)file);

			break;
		}
		case SYS_FILESIZE : 
		{
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			int status = filesize(fd);
			f->eax = status;
			break;
		}
		case SYS_SEEK : 
		{
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			unsigned position = *(uint32_t *)((f->esp)+8);
			seek(fd, position);
			break;
		}
		case SYS_TELL : 
		{
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			unsigned status = tell(fd);
			f->eax = status;
			break;
		}
		case SYS_CLOSE : 
		{
			uint32_t fd = *(uint32_t *)((f->esp)+4);
			close(fd);
			break;
		}
		case SYS_FIBONACCI : 
		{
			verify_addr((f->esp)+4, f->esp);
			int n = *(uint32_t *)((f->esp)+4);
			int res = fibonacci(n);
			f->eax = res;
			break;
		}
		case SYS_MAX_OF_FOUR_INT : 
		{
			verify_addr((f->esp)+4, f->esp);
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
