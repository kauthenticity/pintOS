#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/syscall.h"

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */


tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  struct file *file = NULL;
  tid_t tid;

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);
	
	/* parse file name  */
	/* echo x -> echo */
	char tmp_file_name[1000];
	char *next_ptr;
	strlcpy(tmp_file_name, file_name, strlen(file_name)+1);
	//tmp_file_name = strtok_r(tmp_file_name, " ", &next_ptr);
	next_ptr = strtok_r(tmp_file_name, " ", &next_ptr);

  //file = filesys_open (tmp_file_name);
  file = filesys_open (next_ptr);
	if(file==NULL){
		file_close(file);
    palloc_free_page (fn_copy); 
		return -1;
	}
	/* exec("no-such-file") */


  /* Create a new thread to execute FILE_NAME. */
  //tid = thread_create (file_name, PRI_DEFAULT, start_process, fn_copy);
  tid = thread_create (tmp_file_name, PRI_DEFAULT, start_process, fn_copy);
	
	sema_down(&(thread_current()->load));

  if (tid == TID_ERROR){
    palloc_free_page (fn_copy); 
	}
	
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);

	vm_init(&(thread_current()->vm));
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;

	//struct thread *t = thread_current();
	success = load (file_name, &if_.eip, &if_.esp);
	//t->load_success = load (file_name, &if_.eip, &if_.esp);
	sema_up(&(thread_current()->parent->load));
	//sema_up(&(t->load));
  /* If load failed, quit. */

	if(!success){
  //if (!t->load_success){
		palloc_free_page(file_name);
		exit(-1);
    //thread_exit ();
	} 
	palloc_free_page(file_name);
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If

   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED){

	struct list_elem *e = list_begin(&(thread_current()->childs));
	struct thread *cur_child;
	int status = -1;

	while(e != list_end(&(thread_current()->childs))){
		cur_child = list_entry(e, struct thread, child);

		if(cur_child->tid == child_tid){
			sema_down(&(cur_child->sema));
			status = cur_child->exit_status;
			list_remove(&(cur_child->child));
			sema_up(&(cur_child->sync));
			return status;
		}
		e = list_next(e);
	}	


/*
	int status;
	struct thread *child = thread_get_child(child_tid);

	if(child == NULL){
		return -1;
	}

	sema_down(&child->sema);
	status = child->exit_status;
	list_remove(&child->child);
	sema_up(&child->sync);
*/
	return status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *cur = thread_current ();
  uint32_t *pd;

	for(int i=0; i<128; i++){
		if(cur->fd[i] != NULL){
			file_close(cur->fd[i]);
			cur->fd[i] = NULL;
		}
	}

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

	vm_destroy(&(cur->vm));
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

	/* 열려있는 파일 다 닫아주고 닫혔으니 fd가 가리키는 곳도 NULL */
	
	/* up the sempaphore of this process */	
	sema_up(&(cur->sema));
	sema_down(&(cur->sync));
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

	/* TODO : parse file name*/

	char tmp_file_name[1000];
	char *argv[50];
	int idx = 0;
	
	char *ret_ptr;
	char *next_ptr; 

	strlcpy(tmp_file_name, file_name, strlen(file_name)+1);
	// file_name이 const이므로 tmp_file_name에 strcpy

	if(tmp_file_name == NULL){
		printf("no argvs\n");
		return success;
	}


	ret_ptr = strtok_r(tmp_file_name, " ", &next_ptr);

	while(ret_ptr){
		argv[idx] = ret_ptr;
		idx++;
		ret_ptr = strtok_r(NULL, " ", &next_ptr);
	}
	// 띄어쓰기 단위로 끊어줌

  /* Open executable file. */
  file = filesys_open (argv[0]);
	

  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", argv[0]);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

	/* TODO : construct stack */
	(*esp) = PHYS_BASE;
	// 스택의 맨 위를 PHYS_BASE로 초기화



	/* push argv */
	int *argv_addr[50]; // argv들이 저장된 메모리 영역의 주소
	int word_align = 0; // 메모리에 저장한 총 크기
	
	for(i=idx-1; i>=0; i--){
		int size = strlen(argv[i]) + 1;
		(*esp) -= size; // esp가 가리키는 메모리의 주소를 size만큼 내림 
		argv_addr[i] = (*esp);
		memcpy(*esp, argv[i], size);
		word_align = word_align + size;
	}


	/* word_align */
	word_align = 4 - (word_align % 4);
	if(word_align %4 != 0){
		(*esp) -= word_align;
	}

	/* push NULL */
	(*esp) -= 4;
	**(uint32_t**)esp = 0;

	for(int i=idx-1; i>=0; i--){
		(*esp) -= 4;
		*(int **)(*esp) = argv_addr[i];
	}

	/* push address of argv[0] */
	(*esp) -= 4;
	(*(int **)(*esp)) = (*esp) + 4;
	
	/* push argc */
	(*esp) -= 4;
	(*(int *)(*esp)) = idx;

	/* push return address */
	(*esp) -= 4;
	**(int **)esp = 0;
	
/*
	// 여기서부터 아래 주석까지는 스택 출력하는 부분
	printf("------------------stack printing---------------\n");
	int ofs = (uintptr_t)*esp;
	int byte_size = 0xc0000000-ofs;
	hex_dump(ofs, *esp, byte_size, true);
	// 스택 출력 
*/
  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;
 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

bool handle_mm_fault(struct vm_entry *vme){
	struct page *kpage = alloc_page(PAL_USER);
	kpage->vme = vme;
	//vme->pinned = true;

	bool success = true;

	switch(vme->type){
		case VM_FILE : 
		case VM_BIN : 
		{
			// load file success
			
			if(load_file(kpage->kaddr, vme)){
				if(!install_page(vme->vaddr, kpage->kaddr, vme->writable)){
					free_page(kpage->kaddr);
					return false;
				}
			}
			// load file fail
			else{
				free_page(kpage->kaddr);
				return false;
			}
			break;
			
		}
		case VM_ANON : 
		{
			
			swap_in(vme->swap_slot, kpage->kaddr);

			if(!install_page(vme->vaddr, kpage->kaddr, vme->writable)){
				free_page(kpage->kaddr);
				return false;
			}
			break;
		}
	}

	vme->is_loaded = true;
	return success;
}

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

	struct file *reopen_file = file_reopen(file);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

			struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
			if(vme==NULL) return false;

			vme->file = reopen_file;
			vme->offset = ofs;
			vme->vaddr = upage;
	
			//printf("vme->vaddr : %p\n", vme->vaddr);

			vme->read_bytes = page_read_bytes;
			vme->zero_bytes = page_zero_bytes;
			vme->writable = writable;
			vme->is_loaded = false;
			vme->type = VM_BIN;
			//vme->pinned = false;

			if(!insert_vme(&(thread_current()->vm), vme)){
				printf("insert vme error!!\n");
			}
      /* Advance. */
			ofs += page_read_bytes;
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;

    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  //uint8_t *kpage;
	struct page *kpage;
  bool success = false;
  kpage = alloc_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
			//add_page_to_lru_list(kpage);
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage->kaddr, true);
      if (success)
        *esp = PHYS_BASE;
      else{
        free_page (kpage->kaddr);
			}
    }

	struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
	vme->type = VM_ANON;
	vme->vaddr = ((uint8_t *)PHYS_BASE) - PGSIZE;
	vme->writable = true;
	vme->is_loaded = true;
	//vme->pinned = true;
	kpage->vme = vme;

	success = insert_vme(&(thread_current()->vm), vme);

  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

bool expand_stack(void *addr){

	struct page *kpage;
	
	void *vaddr = pg_round_down(addr);
	
	kpage = alloc_page(PAL_USER | PAL_ZERO);

	struct vm_entry *vme = (struct vm_entry *)malloc(sizeof(struct vm_entry));
	
	vme->type = VM_ANON;
	vme->vaddr = vaddr;
	vme->writable = true;
	vme->is_loaded = true;
	//vme->pinned = true;

	if(!install_page(vaddr, kpage->kaddr, true)){
		free_page(kpage);
		free(vme);
		return false;
	}


	kpage->vme = vme;
	insert_vme(&(thread_current()->vm), kpage->vme);

	//add_page_to_lru_list(kpage);

	return true;


}
