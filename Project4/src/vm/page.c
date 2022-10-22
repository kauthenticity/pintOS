#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <threads/malloc.h>
#include <threads/palloc.h>
#include "vm/page.h"
#include "userprog/pagedir.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/syscall.h"

bool load_file(void *kaddr, struct vm_entry *vme){
/*
	size_t bytes_read = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);

	// 파일을 전부 다 읽었는데, 패딩할 영역이 남은 경우
	if(bytes_read == vme->read_bytes && bytes_read < PGSIZE){
		if(!memset(kaddr + bytes_read, 0, sizeof(uint32_t)*(vme->zero_bytes))){
			return false;
		}
	}

	return true;
*/


	size_t bytes_read = file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset);
	if(bytes_read == vme->read_bytes){
		if(!memset(kaddr + bytes_read, 0, vme->zero_bytes)){
			return false;
		}
	}
	return true;
/*
	bool result = false;   
	if((int)vme->read_bytes == file_read_at(vme->file, kaddr, vme->read_bytes, vme->offset)){
		result = true;
		memset(kaddr + vme->read_bytes, 0, vme->zero_bytes);
	}

	return result;
*/

}

struct vm_entry *find_vme(void *vaddr){
	/* get page number through pg_round_down() */
	/* get hash_elem structure through hash_find() function */
	/* if not exists -> return NULL */
	/* find vm_entry of hash_elem through hash_entry and return it */
	struct vm_entry vme;
	struct hash_elem *h_elem;

	vme.vaddr = pg_round_down(vaddr);
	h_elem = hash_find(&thread_current()->vm, &vme.elem);

	if(h_elem != NULL){
		return hash_entry(h_elem, struct vm_entry, elem);
	}

	return NULL;
}
	
static unsigned vm_hash_func(const struct hash_elem *e, void *aux UNUSED){
	struct vm_entry *vm = hash_entry(e, struct vm_entry, elem);
	return hash_int((int)vm->vaddr);
}

static bool vm_less_func(const struct hash_elem *a, const struct hash_elem *b, void *aux UNUSED){
	struct vm_entry *vmA = hash_entry(a, struct vm_entry, elem);
	struct vm_entry *vmB = hash_entry(b, struct vm_entry, elem);
	return (vmA->vaddr) < (vmB->vaddr) ? true : false;
}
void vm_init(struct hash *vm){
	hash_init(vm, vm_hash_func, vm_less_func, 0);
}

bool insert_vme(struct hash *vm, struct vm_entry *vme){
	return hash_insert(vm, &(vme->elem)) == NULL ? true : false;
}

bool delete_vme(struct hash *vm, struct vm_entry *vme){
	bool res = false;
	if(hash_delete(vm, &vme->elem) != NULL){
		res = true;
	}
	free(vme);
	return res;
}

static void vm_destory_func(struct hash_elem *e, void *aux UNUSED){
	struct vm_entry *vme = hash_entry(e, struct vm_entry, elem);

	if(vme->is_loaded){
		void *kaddr = pagedir_get_page(thread_current()->pagedir, vme->vaddr);
		pagedir_clear_page(thread_current()->pagedir, vme->vaddr);
		free_page(kaddr);
	}

	free(vme);
}

void vm_destroy(struct hash *vm){
	/* remove bucket lists and vm_entries of hash table through hash_destroy() function */
	hash_destroy(vm, vm_destory_func);
}

void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write){
	
	unsigned tempSize = 0;

	while(tempSize < size){
		struct vm_entry *vme = verify_addr(buffer + tempSize, esp);

		if(vme==NULL || (to_write==true && vme->writable==false)){
			exit(-1);
		}

		tempSize += PGSIZE;
	}
}

void check_valid_string(const void *str, void *esp){
	verify_addr((void *)str, esp);
}
