#ifndef VM_PAGE_H
#define VM_PAGE_H

#include <hash.h>

#define VM_BIN 0
#define VM_FILE 1
#define VM_ANON 2


/* virtual memory */
struct vm_entry{
	uint8_t type;
	void *vaddr;
	bool writable;

	bool is_loaded;
	struct file *file;

	size_t offset;
	size_t read_bytes;
	size_t zero_bytes;

	/* for swapping */
	size_t swap_slot;

	struct hash_elem elem;
};


struct page{
	void *kaddr; // physical address of this page
	struct vm_entry *vme; // corresponding virtual memory entry
	struct thread *thread; // pointer of thread using this page
	struct list_elem lru; // element for lru list
};

void vm_init(struct hash *vm);

struct vm_entry *find_vme(void *vaddr);
bool insert_vme(struct hash *vm, struct vm_entry *vme);
bool delete_vme(struct hash *vm, struct vm_entry *vme);

void vm_destroy(struct hash *vm);

void check_valid_buffer(void *buffer, unsigned size, void *esp, bool to_write);
void check_valid_string(const void *str, void *esp);

bool load_file(void *kaddr, struct vm_entry *vme);

#endif
