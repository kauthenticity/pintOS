#include "vm/frame.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "vm/swap.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

struct list lru_list;
struct lock lru_list_lock;
struct list_elem *lru_clock;

void lru_list_init(void){
	list_init(&lru_list);
	lock_init(&lru_list_lock);
	lru_clock = NULL;
}

void add_page_to_lru_list(struct page *page){
	lock_acquire(&lru_list_lock);
	list_push_back(&lru_list, &(page->lru));
	lock_release(&lru_list_lock);
}

void del_page_from_lru_list(struct page *page){
	if(lru_clock == &(page->lru)){
		lru_clock = list_remove(lru_clock);
	}
	else{
		if(!list_empty(&lru_list)){
			list_remove(&(page->lru));
		}
	}
}

struct page *alloc_page(enum palloc_flags flags){

	void *addr = palloc_get_page(flags);

	while(addr == NULL){
		try_to_free_pages();
		addr = palloc_get_page(flags);
	}
	
	struct page *page = (struct page *)malloc(sizeof(struct page));
	page->kaddr = addr;
	//page->vme = NULL;
	page->thread = thread_current();

	add_page_to_lru_list(page);

	return page;
	
}

void free_page(void *kaddr){
	struct list_elem *e;
	struct page *cur_page;

	lock_acquire(&lru_list_lock);
	e = list_begin(&lru_list);

	while(e != list_end(&lru_list)){
		cur_page = list_entry(e, struct page, lru);
		if(cur_page->kaddr == kaddr){
			__free_page(cur_page);
			break;
		}
		e = list_next(e);
	}

	lock_release(&lru_list_lock);
}

void __free_page(struct page *page){
	del_page_from_lru_list(page);
	palloc_free_page(page->kaddr);
	free(page);

}

static struct list_elem *get_next_lru_clock(void){

	if(lru_clock == NULL){
		if(list_empty(&lru_list)){
			return NULL;
		}
		else{
			lru_clock = list_begin(&lru_list);
			return lru_clock;
		}
	}

	if(!list_empty(&lru_list)){
		if(lru_clock == list_end(&lru_list)){
			lru_clock = list_begin(&lru_list);
			return lru_clock;
		}
		else{
			lru_clock = list_next(lru_clock);
			if(lru_clock == list_end(&lru_list)){
				lru_clock = list_begin(&lru_list);
			}

			return lru_clock;
		}
	}
	return lru_clock;

/*
	if (lru_clock == NULL || lru_clock == list_end (&lru_list)){
		if (list_empty (&lru_list)){
			return NULL;
		}
		else{
			return (lru_clock = list_begin (&lru_list));
		}
		
		lru_clock = list_next (lru_clock);
		if (lru_clock == list_end (&lru_list)){
			return get_next_lru_clock ();
		}
	return lru_clock;
	*/
}

struct page *get_victim(void){
	/* lru list를 돌면서page의 accessed bit가 1이면 0으로, 0이면 해당 페이지 리턴 */

	//struct list_elem *e = get_next_lru_clock();
	struct list_elem *e;
	struct page *page;

	//struct page *page = list_entry(e, struct page, lru);
	
	/*
	while(pagedir_is_accessed(page->thread->pagedir, page->vme->vaddr)){
		// set accessed bit to 1 of this page
		pagedir_set_accessed(page->thread->pagedir, page->vme->vaddr, false);
	
		// get next element from lru list and find it's page
		e = get_next_lru_clock();
		page = list_entry(e, struct page, lru);
	}
	*/

	while(1){
		e = get_next_lru_clock();
		page = list_entry(e, struct page, lru);
		// if the page is not accesed, then break
		if(!pagedir_is_accessed(page->thread->pagedir, page->vme->vaddr)){
			break;
		}

		// if page is accessed, then set its accessed bit false
		pagedir_set_accessed(page->thread->pagedir, page->vme->vaddr, false);
	}

	return page;
}

void try_to_free_pages(void){
	lock_acquire(&lru_list_lock);

	struct page *victim = get_victim();


	struct vm_entry *vme = victim->vme;

	bool dirty = pagedir_is_dirty(victim->thread->pagedir, victim->vme->vaddr);

	if(vme->type == VM_ANON){
		vme->swap_slot = swap_out(victim->kaddr);
	}

	else if(vme->type == VM_BIN){
		if(dirty){
			vme->swap_slot = swap_out(victim->kaddr);
			vme->type = VM_ANON;
		}
	}
	vme->is_loaded = false;
	pagedir_clear_page(victim->thread->pagedir, vme->vaddr);
	__free_page(victim);

	lock_release(&lru_list_lock);
}
