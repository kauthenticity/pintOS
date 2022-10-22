#include "vm/swap.h"
#include <bitmap.h>
#include "devices/block.h"
#include "threads/synch.h"
#include <stdio.h>
	
struct lock swap_lock;
struct bitmap *swap_bitmap;	
struct block *swap_block;

void swap_init(size_t size){
	swap_bitmap = bitmap_create(size);
	lock_init(&swap_lock);
}	
	
void swap_in(size_t used_index, void *kaddr){
	// used_index의 swap slot에 저장된 데이터를 논리 주소 kaddr로 복사

	struct block *swap_block;
	swap_block = block_get_role(BLOCK_SWAP);

	lock_acquire(&swap_lock);

	for(int i=0; i<8; i++){
		block_read(swap_block, used_index*8 + i, kaddr + i*BLOCK_SECTOR_SIZE);
	}
	//bitmap_set_multiple (swap_bitmap, used_index, 1, false);
	bitmap_flip(swap_bitmap, used_index);
	lock_release(&swap_lock);
}

size_t swap_out(void *kaddr){
	// kaddr 주소가 가리키는 페이지를 스왑 파티션에 기록
	// 페이지를 기록한 swap slot 번호를 리턴
	size_t index;
	struct block *swap_block = block_get_role(BLOCK_SWAP);

	lock_acquire(&swap_lock);	

	index = bitmap_scan_and_flip(swap_bitmap, 0, 1, false);
	index <<= 3;

	for(int i=0; i<8; i++){
		block_write(swap_block, index + i, kaddr + i*BLOCK_SECTOR_SIZE);
	}
	index >>= 3;
	lock_release(&swap_lock);
	return index;
}
