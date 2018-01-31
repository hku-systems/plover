#ifndef MEM_COMPARE_HASH_H
#define MEM_COMPARE_HASH_H

#define HASH_BITS 64 

#if HASH_BITS == 64
#define hash_t uint64_t
#define hash_sum_t __uint128_t 
#define HASH_MASK 0xffffffffffffffff
#define HASH_SHIFT 8
#elif HASH_BITS == 32 
#define hash_t uint32_t 
#define hash_sum_t uint64_t
#define HASH_MASK 0xffffffff
#define HASH_SHIFT 4
#endif


struct merkle_tree_t {
	hash_t *tree;
	uint64_t tree_size;
	uint8_t full;
	uint64_t full_part_last_index; 
	uint64_t first_leaf_index; 
	uint64_t last_level_leaf_count;
};

typedef struct merkle_tree_t merkle_tree_t; 

struct hash_list {
	hash_t **hashes;

	uint64_t **page_indices;

	uint64_t *len;

 
// /	uint64_t len; 
};

typedef struct hash_list hash_list;





hash_list* get_hash_list_pointer(void);


hash_list* get_remote_hash_list_pointer(void);

//Init global variables (locks, conds), call it once is enought
void hash_init(void);

void build_merkle_tree (unsigned long *bitmap, unsigned long len);

void compute_hash_list (unsigned long *bitmap, unsigned long len);

void compare_hash_list(void);

void print_hash_list(hash_list *list);

unsigned long * get_divergent_bitmap(void);

typedef struct clock_handler_t {
    struct timespec clocks[200];
    int counter;
}clock_handler;



void clock_init(clock_handler *c_k);
void clock_add(clock_handler *c_k);

void clock_display(clock_handler *c_k);

int get_n_thread(void);

#endif //MEM_COMPARE_HASH_H
