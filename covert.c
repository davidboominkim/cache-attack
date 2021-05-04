#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

// possible in 1 second 

// Access hardware timestamp counter
#define RDTSC(cycles) __asm__ volatile ("rdtsc" : "=a" (cycles));

// Serialize execution
#define CPUID() asm volatile ("CPUID" : : : "%rax", "%rbx", "%rcx", "%rdx");

// Intrinsic CLFLUSH for FLUSH+RELOAD attack
#define CLFLUSH(address) _mm_clflush(address);

#define SAMPLES 100 // make this value as small as possible without changing the results 

#define L1_CACHE_SIZE (32*1024)
#define LINE_SIZE 64
#define ASSOCIATIVITY 8
#define L1_NUM_SETS (L1_CACHE_SIZE/(LINE_SIZE*ASSOCIATIVITY)) // 64
#define NUM_OFFSET_BITS 6
#define NUM_INDEX_BITS 6
#define NUM_OFF_IND_BITS (NUM_OFFSET_BITS + NUM_INDEX_BITS)

uint64_t eviction_counts[L1_NUM_SETS] = {0};
__attribute__ ((aligned (64))) uint64_t trojan_array[32*4096];
__attribute__ ((aligned (64))) uint64_t spy_array[4096];


/*
 * This function provides an eviction set address, given the
 * base address of a trojan/spy array, the required cache
 * set ID, and way ID.
 *
 * Extract the tag bits of the eviction set address by simply right shifting the value of the base by the number of non-tag bits, aka the number of 
 * index and offset bits, since that means that all that will be left over is the tag bits. These tag bits will be a part of 
 * the returned eviction set address. Extract the index bits of the base address by first shifting right by the amount of offset bits. This will
 * get rid of the offset bits and make the index bits the least significant bits. Then, use this shifted value to perform an AND operation with the value
 * 0x3f (which is 0011 1111) in order to get rid of the tag bits and leave only the index bits. 
 * 
 * Now, we start constructing the eviction set address. The tag bits are shifted left by the number of index bits in order to append
 * the index bits to the eviction set address. Sometimes, the index bits of the base address (which is always either the trojan array or spy array) could start in the
 * middle of the cache, so if that is the case then we append the index bits as (L1_NUM_SETS + set) in order to utilize bit overflow to wrap around the cache. In all 
 * other cases, the index bits will just be the set ID. Then, we shift left by the number of offset bits in order to append the number of sets times the size of the lines 
 * times the way ID. This is another overflow, which is done to help direct and link eviction set addresses to other eviction set addresses.
 *
 */
uint64_t* get_eviction_set_address(uint64_t *base, int set, int way)
{
    // base is either the spy array or trojan array
    
    uint64_t tag_bits = (((uint64_t)base) >> NUM_OFF_IND_BITS);
    int idx_bits = (((uint64_t)base) >> NUM_OFFSET_BITS) & 0x3f;
    
    // sometimes index can be larger than set number because the base address of the trojan or spy array can be in the middle of the cache. 
    // base address of either of the 2 arrays can start in the  middle of the actual cache, so it would wrap around
    if (idx_bits > set) {
        // overflow (this is what changes the tag bits)
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) +
                               (L1_NUM_SETS + set)) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way)); // another overflow, to go from address 1 to address 2
    } else {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) + set) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way)); // another overflow 
    }
}

/* This function sets up a trojan/spy eviction set using the
 * function above.  The eviction set is essentially a linked
 * list that spans all ways of the conflicting cache set.
 *
 * i.e., way-0 -> way-1 -> ..... way-7 -> NULL
 *
 */
void setup(uint64_t *base, int assoc)
{
    uint64_t i, j;
    uint64_t *eviction_set_addr;

    // Prime the cache set by set (i.e., prime all lines in a set)
    for (i = 0; i < L1_NUM_SETS; i++) {
        // eviction_set_addr starts off pointing at some place in memory (base place/address)
        eviction_set_addr = get_eviction_set_address(base, i, 0);
        for (j = 1; j < assoc; j++) {
            // the VALUE at this address is set as the next address in memory.
            *eviction_set_addr = (uint64_t)get_eviction_set_address(base, i, j);
            // then, eviction_set_addr starts pointing to the value at the address it's pointing at (which is the next spot in memory)
            // that's how this is a linked list. 
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
        }
        *eviction_set_addr = 0;
    }
}

/* 
 * This function implements the trojan that sends a message
 * to the spy over the cache covert channel.  Note that the
 * message forgoes case sensitivity to maximize the covert
 * channel bandwidth.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */

void trojan(char byte)
{
    int set;
    uint64_t *eviction_set_addr;
    CPUID();
    // turn the char into an uppercase char, since we don't care about case sensitivity and want to maximize bandwidth. 
    if (byte >= 'a' && byte <= 'z') {
        byte -= 32;
    }
    // 10 --> new line, 13 --> carriage return (?)
    if (byte == 10 || byte == 13) { // encode a new line
        set = 63;
    } else if (byte >= 32 && byte < 96) {
        set = (byte - 32);
    } else {
        printf("pp trojan: unrecognized character %c\n", byte);
        exit(1);
    }

    // evict a set 
    
    // base address, the start of the linked list.
    eviction_set_addr = get_eviction_set_address(trojan_array, set, 0);
    
    // traverse the linked list. This will fill up the cache with trojan addresses
    while (*eviction_set_addr != 0){
        eviction_set_addr = *eviction_set_addr;
    }
    // every instruction after CPUID cannot be executed before all the instructions before CPUID are committed.
    // this is done because our processor is OOO so we need to make sure spy does not start until after trojan is done.
    CPUID();
}

/* 
 * This function implements the spy that receives a message
 * from the trojan over the cache covert channel.  Evictions
 * are timed using appropriate hardware timestamp counters
 * and recorded in the eviction_counts array.  In particular,
 * only record evictions to the set that incurred the maximum
 * penalty in terms of its access time.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */

// CPUID? can have multiple 
char spy()
{
    CPUID();
    int i, max_set;
    uint64_t *eviction_set_addr;
    int longest = 0;
    
    int time, start, end;
    // Probe the cache line by line and take measurements
    // CPUID(); // ?
    for (i = 0; i < L1_NUM_SETS; i++) {
      
        eviction_set_addr = get_eviction_set_address(spy_array, i, 0);
        // use RDTSC() to time the cache accesses. We want to keep track of which set (aka which i value) took the longest time.
        CPUID();
        RDTSC(start);
	//CPUID();
        // traverse the linked list
        while (*eviction_set_addr != 0){
            eviction_set_addr = *eviction_set_addr;
	    // CPUID();
        }
        CPUID();
        RDTSC(end);
	// CPUID();
        // the time taken to traverse the linked list is end - start.
        time = end - start; 
        // if this time is unusually long, we know that there was a cache miss. Therefore, this is the set that is being communicated by the trojan.
        if (time > longest){
            max_set = i;  
            longest = time;
        }
   
    }
    // CPUID somewhere around here
    // increment the eviction_counts array with the set that is being communicated by the trojan.
    // CPUID();
    eviction_counts[max_set]++;
    CPUID();
    // CPUID();
    // return value does not matter.
    // return 'a';
    // CPUID();
}

int main()
{
    FILE *in, *out;
    in = fopen("transmitted-secret.txt", "r");
    out = fopen("received-secret.txt", "w");

    int j, k;
    int max_count, max_set;

    // TODO: CONFIGURE THIS -- currently, 32*assoc to force eviction out of L2
//     setup(trojan_array, ASSOCIATIVITY*32);
    setup(trojan_array, ASSOCIATIVITY*32);

    setup(spy_array, ASSOCIATIVITY);
    
    for (;;) {
        char msg = fgetc(in);
        if (msg == EOF) {
            break;
        }
        // we do this for SAMPLES iterations because we want to make sure we dont consider conflict misses due to other reasons not related to the attack
        for (k = 0; k < SAMPLES; k++) {
          trojan(msg);
          spy();
        }
        for (j = 0; j < L1_NUM_SETS; j++) {
            if (eviction_counts[j] > max_count) {
                max_count = eviction_counts[j];
                max_set = j;
            }
            eviction_counts[j] = 0;
        }
        if (max_set >= 33 && max_set <= 59) {
            max_set += 32;
        } else if (max_set == 63) {
            max_set = -22;
        }
        // adds the char to the output
        fprintf(out, "%c", 32 + max_set);
        max_count = max_set = 0;
    }
    fclose(in);
    fclose(out);
}
