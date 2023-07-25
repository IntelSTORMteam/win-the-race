#define _GNU_SOURCE
#include <stdio.h> // fprintf, stderr
#include <stdint.h> // uint32_t
#include <ctype.h> // isprint
#include <unistd.h> // optarg, optopt
#include <stdlib.h> // strtol, abort, strtoul
#include <assert.h> // assert
#include <sched.h> // cpu_set_t

int main(int argc, char *argv[]) {
	int cpu = 0;
	cpu_set_t cpus;
	CPU_ZERO(&cpus);
	uint32_t workload_type = 0;

	/*
	 Command line options:

	 -c N: run on CPU N (affinity).
	 -w N: specify workload type. see the switch statement below.
	 */

	char c;
	while ((c = getopt (argc, argv, "c:w:")) != -1)
		switch (c) {
			case 'c':
				cpu = strtol (optarg, NULL, 0);
				break;
			case 'w':
				workload_type = strtoul (optarg, NULL, 0);
				break;
			case '?':
				if (optopt == 'c' || optopt == 'j')
					fprintf (stderr, "-%c requires an argument.\n", optopt);
				else if (isprint (optopt))
					fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
					fprintf (stderr, "Unknown option `\\x%x'.\n", optopt);
				return 1;
			default:
				abort();
		}

	printf("SMT workload running on CPU %i\n", cpu);
	CPU_SET(cpu, &cpus);
	int ret = sched_setaffinity(0, sizeof(cpus), &cpus);
	assert(ret == 0);

	switch (workload_type) {
		case 0:
			printf("Loop of direct JMPs.\n");
			__asm__ __volatile__ (
				".align 64\n"
				"1:\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				".byte 0xeb, 0x02\n"
				"nop;nop\n"
				"jmp 1b\n"
				:::);
			break;
		case 1:
			printf("Loop of taken conditional JMPs.\n");
			__asm__ __volatile__ (
				"xor %%ecx, %%ecx\n"
				".align 64\n"
				"2:\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				"jmp 2b\n"
				:::);
			break;
		case 2:
			printf("Loop of taken/not-taken conditional JMPs.\n");
			__asm__ __volatile__ (
				"xor %%ecx, %%ecx\n"
				".align 64\n"
				"3:\n"
				"not %%ecx\n"
				"test %%ecx, %%ecx\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				".byte 0x74, 0x02\n"
				"nop;nop\n"
				".byte 0x75, 0x02\n"
				"nop;nop\n"
				"jmp 3b\n"
				:::);
			break;

		case 3:
			printf("Loop of XORs.\n");
			__asm__ __volatile__ (
				".align 64\n"
				"4:\n"
				"xor $0x11111111, %%eax\n"
				"xor $0x22222222, %%ebx\n"
				"xor $0x33333333, %%ecx\n"
				"xor $0x44444444, %%edx\n"
				"xor $0x55555555, %%eax\n"
				"xor $0x66666666, %%ebx\n"
				"xor $0x77777777, %%ecx\n"
				"xor $0x88888888, %%edx\n"
				"xor $0x99999999, %%eax\n"
				"xor $0xaaaaaaaa, %%ebx\n"
				"jmp 4b\n"
				:::"rax", "rbx", "rcx", "rdx");
			break;
		case 4:
			printf("Loop of SUBs.\n");
			__asm__ __volatile__ (
				".align 64\n"
				"5:\n"
				"sub $0x11111111, %%eax\n"
				"sub $0x22222222, %%ebx\n"
				"sub $0x33333333, %%ecx\n"
				"sub $0x44444444, %%edx\n"
				"sub $0x55555555, %%eax\n"
				"sub $0x66666666, %%ebx\n"
				"sub $0x77777777, %%ecx\n"
				"sub $0x88888888, %%edx\n"
				"sub $0x99999999, %%eax\n"
				"sub $0xaaaaaaaa, %%ebx\n"
				"jmp 5b\n"
				:::"rax", "rbx", "rcx", "rdx");
			break;
		case 5:
			printf("Loop of indirect JMPs (varying targets).\n");
			__asm__ __volatile__ (
				"lea (%%rip), %%rcx\n"
				"addq $0x32, %%rcx\n"
				"mov %%rcx, %%rbx\n"
				"addq $32, %%rbx\n"
				"mov %%rbx, %%rdx\n"
				"addq $32, %%rdx\n"
				"mov %%rdx, %%rsi\n"
				"addq $32, %%rsi\n"
				"mov %%rsi, %%rdi\n"
				"addq $32, %%rdi\n"
				".align 32\n"
				".rept 22\n"
				"nop\n"
				".endr\n"
				"inc %%eax\n"
				"andl $0xf, %%eax\n"
				"xorq %%rax, %%rbx\n"
				"jmp *%%rbx\n"
				".rept 27\n"
				"nop\n"
				".endr\n"
				"xorq %%rax, %%rdx\n"
				"jmp *%%rdx\n"
				".rept 27\n"
				"nop\n"
				".endr\n"
				"xorq %%rax, %%rsi\n"
				"jmp *%%rsi\n"
				".rept 27\n"
				"nop\n"
				".endr\n"
				"xorq %%rax, %%rdi\n"
				"jmp *%%rdi\n"
				".rept 27\n"
				"nop\n"
				".endr\n"
				"xorq %%rax, %%rcx\n"
				"jmp *%%rcx\n"
				:::"rax", "rbx", "rcx", "rdx", "rsi", "rdi");
			break;
		case 6:
			printf("Loop of indirect JMPs (same target).\n");
			__asm__ __volatile__ (
				".align 64\n"
				"lea (%%rip), %%rcx\n"
				"add $0x10, %%rcx\n"
				".rept 12\n"
				"nop\n"
				".endr\n"
				"jmp *%%rcx\n"
				:::"rcx");
			break;
		case 7:
			printf("Loop of indirect far JMPs.\n");
			__asm__ __volatile__ (
				".align 64\n"
				"lea far_tgt(%%rip), %%rcx\n"
				"mov %%cs, %%eax\n"
				"pushw %%ax\n"
				"sub $4, %%rsp\n"
				"movl %%ecx, (%%rsp)\n"
				"far_tgt:\n"
				"ljmp *(%%rsp)\n"
				:::"rax", "rcx");
			break;

		default:
			printf("Invalid workload type!\n");
			return -1;
	}

	return 0;
}

