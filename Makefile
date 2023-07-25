all: spec_demo spec_demo_lfence smt_workload

clean:
	rm -f ./spec_demo
	rm -f ./spec_demo_lfence
	rm -f ./smt_workload

spec_demo: spec_demo.c
	gcc spec_demo.c -o spec_demo -lrt

spec_demo_lfence: spec_demo.c
	gcc spec_demo.c -DLFENCE -o spec_demo_lfence -lrt

smt_workload: smt_workload.c
	gcc smt_workload.c -o smt_workload -lrt -Wl,-Ttext-segment,0x400000
