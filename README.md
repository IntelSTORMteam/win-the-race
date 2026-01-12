# Supporting code for the paper "You Cannot Always Win the Race: Analyzing mitigations for branch target prediction attacks"

This repository contains two pieces of code to accompany [our paper](https://www.computer.org/csdl/proceedings-article/eurosp/2023/651200a671/1OFthHJ5g2Y). Feel free to reach out to us with any questions.

* `spec\_demo.c`: The code corresponding to one of the experiments in our paper. This example demonstrates that the speculation window of LFENCE/JMP can be sufficient for two dependent loads to execute, transmitting a secret using a cache-based covert channel (flush+reload). The code can also be compiled without LFENCE, to observe the non-mitigated behavior. By adding NOPs in front of the gadget, the code can also be used to measure the "size" of the speculation window, as described in the paper. You can tune the experiment using the #define statements at the top of the file.
* `smt\_workload.c`: A set of SMT workloads which can be executed on a sibling thread together with the code above, to demonstrate the effect of these SMT workloads on the speculation window. (Note that these workloads may not be optimal; see the paper for more discussion.) Please refer to the source code for the command line options.

Run it like this (in this case, threads 0/4 are siblings):

```sh
    $ make
    $ ./smt_workload -w 0 -c 4 &
    $ ./spec_demo_lfence -c 0 -n 1000
```


You'll want to terminate the workload process when you're done (e.g., run 'fg' and type ctrl+c).

You may first need to enable some huge pages; if you get an mmap error, try this:

```sh
    $ echo 16 | sudo tee /proc/sys/vm/nr_hugepages
```


# License

Copyright 2023 Intel Corporation.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
