a) Names + IDs:
Ofek Bengal Shmueli
212052062
Daniel Noor
212201180
Itay Peled
322887332

b) How to compile:
In order to compile the tool, you need to:
1. Copy contents of src into pin/source/tools/SimpleExamples
2. Run the command 'make obj-intel64/project.so'

c) How to run tool:
* To run profiling mode from pin/source/tools/SimpleExamples, use:
../../../pin -t obj-intel64/project.so -prof -- ./bzip2 -k -f input-long.txt
* To run optimization mode from pin/source/tools/SimpleExamples, use:
../../../pin -t obj-intel64/project.so -opt -- ./bzip2 -k -f input-long.txt
(where bzip2 and input-long.txt can be replaced by other files)


d) Format of profiling files:
We saved the profiling info in two files - one relevant to the inline ("call-count.csv") and another one for the reordering ("branch-count.csv").
Their formats are:
* call-count.csv: 
<address of call><number of times this call was executed><target of call>
* branch-counts.csv: 
<start address of BBL><tail address of BBL><address of "taken path" (branch/call target)><address of "non-taken path" (fallthrough)><hotter_next>
[hotter_next = 0 if taken path is more likely to be taken, 1 otherwise]

e) How we perform code reordering:
In the profiling phase, we gather info on each BBL in the trace and save it in "branch-count.csv". From that info we know the start, end, taken path and non-taken path of the block, and we also know which path was taken more often. 
In the optimization phase, We put all instructions in a vector. For each BBl which ends in a conditional branch, we check whether its taken path was more popular than the non-taken path. In that case, we want to reorder these two paths/blocks since the non-taken block is "cold" code. If certain constraints are satisfied (the blocks in the taken/non-taken path do not end with ret or call instructions), we swap the two blocks, and revert the conditional branch at the original block's tail. We also add non-conditional jmp instructions after the original block and the taken/non-taken paths, since we need to ensure they will continue to their fallthrough instructions after changing the program's code order.

f) How we gather "hot" calls:
In "call-count.csv", we wrote the number of times each call in the program was executed. If there were multiple calls to the same routine, we only saved the most popular one amongst them in the file. 
In the optimization phase, we first took all calls which were executed at least a 100 times (we chose this threshold after examining the call counts of different files). Then, we filtered these calls and left out any calls to routines which will be problematic to inline (for example, the routine accesses rbp+<positive offset>). After that we were left with a handful of "hot" calls, from which we take the 10 hottest ones.