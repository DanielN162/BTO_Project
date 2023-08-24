# BTO_Project
To compile and run in VM:
1. Paste project.cpp to <PIN>/pin/source/tools/SimpleExamples/obj-intel64, along with makefile.
2. In SimpleExamples, run ```make obj-intel64/project.so```.
3. In SimpleExamples, run ```../../../pin -t project.so -[prof|opt] -- <input file path>```.
