DwarrowdELF
===========

This repo holds the task files and solution scripts for two tasks from PwnThyBytes CTF 2019:  
* DwarrowdELF - Exploration (Coding/Forensics)  
	A group of Erebor dwarves set out to reconquer their ancestral home of DwarrowdELF, aided by the mythical Cap stone of the Fourth Age.
	Follow their quest at 137.117.216.128:13371

	Note: This task is a prerequisite for "DwarrowdELF: Conquest" from the Pwn category.

* DwarrowdELF - Conquest (Memory Corruption)  

	You have proven yourselves and established your seat in the Chamber of Mazarbul. Armed with the forbidden knowledge uncovered within
	you endeavour to master all the tides of the world.

	Note: This is the second part of "DwarrowdELF: Exploration".


Setup
=====

The binary and libraries were available only if you solved the first part (DwarrowdELF - Exploration).
The first part had as its resources only the remote service and [bin/gotplt.txt](gotplt.txt) .

To solve it as it was intended, you have to set up a docker using the provided Dockerfile and solve the first part by interacting with the service:
```console
sudo docker build -t ptb_dwarrowdelf:v1 .
sudo docker run  -p 127.0.0.1:13371:13371 --rm  -it ptb_dwarrowdelf:v1
```

For the second part, you may use the [bin/dwarrowdelf](binary) and libraries.
