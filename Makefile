module_stomping:
	x86_64-w64-mingw32-gcc -c src/ModuleStomping/module_stomping.c -o module_stomping.o

UACBypass:
	x86_64-w64-mingw32-gcc -c src/ComExploit/UACBypassCMSTPLUA.c -o ./dst/UACBypassCMSTPLUA.x64.o
