In-Memory Execution
===================

Linux makes it possible to generate binaries and execute them without touching
a filesystem.  New system calls introduced in the last couple of years allow
the creation of appropriate memory objects and a method to execute a binary
with just a file handle.

The code is just an example.  It is by no means something that is ready to
use in a meaningful program.  For once, no error checking is done.  Second,
the generate code is fixed and hardcoded.  At some point the code might be
extended to more completely resemble a linker at which point it could be
used in projects.

The code implements a mini-linker.  The code and data is provided in binary
form.  In addition there is a symbol table and a relocation table, referencing it.
This is in principle the information contained in object files.  Using this
information the code automatically relocates the code for the load address which
makes it easier to extend the code example.

Much of the work of creating the output is done by the `libelf` library which
has functions to arrange the information provided in the right form.  The output
is written to a file descriptor which in this case is not really a file,
just the memory image of it but for learning purposes the file could be generated
on disk and inspected.  This will show a well-formed ELF file which is much more than
is practically needed since some of the generated information is never used when
the kernel executes the file.
