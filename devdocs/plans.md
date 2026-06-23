# plans - overall design of project, subject to change
## Simple slim python tui/cli tool for linux/windows that allows you to view exception/unwind info in a PE64 with rich detail.

Things like UWOP* "Unwind operations" need to be easily viewable and sortable through all the collected information about the x64 C++ EH in the input binary. Samples exist in samples as {sha1_hash}.bin but are all going to be well formed compiler emitted PE64s. 

Chaining needs to be properly supported, anything that does not conform to the spec should raise/throw and anything that has suspicious traits like section changes and ANY odd patterns in the exception directory needs to be warned about loudly.

Development should be iterative with tests and commmits occurring as frequently as necessary, though it shouldn't be too hard as the spec is thoroughly documented. 

Dependencies such as lief and etc are heavy and unnecessary here, we really should be able to just quickly retrieve the PE/nt headers and exception directory (if one is to exist) through simple reading from the mapped image virtually (or off disk if its easier) and immediately raise if the input binary is malformed.

Samples are in samples/
Our first is:
b325e5a8da4f8bea2db9fc118f6a6f237731d734.bin # PE64, no idea how many unwind entries but should suffice for testing. 

# references:
https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64
https://learn.microsoft.com/en-us/cpp/build/x64-unwind-information-v3 # Note, this does not presently exist but the spec exists and having potential future support would be extra credit.