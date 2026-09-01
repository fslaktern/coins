# coins

An x86-64 binary that reads a ROP chain from stdin and only accepts chains made exclusively from a specific set of gadgets.

The flag is reached by computing a relative jump to a `win` function is copied to a random offset within a 1 MiB memory region.
