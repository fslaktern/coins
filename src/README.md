# coins

An x86-64 binary that reads a ROP chain from stdin and only accepts chains made exclusively from a specific set of gadgets.

The flag is printed by jumping to a `win` function placed somewhere in a 1 MiB memory buffer. Requires chaining a valid set of several different gadgets to perform a relative jump to the correct address. Allowed gadgets are: <https://github.com/fslaktern/coins/blob/main/src/coins.asm#L460-L588>. `adc` is used instead of `add` to cause an off-by-one in the jump length calculation.
