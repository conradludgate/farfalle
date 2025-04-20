# Farfalle construction for building deck functions

Farfalle is a construction for building deck functions based on simple permutations.

Deck functions are a formulation of an keyed extendable output function (XOF), where getting the extendable output
does not necessitate the resetting of the original deck state, allowing it to still be updated.

Session-supporting authenticated encryption (SAE) is a mode of _incremental_ authenticated encryption. It allows
a continous stream of messages to be encrypted and authenticated. The each additional authentication tag
also authenticates all prior received messages.

Deck-SANE is a SAE construction based on deck functions.

## References

* Xoodoo cookbook <https://eprint.iacr.org/2018/767>
* Farfalle: parallel permutation-based cryptography <https://tosc.iacr.org/index.php/ToSC/article/view/855>
