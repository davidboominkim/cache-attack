# cache-attack

A simulation of a covert channel attack, specifically PRIME+PROBE, using a trojan and a spy in order to exchange secret messages.
The secret message to be exchanged is "transmitted-secret.txt," which is encoded by the trojan, character by character, by invoking cache misses in certain cache blocks. These cache misses are then repeatedly probed by the spy in order to determine the character that is being sent by the trojan.

To run the covert channel attack, compile and run the processor using "covert.c"

The variable "SAMPLES," which is the number of repeated probes per character, and the associativities of the trojan/spy arrays might differ depending on the cache/processor of the machine the code is compiled on.

Sources: UVA Undergraduate Computer Architecture
