hashcathelper
=============

Wrapper for hashcat which helps you crack hashes in the pwdump format.

First, it bruteforces all LM hashes and uses the results to crack the
corresponding NT hashes. Then, a large wordlist (Crackstation) is used
together with a large ruleset (OneRule) to crack all remaining NT hashes.

The pwdump format is the one which is used by secretsdump or Meterpreter's
hashdump function.

Notes
-----

Config file should look like this:

```
[DEFAULT]

# Path to hashcat binary
hashcat_bin = /home/cracker/hashcat/hashcat-latest

# Path to hashcat rule set (OneRule is recommended)
rule = /home/cracker/hashcat/rules/OneRule.rule

# Path to hashcat wordlist (Crackstation is recommended)
wordlist = /home/cracker/00_Wortlisten/crackstation.txt

# Hash speed of the machine
hash_speed = 60000
```

The hash speed characterizes the power of the machine.  Unit: MH/s
(Megahashes per second for MD5).

It can be measured with `hashcat -b -m 0`.


Idea for development: Support other hash formats and choose a suitable
wordlist and ruleset based on how long the attack is supposed to run as
well as the cracking power of the local machine.
