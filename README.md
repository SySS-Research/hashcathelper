hashcathelper
=============

Convience tool for hashcat.

Usage
-----

Run `hashcathelper -h` for help. The program is structured in subcommands.
See `hashcathelper <subcommand> -h` for more information.

### Subcommand "ntlm"

First, it bruteforces all LM hashes and uses the results to crack the
corresponding NT hashes. Then, a large wordlist (recommendation:
[Crackstation](https://crackstation.net/crackstation-wordlist-password-cracking-dictionary.htm))
is used together with a large ruleset (recommendation:
[OneRule](https://notsosecure.com/one-rule-to-rule-them-all/)) to crack all
remaining NT hashes.

The pwdump format is the one which is used by
[secretsdump](https://github.com/SecureAuthCorp/impacket/blob/master/impacket/examples/secretsdump.py)
or Meterpreter's
[hashdump](https://www.offensive-security.com/metasploit-unleashed/meterpreter-basics/)
function.

Example:

```
$ hashcathelper ntlm dc01.ntds
```

### Subcommand "analytics"

Output interesting statistics about the cracked passwords. It is meant to be
used together with the output of the `ntlm` subcommand, but passwords which
were obtained elsewhere can be analyzed as well.

It takes the following files as an input:

* Password hashes in the pwdump format
* Cracked passwords with accounts (output of the `ntlm` subcommand)
* Plain passwords

At least one of those is required. Ideally, you pass the hashes and the
output of the `ntlm` subcommand.

Additionally, you can pass the path to a file containing account names to be
used as a filter. Only the accounts whose names are listed in this file will
be considered. This is useful if you are only interested in statistics
regarding active accounts, for example. Or you want the statistics regarding
all accounts with `admin` in their name. Or statistics regarding
kerberoastable users.

Example:

```
$ hashcathelper analytics -f text \
    -H dc01.ntds \
    -A dc01.ntds.out \
    -F active_accounts.txt
```

### Subcommand "autocrack"

To be done; stay tuned.


Installation
------------

`python3 setup.py install --user`

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
wordlist = /home/cracker/wordlists/crackstation.txt

# Hash speed of the machine
hash_speed = 60000
```

The hash speed characterizes the power of the machine. Unit: MH/s
(Megahashes per second for MD5).

It can be measured with `hashcat -b -m 0`.
