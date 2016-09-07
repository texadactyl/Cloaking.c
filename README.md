OVERVIEW

This git project provides a "File Cloaking Utility" that provides password-based privacy of a single file or file system archive file.  The utility is probably most useful in the following situations:

* Storing backups of sensitive information on the Internet
* Transporting sensitive information electronically (E.g. email) or manually (E.g. using a flash drive)

This project is already proven running on an Intel/AMD environment (Biostar Celeron CPU motherboard) and a Raspberry Pi 2 (ARM 32-bit processor).

LICENSING

This is *NOT* commercial software; instead, usage is covered by the GNU General Public License version 3 (2007).  In a nutshell, please feel free to use the project and share it as you will but please don't sell it.  Thanks!

See the license.txt and gplv3.txt files for the GNU licensing information.

GETTING STARTED

Subfolders:

* src - C-language source code and a Makefile
* bin - Upon completion of the `make` utility, this folder holds the `cloak` and `uncloak` executables.
* docs - project documentation (admittedly, skimpy)
* data - project example data files

The starting point with this project is in the docs/operations.txt file.  Also, this note contains for cloaking the sample cleartext data and uncloaking the ciphertext.

Feel free to contact richard.elkins@gmail.com for inquiries and issues, especially if you find any bugs.  I'll respond as soon as I can.

Richard Elkins
Dallas, Texas, USA, 3rd Rock, Sol
