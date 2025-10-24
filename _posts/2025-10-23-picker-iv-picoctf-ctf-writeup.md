---
title: "Picker IV (picoCTF)—CTF Writeup"
date: 2025-10-23 15:11
layout: post
categories: 
- CTF 
- Writeup
tags: 
- binary-exploitation 
- ctf 
- writeup
---


# Table of Contents

1.  [Description and Hints](#orgb73f26a)
2.  [Assets](#orge368fed)
    1.  [`picker-IV.c`](#org7fce816)
    2.  [`picker-IV`](#orge043842)
3.  [Input `win`'s address to get the flag](#org4ae31a4)
4.  [Takeaways](#org8ed88ae)
5.  [Risks and Mitigations](#org2afec56)


<a id="orgb73f26a"></a>

# Description and Hints

In the [challenge's page](https://play.picoctf.org/practice/challenge/403) we are greeted with the following question:

> Can you figure out how this program works to get the flag?

and given the following hints:

> 1.  With Python, there are no binaries. With compiled languages like C, there is source code, and there are binaries. Binaries are created from source code, they are a conversion from the human-readable source code, to the highly efficient machine language, in this case: x86\_64.
> 2.  How can you find the address that `win` is at?


<a id="orge368fed"></a>

# Assets

We are given the following assets:

1.  The binary `picker-IV` and
2.  Its source code `picker-IV.c`.


<a id="org7fce816"></a>

## `picker-IV.c`

This is the source code that was provided.

{% highlight c %}
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void print_segf_message(){
  printf("Segfault triggered! Exiting.\n");
  sleep(15);
  exit(SIGSEGV);
}

int win() {
  FILE *fptr;
  char c;

  printf("You won!\n");
  // Open file
  fptr = fopen("flag.txt", "r");
  if (fptr == NULL)
  {
      printf("Cannot open file.\n");
      exit(0);
  }

  // Read contents from file
  c = fgetc(fptr);
  while (c != EOF)
  {
      printf ("%c", c);
      c = fgetc(fptr);
  }

  printf("\n");
  fclose(fptr);
}

int main() {
  signal(SIGSEGV, print_segf_message);
  setvbuf(stdout, NULL, _IONBF, 0); // _IONBF = Unbuffered

  unsigned int val;
  printf("Enter the address in hex to jump to, excluding '0x': ");
  scanf("%x", &val);
  printf("You input 0x%x\n", val);

  void (*foo)(void) = (void (*)())val;
  foo();
}
{% endhighlight %}

After a quick inspection of the code, we have:

1.  Our objective is to get the flag;
2.  There's a function, `win`, that prints the contents of a file called `flag.txt`;
3.  Apparently, in `main` we can give any address for the program, and it will go there and execute the code.

Well, a reasonable approach would be to give `win`'s address in `main`, so the program jumps there and prints the flag for us.

Now, how can we get `win`'s address?
One way to do that is by using the program `readelf`.
From the `man` page:

> `readelf` displays information about one or more ELF format object files.

From [Wikipedia](https://en.wikipedia.org/wiki/Executable_and_Linkable_Format):

> In computing, the Executable and Linkable Format (ELF [&#x2026;]) is a common standard file format for executable files, object code, shared libraries, device drivers, and core dumps.

ELF files are *programs*: a chunk of bytes that we can run on the computer, and `readelf` gives us info about those ELFs.
In the next section we analyze the chunk we got here.


<a id="orge043842"></a>

## `picker-IV`

We got the binary `picker-IV`.
First, we run `file` on it.
It is a good rule to always run `file` on an asset as the first step (unless it is obviously a text file, but, even then, make a mental note, and come back to it if suspicious).
Let's do that on `picker-IV`.

{% highlight shell %}
file picker-IV
{% endhighlight %}

    picker-IV: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=12b33c5ff389187551aae5774324da558cee006c, for GNU/Linux 3.2.0, not stripped

The relevant info for us is:

-   `ELF 64-bit LSB executable`
    -   It is indeed a **program** (the *executable* part gave that away);
-   `not stripped`
    -   This means that we can see the *names* of the functions inside binary; we'll need that to get `win`'s address.

Let's call `readelf` to get `win`'s address.

{% highlight shell %}
readelf --symbols picker-IV | grep win
{% endhighlight %}

{% highlight shell %}
63: 000000000040129e   150 FUNC    GLOBAL DEFAULT   15 win
{% endhighlight %}

The address of `win` is `40129e`.

​**Note:** If we run the command without the `grep` part, we can see the headers of the symbol table.
*Value* is the value of the memory address, and *Name* the name of the symbol; in our case the `FUNC~tion ~win`.
Below we can see a stripped output with just the header and `win`'s line.

{% highlight shell %}
readelf --symbols picker-IV
{% endhighlight %}

    Num:    Value          Size Type    Bind   Vis      Ndx Name
     63: 000000000040129e   150 FUNC    GLOBAL DEFAULT   15 win 


<a id="org4ae31a4"></a>

# Input `win`'s address to get the flag

We then run the `netcat` (`nc`) command to connect to `picker-IV` running on picoCTF's server and input the address.

    Enter the address in hex to jump to, excluding '0x': 40129e
    You input 0x40129e
    You won!
    picoCTF{n3v3r_jump_t0_u53r_5uppl13d_4ddr35535}

​**Note:** `readelf` does not output the address with `0x` (which indicates the number is in hexadecimal).
On the other hand, `gdb` does.
To check that we run.

{% highlight shell %}
gdb picker-IV
{% endhighlight %}

And get:

{% highlight shell %}
GNU gdb (Debian 13.1-3) 13.1
Copyright (C) 2023 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from picker-IV...
(No debugging symbols found in picker-IV)
(gdb) 
{% endhighlight %}

Then we type:

{% highlight shell %}
(gdb) info functions win 
{% endhighlight %}

And get:

{% highlight shell %}
All functions matching regular expression "win":

Non-debugging symbols:
0x000000000040129e  win
{% endhighlight %}

There's the same address, but with the prefix `0x`.

​**Note:** The fact that a program is not *stripped* also means that debugging it with `gdb` is much easier, because it preserves a lot of information from the source code.
This also makes it much easier *reverse engineering* that binary.


<a id="org8ed88ae"></a>

# Takeaways

1.  Programs walk through memory addresses, that contain their instructions.
    It always keep a pointer to the memory address of the next instruction it will execute.
    If we have a way to change that pointer, we control the program's execution.
2.  It is possible to obtain the address of a given function on a program that is *not stripped*.
    We may use `readelf` or `gdb` for that.


<a id="org2afec56"></a>

# Risks and Mitigations

As `n3v3r_jump_t0_u53r_5uppl13d_4ddr35535` suggests, allowing the user to supply jump addresses may not be a good idea.
In this case we were able to access the most important *secret* of the challenge: the flag.
In real scenarios, this poses a severe security threat: a malicious user may control the program execution in harmful ways.

Mitigations:

1.  Never jump to user supplied addresses; instead, provide a list of secure functionalities (e.g., menus, buttons);
2.  Apply *symbol hardening* techniques when compiling (example below).

Here is a more secure compile command (courtesy of ChatGPT) for our program, that removes the symbol names, and also changes the addresses of the functions (including `win`), besides other protection techniques (complete list below).

{% highlight shell %}
gcc -O2 -fPIE -pie -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now -s -o picker-IV picker-IV.c
{% endhighlight %}

The complete list of techniques applied on this compile command are:

-   PIE (Position-Independent Executable): when enabled, the loader can place the executable at a randomized base each run. This makes absolute addresses (like 0x40129e) unpredictable across runs.

-   ASLR (Address Space Layout Randomization): OS feature that randomizes where libraries/executable/stack/mmap land — raises the cost for attacker to guess addresses.

-   RELRO / BIND\_NOW: linker options to harden dynamic symbol resolution, making GOT overwrites harder.

-   NX / DEP: prevents executing code in data sections like stack; doesn’t stop jumping to existing code in the text segment.

-   Stack canaries / FORTIFY / -fstack-protector: detect common overflow attacks.

-   Stripping: removing symbol table and debug symbols (e.g. strip) so readelf won’t show function names/addresses.
