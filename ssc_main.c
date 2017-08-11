/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 3: Meet-in-the-middle                           *
**                                                           *
**************************************************************
**
** ssc_main.c: Ver/Entschlüsselung mit ssc
**/
#include <stdio.h>
#include <stdlib.h>

#include "praktikum.h"
#include "ssc.h"


char *av0;

void usage (void)
{
  fprintf (stderr, "Usage: %s [key [block [e|d]]]\n", av0);
  exit (2);
}

int main (int argc, char **argv)
{
  block a, b;
  ULONG key;
  char c;

  av0 = *argv;
  argc--; argv++;
  if (argc) {
    sscanf (*argv, "%x", &key);
    argc--, argv++;
  } else {
    printf ("Key (hexadecimal input) -> ");
    scanf ("%x", &key);
  }
  if (argc) {
    sscanf (*argv, "%08x%08x", &(a.left), &(a.right));
    argc --; argv ++;
  } else {
    printf ("Block to en/decrypt (16 hex digits) -> ");
    scanf ("%08x%08x", &(a.left), &(a.right));
  }
  if (argc) {
    c = **argv & 0xdf;
    argc --; argv ++;
  } else {
    printf ("(E)ncrypt or (D)ecrypt -> ");
    do {
      c = getchar ();
      c &= 0xdf;
    } while (c != 'E' && c != 'D');
    do {} while (getchar() != '\n');
  }
  if (argc) usage ();
  if (c == 'E') {
    ssc_encrypt (key, &a, &b);
    printf ("E(key = %08x, blk = %08x%08x) = %08x%08x\n",
            key, a.left, a.right, b.left, b.right);
  } else if (c == 'D') {
    ssc_decrypt (key, &a, &b);
    printf ("D(key = %08x, blk = %08x%08x) = %08x%08x\n",
            key, a.left, a.right, b.left, b.right);
  } else usage ();
  exit (0);
}
