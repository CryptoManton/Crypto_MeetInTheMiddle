/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 3: Meet-in-the-middle                           *
**                                                           *
**************************************************************
**
** attack.c: Implementierung der Meet-in-the-middle-Attacke
**/
/* An Stellen, wo XXX steht, muss etwas eingesetzt werden! */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#define bzero(m,s) memset((m),0,(s))

#include "praktikum.h"
#include "ssc.h"

#define KEY_BITS 26// 30 /* Groesse der Teilschluessels */
#define KEY_MAX (1<<KEY_BITS)
  /* Wieviele Moeglichkeiten gibt es fuer einen Teilschluessel */

#define HASH_BITS 34 // XXX /* Wieviele Bits die Hashfunktion umfassen soll */
/* Waehlen Sie eine Zahl, die nicht zu viel Speicheraufwand
 * bringt, andererseits die Liste der Loesungskandidaten (Schritt 2)
 * genuegend klein haelt */

/* ACHTUNG: Dies hat noch nichts mit der Anzahl der Eintraege im Bitarray
 * zu tun, da evtl. dieses in mehreren Teilen berechnet/verarbeitet
 * werden sollte.
 */

#define LOGNITERATIONS 0
/* Der Wertebereich der Hashfunktion wird in 2^LOGNITERATIONS
 * Teile zerlegt. Hier ist auch der Wert 0 moeglich. In diesem Fall
 * Wird das ganze Bitarray auf einmal berechnet (Schritt 1) und
 * verwendet (Schritt 2).
 */

#define NITERATIONS (1<<LOGNITERATIONS)
#define HASHTABLE_ELEM (1<<(HASH_BITS-LOGNITERATIONS-5)) //2^29
  /* Anzahl der *int*'s, die fuer das Bitarray alloziert werden
   * muessen. Da 32 bits in einem Int enthalten sind, also
   * 2^(... -5)
   *        ^^
   */

#define NESTIMATED_COLLISIONS pow(2, (2*KEY_BITS - HASH_BITS))  // 52-34 = 18  => 2^18
  /* Erwartungswert fuer die Anzahlen der Kollisionen (Eintraege
   * in die Liste, die im Schritt 2 insgesamt anfallen)
   */

#define COLLTABLE_ELEM 1.5f * NESTIMATED_COLLISIONS
/* Maximale Anzahl der Eintraege in der Kollisionstabelle.
 * sollte um einen Sicherheitsabstand hoeher sein als der
 * Erwartungswert.
 */


/* Einige Hilfsmakros */
#define SET_BIT(a,b,c) ((a)[b]|=(1<<(c)))
/* setzt das c-te Bit in Element b des Arrays a.
 * wenn a ein Array von 32-Bit-Werten ist (wie z.B. hashtable),
 * ist c also zwischen 0 und 31.
 */

#define GET_BIT(a,b,c) (((a)[b]>>(c))&1)
/* holt das c-te Bit in Element b des Arrays a */

#define HASH_ELEM(l,r) (l & 0x3fff) | (r & 0x1fffc000) //XXX  nimmt die 14 oberen Bits von l und die 15 unteren Bits von r 
                                                    // und concatet sie = [0..2^29]
/* Eine Hashfunktion, die ein Element in hashtable indiziert.
 * Der Wert sollte also zwischen 0 und HASHTABLE_ELEM-1 sein.
 * l und r sind die linken bzw. rechten Teilschluessel
 */

#define HASH_BIT(l,r) ((l>>16 & 0x1c) | (r & 0x3))  // XXX   nimm von l Bit 4,3,2 (0x1c) und von r 1,0 (0x3) = 5-Bit [0..31]
/* Eine Hashfunktion, die eine Bitnummer von 0 bis 31 ergibt */

/* Zugriffe auf hashtable sollten also in etwa so erfolgen:
 * SET_BIT(hashtable, HASH_ELEM(l,r), HASH_BIT(l,r))
 */

#define PLAINTEXT_FILENAME "plaintext"
#define CIPHERTEXT_FILENAME "ciphertext"

struct collision {
  block midtext; /* mit r_key entschluesselter Chiffretextblock */
  ULONG r_key;   /* versuchter rechter Teilschluessel */
} *collision_tab;
int ncollisions; /* Anzahl der bisher bekannten "Kollisionen" */

/* Die Funktion enter_collision traegt eine Kollision in die Tabelle ein.
 * k ist der betrachtete rechte Teilschluessel, b der zugehoerige Block
 * (d.h. Chiffrat, (teil)entschluesselt mit k) */

void enter_collision(block b, ULONG k) {
      if (ncollisions >= COLLTABLE_ELEM) {
        printf ("More collisions than 2*expected number of collisions\n");
        printf ("Either something's faulty, or you must increase\n");
        printf ("the define COLLTABLE_ELEM in the program\n");
        exit(1);
      }
      collision_tab[ncollisions].midtext = b;
      collision_tab[ncollisions].r_key = k;
      ncollisions ++;
}

int *hashtable; /* Bitarray, implementiert als Array von int's */

block plaintext; /* hier steht der Klartext */
block ciphertext; /* hier steht der Chiffretext */
/* diese beiden Variablen sollten am besten nie veraendert werden */

/* initialize(): Alloziert den Speicher fuer das Bitarray
 * (hashtable) und die Liste der moeglichen rechten Teilschluessel
 * (Kollisionen)
 */
void initialize (void)
{
  hashtable = calloc (HASHTABLE_ELEM, sizeof (int));
  collision_tab = calloc (COLLTABLE_ELEM, sizeof (struct collision));
  if(!hashtable || !collision_tab) {
	long long memory = HASHTABLE_ELEM * sizeof(int);
	memory += COLLTABLE_ELEM * sizeof(struct collision);
	printf("Failed to allocate memory, need %lld bytes of memory. Exiting.\n", memory);
	exit(1);
  }
}

/* stage_1 (int iteration)
 * Fuehrt den "iteration"-ten Durchlauf des ersten Schrittes des
 * Algorithmus' durch. (iteration laeuft von 0 bis NITERATIONS-1)
 */
void stage_1 (int iteration)
{
  printf("Beginning stage 1...\n");
  bzero (hashtable, HASHTABLE_ELEM*sizeof (int)); /* Loeschen aller Bits */
  /* XXX Aufgabe */
  unsigned long block_size = (KEY_MAX-1) / NITERATIONS;    // iteriere über KEY_MAX-1 linke Teilschlüssel 
  for (unsigned long l_key = block_size * iteration; l_key < block_size * (iteration+1); l_key++) {
    block tmp_cipher;
    ssc_encrypt(l_key, &plaintext, &tmp_cipher);
    //printf("Plain: %lu%lu, Cipher: %lu%lu\n", plaintext.left, plaintext.right, tmp_cipher.left, tmp_cipher.right);
    SET_BIT(hashtable, HASH_ELEM(tmp_cipher.left, tmp_cipher.right), HASH_BIT(tmp_cipher.left, tmp_cipher.right));
  }
}

/* stage_2 (int iteration)
 * Fuehrt den "iteration"-ten Durchlauf des zweiten Schrittes
 * des Algorithmus' durch.
 */
void stage_2 (int iteration)
{
  printf("Beginning stage 2...\n");
  /* XXX Aufgabe */
  unsigned long block_size = (KEY_MAX-1) / NITERATIONS;    // iteriere über KEY_MAX-1 rechte Teilschlüssel
  for (unsigned long r_key = block_size * iteration; r_key < block_size * (iteration+1); r_key++) {
    block tmp_plain;
    ssc_decrypt(r_key, &ciphertext, &tmp_plain);
    if (GET_BIT(hashtable, HASH_ELEM(tmp_plain.left, tmp_plain.right), HASH_BIT(tmp_plain.left, tmp_plain.right))) {
      enter_collision(tmp_plain, r_key);
      //printf("Cipher: %lu%lu, Plain: %lu%lu\n", ciphertext.left, ciphertext.right, tmp_plain.left, tmp_plain.right);
    }
  }
  printf("End of stage 2.\n");
}

int coll_compare (const void *left, const void *right)
{
  const struct collision *l = (const struct collision *)left,
                   *r = (const struct collision *)right;
  if (l->midtext.left < r->midtext.left) return -1;
  if (l->midtext.left > r->midtext.left) return 1;
  if (l->midtext.right < r->midtext.right) return -1;
  if (l->midtext.right > r->midtext.right) return 1;
  return 0;
}

/* stage_3()
 * Sortiert die Liste der Kollisionen */
void stage_3 (void)
{
  printf("Beginning stage 3...\n");
  qsort (collision_tab, ncollisions, sizeof (struct collision), coll_compare);
  printf("End of stage 3.\n");
}

static struct collision tmp_collision; /* Hilfsvariable fuer das folgende
                                        * Makro */
/* search_collision(b)
 * Sucht in der Liste der Kollisionen (in Schritt 2 erstellt) den
 * Block b.
 * Gibt entweder den Null-Pointer zurueck, wenn nichts gefunden wurde,
 * oder einen Zeiger auf das entsprechende Element der Liste
 * (struct collision *), das den Block und den zugehoerigen
 * rechten Teilschluessel enthaelt.
 */
#define search_collision(b) (tmp_collision.midtext=b,\
    (struct collision *) bsearch (&tmp_collision, collision_tab, \
                                  ncollisions, sizeof (struct collision), \
                                  coll_compare))

/* stage_4 ():
 * Finden der Loesungen.
 */
void stage_4 (void)
{
  printf("Beginning stage 4...\n");
  unsigned long real_l_key = 0;
  unsigned long real_r_key = 0;
  /* XXX Aufgabe */
  for (unsigned long l_key = 0; l_key < KEY_MAX-1; l_key++) {
    block tmp_cipher;
    ssc_encrypt(l_key, &plaintext, &tmp_cipher);
    struct collision tmp_collision;
    if (search_collision(tmp_cipher)) {
      tmp_collision.r_key = search_collision(tmp_cipher)->r_key;
      printf("Schlüssel gefunden.\n");
      real_l_key = l_key;
      real_r_key = tmp_collision.r_key;
      printf("Left Key: %lu, Right Key: %lu.\n", real_l_key, real_r_key);
      printf("Plaintext: %lu %lu, Cipher: %lu %lu \n", plaintext.left, plaintext.right, ciphertext.left, ciphertext.right);
      ssc_encrypt(real_l_key, &plaintext, &tmp_cipher);
      ssc_encrypt(real_r_key, &tmp_cipher, &tmp_cipher);
      printf("New Cipher: %lu %lu\n", tmp_cipher.left, tmp_cipher.right);
    }
  }
  printf("End of stage 4.\n");
}

int main (void)
{
  FILE *tmp;
  int i;

  /* Einlesen des Klartextes */
  tmp = fopen (PLAINTEXT_FILENAME, "r");
  if (! tmp) {
    perror ("Error opening " PLAINTEXT_FILENAME);
    exit (2);
  }
  fscanf (tmp, "%08x%08x", &(plaintext.left), &(plaintext.right));
  fclose (tmp);
  /* ... und des Chiffrats */
  tmp = fopen (CIPHERTEXT_FILENAME, "r");
  if (! tmp) {
    perror ("Error opening " CIPHERTEXT_FILENAME);
    exit (2);
  }
  fscanf (tmp, "%08x%08x", &(ciphertext.left), &(ciphertext.right));
  fclose (tmp);

  printf ("Initializing ..."); fflush (stdout);
  initialize (); /* Speicher allozieren */
  printf (" done\n");

  /* NITERATIONS mal Schritt 1 und 2 ... */
  for (i = 0; i < NITERATIONS; i++) {
    printf ("Iteration %d stage 1: ", i); fflush (stdout);
    stage_1 (i); /* i-ter Durchlauf von Schritt 1 */
    printf (" done\nIteration %d stage 2: ", i); fflush (stdout);
    stage_2 (i); /* i-ter Durchlauf von Schritt 2 */
    printf (" done\n");
  }
  /* Kontroll-Ausgabe */
  printf ("Found %d collision candidates.\n", ncollisions);
  printf ("stage 3 ..."); fflush (stdout);
  stage_3 (); /* Schritt 3: Kollisions-Liste sortieren */
  printf (" done\nstage 4 ... (printing results)\n"); fflush (stdout);
  stage_4 (); /* Schritt 4 */
  printf ("\nThat's it :-)\n");
  exit (0);
}
