/*************************************************************
**         Europäisches Institut für Systemsicherheit        *
**         Praktikum "Kryptoanalyse"                         *
**                                                           *
**   Versuch 3: Meet-in-the-middle                           *
**                                                           *
**************************************************************
**
** ssc.h: Interface zur Schnellen-Spiel-Chiffre
**/

struct block {
  ULONG left, right;
};

typedef struct block block, *blkptr;

/* Die im folgenden deklarierten Funktionen verschluesseln/entschluesseln
 * die Eingabe, auf die "in" zeigt, mit dem Schluessel key
 * (im Versuch gilt 0<=key<2^26).
 * Das Ergebnis wird in den Block, auf den der Zeiger "out" zeigt,
 * geschrieben. "in" und "out" duerfen auch auf die selbe Speicherstelle
 * zeigen
 */

extern void ssc_encrypt (ULONG key, blkptr in, blkptr out);
extern void ssc_decrypt (ULONG key, blkptr in, blkptr out);
