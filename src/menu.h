/*
 * menu.h: the dialogue of Keep (see menu.c).
 */
#ifndef KEEP_MENU_H
#define KEEP_MENU_H

/* Ask for the parameters of one run, list them, and run it. With DRY the run is shown and not
   started. Returns the exit status: that of the run, 0 after a dry run, 1 when the dialogue
   ended without a run. */
int menu_run(int dry);

#endif
