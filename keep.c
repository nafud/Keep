/* keep.c : the launcher of Keep on the tool medium.
 *
 *   sudo /media/tools/keep [-n]
 *
 * It starts keep-menu.sh, which lies beside it, in the shell of the medium: it finds its own
 * directory and runs  DIR/bin/bash -p DIR/keep-menu.sh  with the arguments it was given. That
 * is the start which the scripts of the medium demand, as one word. The shell of the examined
 * system takes no part in it, and -p keeps the environment of the root shell out of the script
 * (BASH_ENV, functions, SHELLOPTS).
 *
 * The program is linked statically, so that it runs on the examined system without its
 * libraries. Its own directory is the directory of /proc/self/exe, or, where /proc is not
 * mounted, of the path it was called by. Exit status: that of keep-menu.sh, or 1 with a
 * message when the shell or the script is not beside it.
 *
 *   gcc -static -O2 -Wall -o keep keep.c
 */
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define VERSION "1.0"

static int fail(const char *what, const char *path)
{
    fprintf(stderr, "keep %s: %s%s%s\n", VERSION, what, path ? ": " : "", path ? path : "");
    return 1;
}

int main(int argc, char **argv)
{
    static char dir[PATH_MAX], shell[PATH_MAX + 16], menu[PATH_MAX + 16];
    char **av, *slash;
    ssize_t n;
    int i;

    n = readlink("/proc/self/exe", dir, sizeof dir - 1);
    if (n > 0 && (size_t)n < sizeof dir - 1) {
        dir[n] = 0;
    } else if (argc > 0 && strchr(argv[0], '/') && realpath(argv[0], dir)) {
        ;
    } else {
        return fail("cannot find the directory of this program, start it by its full path", NULL);
    }
    slash = strrchr(dir, '/');
    if (!slash)
        return fail("cannot find the directory of this program", dir);
    *slash = 0;

    snprintf(shell, sizeof shell, "%s/bin/bash", dir);
    snprintf(menu, sizeof menu, "%s/keep-menu.sh", dir);
    if (access(shell, X_OK) != 0)
        return fail("the shell of the medium is not beside this program", shell);
    if (access(menu, R_OK) != 0)
        return fail("keep-menu.sh is not beside this program", menu);

    av = calloc((size_t)argc + 3, sizeof *av);
    if (!av)
        return fail("out of memory", NULL);
    av[0] = shell;
    av[1] = "-p";
    av[2] = menu;
    for (i = 1; i < argc; i++)
        av[i + 2] = argv[i];
    execv(shell, av);
    perror(shell);
    return 1;
}
