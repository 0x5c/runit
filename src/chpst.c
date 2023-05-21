#include <sys/types.h>
#include <time.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <unistd.h>
#include <grp.h>
#include <stdio.h>
#include "sgetopt.h"
#include "error.h"
#include "errprintf.h"
#include "str.h"
#include "strquote.h"
#include "uidgid.h"
#include "scan.h"
#include "lock.h"
#include "pathexec.h"
#include "stralloc.h"
#include "byte.h"
#include "open.h"
#include "openreadclose.h"
#include "direntry.h"

#define USAGE_MAIN "[-vP012] [-u user[:group]] [-U user[:group]] [-b argv0] [-e dir] [-/ root] [-C pwd] [-n nice] [-l|-L lock] [-m n] [-d n] [-o n] [-p n] [-f n] [-c n] prog"
#define FATAL "chpst: fatal: "
#define WARNING "chpst: warning: "

const char *progname;
static stralloc sa;

void usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_MAIN);
}

char *set_user =0;
char *env_user =0;
const char *argv0 =0;
const char *env_dir =0;
unsigned int verbose =0;
unsigned int pgrp =0;
unsigned int nostdin =0;
unsigned int nostdout =0;
unsigned int nostderr =0;
long limitd =-2;
long limits =-2;
long limitl =-2;
long limita =-2;
long limito =-2;
long limitp =-2;
long limitf =-2;
long limitc =-2;
long limitr =-2;
long limitt =-2;
long nicelvl =0;
const char *lock =0;
const char *root =0;
const char *pwd =0;
unsigned int lockdelay;

void suidgid(char *user, unsigned int ext) {
  struct uidgid ugid;

  if (ext) {
    if (! uidgids_get(&ugid, user)) {
      if (*user == ':') {
        errprintf_die(111, FATAL "invalid uid/gids: %s\n", user + 1);
      }
      if (errno) {
        errprintf_die(111, FATAL "unable to get password/group file entry: %s\n", error_str(errno));
      }
      errprintf_die(111, FATAL "unknown user/group: %s\n", user);
    }
  }
  else
    if (! uidgid_get(&ugid, user)) {
      if (errno) {
        errprintf_die(111, FATAL "unable to get password file entry: %s\n", error_str(errno));
      }
      errprintf_die(111, FATAL "unknown account: %s\n", user);
    }
  if (setgroups(ugid.gids, ugid.gid) == -1) {
    errprintf_die(111, FATAL "unable to setgroups: %s\n", error_str(errno));
  }
  if (setgid(*ugid.gid) == -1) {
    errprintf_die(111, FATAL "unable to setgid: %s\n", error_str(errno));
  }
  if (setuid(ugid.uid) == -1) {
    errprintf_die(111, FATAL "unable to setuid: %s\n", error_str(errno));
  }
}

void euidgid(char *user, unsigned int ext) {
  struct uidgid ugid;
  // "Long enough for a formatted ulong+Null"
  char str_buf[40];

  if (ext) {
    if (! uidgids_get(&ugid, user)) {
      if (*user == ':') {
        errprintf_die(111, FATAL "invalid uid/gids: %s\n", user + 1);
      }
      if (errno) {
        errprintf_die(111, FATAL "unable to get password/group file entry: %s\n",
                      error_str(errno));
      }
      errprintf_die(111, FATAL "unknown user/group: %s\n", user);
    }
  }
  else
    if (! uidgid_get(&ugid, user)) {
      if (errno) {
        errprintf_die(111, FATAL "unable to get password file entry: %s\n",
                      error_str(errno));
      }
      errprintf_die(111, FATAL "unknown account: %s\n", user);
    }

  snprintf(str_buf, 40, "%lu", (unsigned long)*ugid.gid);
  if (! pathexec_env("GID", str_buf)) {
    errprintf_die(111, FATAL "out of memory.\n");
  }

  snprintf(str_buf, 40, "%lu", (unsigned long)ugid.uid);
  if (! pathexec_env("UID", str_buf)) {
    errprintf_die(111, FATAL "out of memory.\n");
  }
}

void edir(const char *dirname) {
  int wdir;
  DIR *dir;
  direntry *d;
  int i;

  if ((wdir =open_read(".")) == -1) {
    errprintf_die(111, FATAL "unable to open current working directory: %s\n",
                  error_str(errno));
  }
  if (chdir(dirname)) {
    errprintf_die(111, FATAL "unable to switch to directory: %s: %s\n", dirname, error_str(errno));
  }
  if (! (dir =opendir("."))) {
    errprintf_die(111, FATAL "unable to open directory: %s: %s\n", dirname, error_str(errno));
  }
  for (;;) {
    errno =0;
    d =readdir(dir);
    if (! d) {
      if (errno) {
        errprintf_die(111, FATAL "unable to read directory: %s: %s\n", dirname, error_str(errno));
      }
      break;
    }
    if (d->d_name[0] == '.') continue;
    if (openreadclose(d->d_name, &sa, 256) == -1) {
      if ((errno == error_isdir) && env_dir) {
        if (verbose)
          errprintf(WARNING "unable to read %s/%s: %s\n",
                       dirname, d->d_name, error_str(errno));
        continue;
      }
      else
        errprintf_die(111, FATAL "unable to read %s/%s: %s\n",
                      dirname, d->d_name, error_str(errno));
    }
    if (sa.len) {
      sa.len =byte_chr(sa.s, sa.len, '\n');
      while (sa.len && (sa.s[sa.len -1] == ' ' || sa.s[sa.len -1] == '\t'))
        --sa.len;
      for (i =0; i < sa.len; ++i) if (! sa.s[i]) sa.s[i] ='\n';
      if (! stralloc_0(&sa)) {
        errprintf_die(111, FATAL "out of memory.\n");
      }
      if (! pathexec_env(d->d_name, sa.s)) {
        errprintf_die(111, FATAL "out of memory.\n");
      }
    }
    else
      if (! pathexec_env(d->d_name, 0)) {
        errprintf_die(111, FATAL "out of memory.\n");
      }
  }
  closedir(dir);
  if (fchdir(wdir) == -1) {
    errprintf_die(111, FATAL "unable to switch to starting directory: %s\n",
                  error_str(errno));
  }
  close(wdir);
}

void slock_die(const char *m, const char *f, unsigned int x) {
  if (! x) {
    errprintf_die(111, FATAL "%s: %s: %s\n", m, f, error_str(errno));
  }
  _exit(0);
}
void slock(const char *f, unsigned int d, unsigned int x) {
  int fd;

  if ((fd =open_append(f)) == -1) slock_die("unable to open lock", f, x);
  if (d) {
    if (lock_ex(fd) == -1) slock_die("unable to lock", f, x);
    return;
  }
  if (lock_exnb(fd) == -1) slock_die("unable to lock", f, x);
}

void limit(int what, long l) {
  struct rlimit r;

  if (getrlimit(what, &r) == -1) {
    errprintf_die(111, FATAL "unable to getrlimit(): %s\n", error_str(errno));
  }
  if ((l < 0) || (l > r.rlim_max))
    r.rlim_cur =r.rlim_max;
  else
    r.rlim_cur =l;
  if (setrlimit(what, &r) == -1) {
    errprintf_die(111, FATAL "unable to setrlimit(): %s\n", error_str(errno));
  }
}
void slimit() {
  if (limitd >= -1) {
#ifdef RLIMIT_DATA
    limit(RLIMIT_DATA, limitd);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_DATA\n");
    }
#endif
  }
  if (limits >= -1) {
#ifdef RLIMIT_STACK
    limit(RLIMIT_STACK, limits);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_STACK\n");
    }
#endif
  }
  if (limitl >= -1) {
#ifdef RLIMIT_MEMLOCK
    limit(RLIMIT_MEMLOCK, limitl);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_MEMLOCK\n");
    }
#endif
  }
  if (limita >= -1) {
#ifdef RLIMIT_VMEM
    limit(RLIMIT_VMEM, limita);
#else
#ifdef RLIMIT_AS
    limit(RLIMIT_AS, limita);
#else
    if (verbose) {
      errprintf(WARNING "system does neither support RLIMIT_VMEM nor RLIMIT_AS\n");
    }
#endif
#endif
  }
  if (limito >= -1) {
#ifdef RLIMIT_NOFILE
    limit(RLIMIT_NOFILE, limito);
#else
#ifdef RLIMIT_OFILE
    limit(RLIMIT_OFILE, limito);
#else
    if (verbose) {
      errprintf(WARNING "system does neither support RLIMIT_NOFILE nor RLIMIT_OFILE\n");
    }
#endif
#endif
  }
  if (limitp >= -1) {
#ifdef RLIMIT_NPROC
    limit(RLIMIT_NPROC, limitp);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_NPROC\n");
    }
#endif
  }
  if (limitf >= -1) {
#ifdef RLIMIT_FSIZE
    limit(RLIMIT_FSIZE, limitf);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_FSIZE\n");
    }
#endif
  }
  if (limitc >= -1) {
#ifdef RLIMIT_CORE
    limit(RLIMIT_CORE, limitc);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_CORE\n");
    }
#endif
  }
  if (limitr >= -1) {
#ifdef RLIMIT_RSS
    limit(RLIMIT_RSS, limitr);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_RSS\n");
    }
#endif
  }
  if (limitt >= -1) {
#ifdef RLIMIT_CPU
    limit(RLIMIT_CPU, limitt);
#else
    if (verbose) {
      errprintf(WARNING "system does not support RLIMIT_CPU\n");
    }
#endif
  }
}

/* argv[0] */
void setuidgid(int, const char *const *);
void envuidgid(int, const char *const *);
void envdir(int, const char *const *);
void pgrphack(int, const char *const *);
void setlock(int, const char *const *);
void softlimit(int, const char *const *);

int main(int argc, const char **argv) {
  int opt;
  int i;
  unsigned long ul;

  progname =argv[0];
  for (i =str_len(progname); i; --i)
    if (progname[i -1] == '/') {
      progname +=i;
      break;
    }
  if (progname[0] == 'd') ++progname;

  /* argv[0] */
  if (str_equal(progname, "setuidgid")) setuidgid(argc, argv);
  if (str_equal(progname, "envuidgid")) envuidgid(argc, argv);
  if (str_equal(progname, "envdir")) envdir(argc, argv);
  if (str_equal(progname, "pgrphack")) pgrphack(argc, argv);
  if (str_equal(progname, "setlock")) setlock(argc, argv);
  if (str_equal(progname, "softlimit")) softlimit(argc, argv);

  while ((opt =getopt(argc, argv, "u:U:b:e:m:d:o:p:f:c:r:t:/:C:n:l:L:vP012V"))
         != opteof)
    switch(opt) {
    case 'u': set_user =(char*)optarg; break;
    case 'U': env_user =(char*)optarg; break;
    case 'b': argv0 =(char*)optarg; break;
    case 'e': env_dir =optarg; break;
    case 'm':
      if (optarg[scan_ulong(optarg, &ul)]) usage();
      limits =limitl =limita =limitd =ul;
      break;
    case 'd': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitd =ul; break;
    case 'o': if (optarg[scan_ulong(optarg, &ul)]) usage(); limito =ul; break;
    case 'p': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitp =ul; break;
    case 'f': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitf =ul; break;
    case 'c': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitc =ul; break;
    case 'r': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitr =ul; break;
    case 't': if (optarg[scan_ulong(optarg, &ul)]) usage(); limitt =ul; break;
    case '/': root =optarg; break;
    case 'C': pwd =optarg; break;
    case 'n':
      switch (*optarg) {
        case '-':
          ++optarg;
          if (optarg[scan_ulong(optarg, &ul)]) usage(); nicelvl =ul;
          nicelvl *=-1;
          break;
        case '+': ++optarg;
        default:
          if (optarg[scan_ulong(optarg, &ul)]) usage(); nicelvl =ul;
          break;
      }
      break;
    case 'l': if (lock) usage(); lock =optarg; lockdelay =1; break;
    case 'L': if (lock) usage(); lock =optarg; lockdelay =0; break;
    case 'v': verbose =1; break;
    case 'P': pgrp =1; break;
    case '0': nostdin =1; break;
    case '1': nostdout =1; break;
    case '2': nostderr =1; break;
    case 'V': errprintf("%s\n", STR(VERSION));
    case '?': usage();
    }
  argv +=optind;
  if (! argv || ! *argv) usage();

  if (pgrp) setsid();
  if (env_dir) edir(env_dir);
  if (root) {
    if (chdir(root) == -1) {
      errprintf_die(111, FATAL "unable to change directory: %s: %s\n", root, error_str(errno));
    }
    if (chroot(".") == -1) {
      errprintf_die(111, FATAL "unable to change root directory: %s\n", error_str(errno));
    }
  }
  if (pwd) {
    if (chdir(pwd) == -1) {
      errprintf_die(111, FATAL "unable to change directory: %s: %s\n", pwd, error_str(errno));
    }
  }
  if (nicelvl) {
    errno =0;
    if (nice(nicelvl) == -1) {
      if (errno) {
        errprintf_die(111, FATAL "unable to set nice level: %s\n", error_str(errno));
      }
    }
  }
  if (env_user) euidgid(env_user, 1);
  if (set_user) suidgid(set_user, 1);
  if (lock) slock(lock, lockdelay, 0);
  if (nostdin) if (close(0) == -1) {
    errprintf_die(111, FATAL "unable to close stdin: %s\n", error_str(errno));
  }
  if (nostdout) if (close(1) == -1) {
    errprintf_die(111, FATAL "unable to close stdout: %s\n", error_str(errno));
  }
  if (nostderr) if (close(2) == -1) {
    errprintf_die(111, FATAL "unable to close stderr: %s\n", error_str(errno));
  }
  slimit();

  progname =*argv;
  if (argv0) *argv =argv0;
  pathexec_env_run(progname, argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
  return(0);
}

/* argv[0] */
#define USAGE_SETUIDGID "account child"
#define USAGE_ENVUIDGID "account child"
#define USAGE_ENVDIR "dir child"
#define USAGE_PGRPHACK "child"
#define USAGE_SETLOCK "[ -nNxX ] file program [ arg ... ]"
#define USAGE_SOFTLIMIT "[-a allbytes] [-c corebytes] [-d databytes] [-f filebytes] [-l lockbytes] [-m membytes] [-o openfiles] [-p processes] [-r residentbytes] [-s stackbytes] [-t cpusecs] child"

void setuidgid_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_SETUIDGID);
}
void setuidgid(int argc, const char *const *argv) {
  const char *account;

  if (! (account =*++argv)) setuidgid_usage();
  if (! *++argv) setuidgid_usage();
  suidgid((char*)account, 0);
  pathexec(argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
}

void envuidgid_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_ENVUIDGID);
}
void envuidgid(int argc, const char *const *argv) {
  const char *account;

  if (! (account =*++argv)) envuidgid_usage();
  if (! *++argv) envuidgid_usage();
  euidgid((char*)account, 0);
  pathexec(argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
}

void envdir_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_ENVDIR);
}
void envdir(int argc, const char *const *argv) {
  const char *dir;

  if (! (dir =*++argv)) envdir_usage();
  if (! *++argv) envdir_usage();
  edir(dir);
  pathexec(argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
}

void pgrphack_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_PGRPHACK);
}
void pgrphack(int argc, const char *const *argv) {
  if (! *++argv) pgrphack_usage();
  setsid();
  pathexec(argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
}

void setlock_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_SETLOCK);
}
void setlock(int argc, const char *const *argv) {
  int opt;
  unsigned int delay =0;
  unsigned int x =0;
  const char *fn;

  while ((opt =getopt(argc, argv, "nNxX")) != opteof)
    switch(opt) {
      case 'n': delay =1; break;
      case 'N': delay =0; break;
      case 'x': x =1; break;
      case 'X': x =0; break;
      default: setlock_usage();
    }
  argv +=optind;
  if (! (fn =*argv)) setlock_usage();
  if (! *++argv) setlock_usage();

  slock(fn, delay, x);
  pathexec(argv);
  if (! x) {
    errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
  }
  _exit(0);
}

void softlimit_usage() {
  errprintf_die(100, "usage: %s %s\n\n", progname, USAGE_SOFTLIMIT);
}
void getlarg(long *l) {
  unsigned long ul;

  if (str_equal(optarg, "=")) { *l =-1; return; }
  if (optarg[scan_ulong(optarg, &ul)]) usage();
  *l =ul;
}
void softlimit(int argc, const char *const *argv) {
  int opt;
  
  while ((opt =getopt(argc,argv,"a:c:d:f:l:m:o:p:r:s:t:")) != opteof)
    switch(opt) {
    case '?': softlimit_usage();
    case 'a': getlarg(&limita); break;
    case 'c': getlarg(&limitc); break;
    case 'd': getlarg(&limitd); break;
    case 'f': getlarg(&limitf); break;
    case 'l': getlarg(&limitl); break;
    case 'm': getlarg(&limitd); limits =limitl =limita =limitd; break;
    case 'o': getlarg(&limito); break;
    case 'p': getlarg(&limitp); break;
    case 'r': getlarg(&limitr); break;
    case 's': getlarg(&limits); break;
    case 't': getlarg(&limitt); break;
    }
  argv +=optind;
  if (!*argv) softlimit_usage();
  slimit();
  pathexec(argv);
  errprintf_die(111, FATAL "unable to run: %s: %s\n", *argv, error_str(errno));
}
