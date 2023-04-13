#ifdef FD_HAS_SANDBOX

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "fd_sandbox.h"
#include "fd_sandbox_private.h"

#include <errno.h>        /* errno */
#include <fcntl.h>        /* open */
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>        /* CLONE_*, setns, unshare */
#include <stddef.h>
#include <stdio.h>        /* snprintf */
#include <stdlib.h>       /* clearenv, mkdtemp*/
#include <sys/mount.h>    /* MS_*, MNT_*, mount, umount2 */
#include <sys/prctl.h>
#include <sys/resource.h> /* RLIMIT_*, rlimit, setrlimit */
#include <sys/stat.h>     /* mkdir */
#include <sys/syscall.h>  /* SYS_* */
#include <unistd.h>       /* set*id, sysconf, close, chdir, rmdir syscall */

#include "../log/fd_log.h"

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

void
fd_sandbox_profile_init( fd_sandbox_profile_t * profile ) {
  profile->initialized      = true;
  profile->chroot_path      = NULL;
  profile->netns            = "fd-frank-netless",
  profile->seccomp_prog     = NULL;
  profile->user             = "nobody";
  profile->close_fds_beyond = 3U;
  profile->max_open_fds     = 3U;
}

int
fd_sandbox( const fd_sandbox_profile_t * profile ) {
  if ( FD_UNLIKELY( !profile->initialized ) ) {
    FD_LOG_ERR(( "the sandbox profile has not been initialized" ));
  }

  // Get target user before doing other kinds of restrictions
  struct passwd * uinfo = getpwnam( profile->user );
  if ( FD_UNLIKELY( !uinfo ) ) {
    FD_LOG_ERR(( "getpwnam: %s", strerror( errno ) ));
  }

  // todo: maybe not clearenv but only keep vars prefixed with FD_
  clearenv();
  fd_sandbox_setup_netns( profile->netns );
  fd_sandbox_setup_mountns( profile->chroot_path );
  fd_sandbox_set_resource_limits( profile->max_open_fds );
  fd_sandbox_change_user( uinfo );
  fd_sandbox_close_fds_beyond( profile->close_fds_beyond );
  fd_sandbox_seccomp( profile->seccomp_prog );

  FD_LOG_INFO(( "thread group sandboxed" ));
  return 0;
}

void
fd_sandbox_change_user( struct passwd * u ) {
  errno = 0;
  
  if ( FD_UNLIKELY( u->pw_uid == 0 ) ) {
    FD_LOG_ERR(( "will not run as root" ));
  }

  FD_LOG_INFO(( "switching to user='%s' uid='%d' gid='%d'", u->pw_name, u->pw_uid, u->pw_gid ));

  // setregid before setreuid otherwise setregid won't be allowed

  if ( FD_UNLIKELY( setregid( u->pw_gid, u->pw_gid ) ) ) {
    FD_LOG_ERR(( "setregid: %s", strerror( errno ) ));
  }

  if ( FD_UNLIKELY( setreuid( u->pw_uid, u->pw_uid ) ) ) {
    FD_LOG_ERR(( "setreuid: %s", strerror( errno ) ));
  }
}

void
fd_sandbox_close_fds_beyond( uint max_fd ) {
  FD_LOG_INFO(( "closing all fds beyond %d", max_fd ));
  long max_fds = sysconf(_SC_OPEN_MAX );
  for ( long fd = max_fds - 1; fd > max_fd; fd-- ) {
     close( (int)fd );
  } 
}

void
fd_sandbox_set_resource_limits(uint max_open_fds) {
  FD_LOG_INFO(( "setting resource limits" ));
  // todo(marcus-jump): set more limits
  struct rlimit l = {
    .rlim_cur = max_open_fds,
    .rlim_max = max_open_fds,
  };

  if ( FD_UNLIKELY( setrlimit(RLIMIT_NOFILE, &l) == -1 ) ) {
    FD_LOG_ERR(( "setrlimit: %s", strerror( errno ) ));
  }
}

void
fd_sandbox_setup_netns( char * ns_name ) {
  char netns_path[ PATH_MAX ];
  int nsfd;

  FD_LOG_INFO(( "setting up network namespace" ));

  // realize the namespace path
  int reslen = snprintf( netns_path, ARRAY_SIZE(netns_path), "/var/run/netns/%s", ns_name );
  if ( FD_UNLIKELY( (ulong) (reslen + 1) > ARRAY_SIZE(netns_path) ) ) {
    FD_LOG_ERR(( "namespace name too long" ));
  }

  // get a reference to the namespace
  if ( FD_UNLIKELY( ( nsfd = open( netns_path, 0 ) ) == -1 ) ) {
    FD_LOG_ERR(( "netns open: %s", strerror( errno ) ));
  }

  // enter the namespace
  if ( FD_UNLIKELY( setns( nsfd, CLONE_NEWNET ) == -1 ) ) {
    FD_LOG_ERR(( "netns setns: %s", strerror( errno ) ));
  };

  // close the namespace reference
  close( nsfd );
}

void 
fd_sandbox_setup_mountns( char * chroot_path ) {
  if ( FD_UNLIKELY( unshare(CLONE_NEWNS) == -1 ) )
    FD_LOG_ERR(( "unshare: (%d) %s", errno, strerror( errno ) ));

  if ( FD_UNLIKELY( mount( NULL, "/", NULL, MS_SLAVE | MS_REC, NULL) == -1 ) )
    FD_LOG_ERR(( "unshare: %s", strerror( errno ) ));

  // If chroot_path is null, we will set this new mountns' root to be a temp directory where the user won't be able to do anything.
  if ( FD_UNLIKELY( chroot_path == NULL ) ) {
    char * tmp_str = "/tmp/fd-sandbox-XXXXXX";
    char str_buf[ sizeof("/tmp/fd-sandbox-XXXXXX") ];
    memcpy( str_buf, tmp_str, sizeof( "/tmp/fd-sandbox-XXXXXX" ) );
    chroot_path = mkdtemp( str_buf );
    if ( FD_UNLIKELY( chroot_path == NULL ) )
      FD_LOG_ERR(( "mkdtemp: (%d) %s", errno, strerror( errno ) ));
  }

  FD_LOG_INFO(( "using %s as root mount", chroot_path ));

  if ( FD_UNLIKELY( mount( chroot_path, chroot_path, NULL, MS_BIND | MS_REC, NULL ) == -1 ) )
    FD_LOG_ERR(( "mount: (%d) %s", errno, strerror( errno ) ));

  if ( FD_UNLIKELY( chdir(chroot_path) == -1 ) ) 
    FD_LOG_ERR(( "cwd: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( mkdir(".old-root", 0600) == -1 ) )
    FD_LOG_ERR(( "mkdir: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( syscall(SYS_pivot_root, "./", ".old-root" ) ) )
    FD_LOG_ERR(( "SYS_pivot_root: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( umount2(".old-root", MNT_DETACH) == -1 ) ) 
    FD_LOG_ERR(( "umount2: %s", strerror( errno ) ));

  if ( FD_UNLIKELY( rmdir(".old-root") == -1 ) )
    FD_LOG_ERR(( "rmdir: %s", strerror( errno ) ));
}


/* seccomp */
#define X32_SYSCALL_BIT 0x40000000

#define ALLOW_SYSCALL(name) \
  /* If the syscall does not match, jump over RET_ALLOW */ \
  BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)

#if defined(__i386__)
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define ARCH_NR	AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
# define ARCH_NR AUDIT_ARCH_AARCH64
#else
# error "Unsupported seccomp platform. This platform cannot build with FD_sandbox=1."
#endif

void
fd_sandbox_seccomp( struct sock_fprog *prog ) {
    struct sock_filter filter[] = {
      // [0] Validate architecture
      // Load the arch number
      BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, arch ) ) ),
      // Do not jump (and die) if the compile arch is neq the runtime arch.
      // Otherwise, jump over the SECCOMP_RET_KILL_PROCESS statement.
      BPF_JUMP( BPF_JMP | BPF_JEQ | BPF_K, ARCH_NR, 1, 0 ),
      BPF_STMT( BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS ),

      // [1] Verify that the syscall is allowed
      // Load the syscall
      BPF_STMT( BPF_LD | BPF_W | BPF_ABS, ( offsetof( struct seccomp_data, nr ) ) ),

      // Attempt to sort syscalls by call frequency.
      ALLOW_SYSCALL( writev       ),
      ALLOW_SYSCALL( write        ),
      ALLOW_SYSCALL( fsync        ),
      ALLOW_SYSCALL( gettimeofday ),
      ALLOW_SYSCALL( futex        ),
      // sched_yield is useful for both floating threads and hyperthreaded pairs.
      ALLOW_SYSCALL( sched_yield  ),
      // The rules under this line are expected to be used in fewer occasions.
      // exit is needed to let tiles exit gracefully.
      ALLOW_SYSCALL( exit         ),
      // exit_group is needed to let any tile crash the whole group.
      ALLOW_SYSCALL( exit_group   ),
      // munmap is needed for a clean exit.
      ALLOW_SYSCALL( munmap       ),
      // nanosleep is needed for a clean exit.
      ALLOW_SYSCALL( nanosleep    ),
      ALLOW_SYSCALL( rt_sigaction ),
      ALLOW_SYSCALL( rt_sigreturn ),
      ALLOW_SYSCALL( sync         ),
      // close is needed for a clean exit and for closing logs.
      ALLOW_SYSCALL( close        ),

      // [2] None of the syscalls approved were matched: die
      BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    };

    struct sock_fprog default_prog = {
      .len = ARRAY_SIZE( filter ),
      .filter = filter,
    };

  if ( FD_LIKELY( !prog ) ) {
    FD_LOG_INFO(( "Loading default filter" ));
    prog = &default_prog;
  }

  if ( FD_UNLIKELY( prctl( PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0 ) ) ) {
    FD_LOG_ERR(( "prctl( PR_SET_NO_NEW_PRIVS, ... ): %s", strerror( errno ) ));
  }

  if ( FD_UNLIKELY( syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, prog ) ) ) {
    FD_LOG_ERR(( "syscall( SYS_seccomp, SECCOMP_SET_MODE_FILTER, ... ): %s", strerror( errno ) ));
  }
}

#endif /* FD_HAS_SANDBOX */
