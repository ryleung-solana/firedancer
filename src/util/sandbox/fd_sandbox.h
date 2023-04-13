#ifdef FD_HAS_SANDBOX

#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_h

#include "../fd_util_base.h"

#include <linux/filter.h>
#include <stdbool.h>

struct fd_sandbox_profile {
  bool                initialized;

  char *              chroot_path;
  uint                close_fds_beyond;
  uint                max_open_fds;
  char *              netns;
  struct sock_fprog * seccomp_prog;
  char *              user;
};
typedef struct fd_sandbox_profile fd_sandbox_profile_t;

/* fd_sandbox sandboxes the current process. */
int fd_sandbox              ( const fd_sandbox_profile_t * const sandbox_profile );

/* fd_sandbox_profile_init initializes a fd_sandbox_profile_t* with sane defaults. */
void fd_sandbox_profile_init ( fd_sandbox_profile_t * profile );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_h */
#endif /* FD_HAS_SANDBOX */
