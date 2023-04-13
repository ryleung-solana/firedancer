#ifdef FD_HAS_SANDBOX

#ifndef HEADER_fd_src_util_sandbox_fd_sandbox_private_h
#define HEADER_fd_src_util_sandbox_fd_sandbox_private_h

#include <linux/filter.h>
#include <pwd.h>

void fd_sandbox_change_user         ( struct passwd * u );
void fd_sandbox_close_fds_beyond    ( uint max_fd );
void fd_sandbox_set_resource_limits ( uint max_open_fds );
void fd_sandbox_setup_netns         ( char * ns_name );
void fd_sandbox_setup_mountns       ( char * chroot_path );
void fd_sandbox_seccomp             ( struct sock_fprog * prog );

#endif /* HEADER_fd_src_util_sandbox_fd_sandbox_private_h */
#endif /* FD_HAS_SANDBOX */
