"""Linux seccomp confinement for the test agent processes, not the host."""
import ctypes
import ctypes.util
import errno
import os
import platform
import resource


class Compare(ctypes.Structure):
    _fields_ = [('arg', ctypes.c_uint), ('op', ctypes.c_int),
                ('a', ctypes.c_uint64), ('b', ctypes.c_uint64)]


def confine(channel_fd):
    """Fail closed. No new files, sockets, processes or process inspection.

    Only the preconnected gateway FD and stdin/stdout/stderr remain usable.
    Stdio is an explicit trusted test-controller channel, NOT complete egress control.
    """
    if platform.system() != 'Linux':
        raise RuntimeError('Linux and libseccomp are required; no isolation fallback')
    library = ctypes.util.find_library('seccomp')
    if not library:
        raise RuntimeError('libseccomp is required; no isolation fallback')
    sec = ctypes.CDLL(library, use_errno=True)
    sec.seccomp_init.argtypes = [ctypes.c_uint32]
    sec.seccomp_init.restype = ctypes.c_void_p
    sec.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    sec.seccomp_syscall_resolve_name.restype = ctypes.c_int
    sec.seccomp_rule_add_array.argtypes = [ctypes.c_void_p, ctypes.c_uint32,
                                          ctypes.c_int, ctypes.c_uint,
                                          ctypes.POINTER(Compare)]
    sec.seccomp_load.argtypes = [ctypes.c_void_p]
    sec.seccomp_release.argtypes = [ctypes.c_void_p]
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(38, 1, 0, 0, 0):  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'no_new_privs failed')
    if libc.prctl(4, 0, 0, 0, 0):  # PR_SET_DUMPABLE
        raise OSError(ctypes.get_errno(), 'dump protection failed')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    ctx = sec.seccomp_init(0x00050000 | errno.EPERM)
    if not ctx:
        raise RuntimeError('seccomp_init failed')
    allowed = [
        'brk', 'mmap', 'mmap2', 'mprotect', 'munmap', 'mremap', 'madvise',
        'futex', 'futex_time64', 'getrandom', 'clock_gettime', 'clock_gettime64',
        'gettimeofday', 'time', 'nanosleep', 'clock_nanosleep', 'clock_nanosleep_time64',
        'rt_sigaction', 'rt_sigprocmask', 'rt_sigreturn', 'sigaltstack',
        'getpid', 'gettid', 'getuid', 'geteuid', 'getgid', 'getegid',
        'sched_yield', 'restart_syscall', 'exit', 'exit_group', 'close',
        'poll', 'ppoll', 'ppoll_time64', 'select', 'pselect6', 'pselect6_time64',
        'fstat', 'newfstatat', 'fstat64', 'fcntl', 'fcntl64',
    ]
    def allow(name, fd=None):
        number = sec.seccomp_syscall_resolve_name(name.encode())
        if number < 0:
            return
        arg = Compare(0, 4, fd, 0) if fd is not None else None  # SCMP_CMP_EQ
        result = sec.seccomp_rule_add_array(ctx, 0x7fff0000, number,
                                           1 if arg is not None else 0,
                                           ctypes.byref(arg) if arg is not None else None)
        if result:
            raise RuntimeError(f'seccomp rule {name}: {result}')
    try:
        for name in allowed:
            allow(name)
        for name in ('read', 'readv', 'write', 'writev'):
            for fd in (0, 1, 2, channel_fd):
                allow(name, fd)
        for name in ('sendto', 'recvfrom', 'sendmsg', 'recvmsg',
                     'getsockopt', 'getpeername', 'getsockname', 'shutdown'):
            allow(name, channel_fd)
        result = sec.seccomp_load(ctx)
        if result:
            raise RuntimeError(f'seccomp_load: {result}')
    finally:
        sec.seccomp_release(ctx)
    return {'seccomp': True, 'policy': 'default-EPERM syscall allowlist',
            'pid': os.getpid(), 'gateway_fd': channel_fd,
            'allowed_channels': ['stdin', 'stdout', 'stderr', 'preconnected gateway']}
