"""函数签名数据库

格式: name → (arg_count, variadic)
"""

SIGS = {
    # 内存
    "malloc": (1, False), "calloc": (2, False), "realloc": (2, False),
    "free": (1, False), "memalign": (2, False), "posix_memalign": (3, False),
    "aligned_alloc": (2, False),
    "mmap": (6, False), "munmap": (2, False), "brk": (1, False),
    "sbrk": (1, False),

    # 字符串
    "strlen": (1, False), "strcmp": (2, False), "strncmp": (3, False),
    "strcpy": (2, False), "strncpy": (3, False), "strcat": (2, False),
    "strncat": (3, False), "strchr": (2, False), "strrchr": (2, False),
    "strstr": (2, False), "strdup": (1, False), "strndup": (2, False),
    "memset": (3, False), "memcpy": (3, False), "memmove": (3, False),
    "memcmp": (3, False),

    # IO
    "open": (3, False), "open64": (3, False), "creat": (2, False),
    "close": (1, False), "read": (3, False), "write": (3, False),
    "pread": (4, False), "pwrite": (4, False),
    "lseek": (3, False), "stat": (2, False), "fstat": (2, False),
    "lstat": (2, False), "fstat64": (2, False),
    "fcntl": (3, True), "ioctl": (3, True),

    # 输出
    "printf": (1, True), "fprintf": (2, True), "sprintf": (3, True),
    "snprintf": (3, True), "dprintf": (2, True),
    "vprintf": (1, False), "vfprintf": (2, False), "vsprintf": (3, False),
    "vsnprintf": (3, False),
    "puts": (1, False), "fputs": (2, False), "putchar": (1, False),
    "putc": (2, False), "fputc": (2, False),

    # 错误
    "exit": (1, False), "_exit": (1, False), "abort": (0, False),
    "perror": (1, False), "strerror": (1, False),

    # 信号
    "signal": (2, False), "sigaction": (3, False),
    "kill": (2, False), "raise": (1, False),

    # 时间
    "time": (1, False), "ctime": (1, False), "localtime": (1, False),
    "gmtime": (1, False), "mktime": (1, False),
    "clock_gettime": (2, False), "nanosleep": (2, False),

    # 线程
    "pthread_create": (4, False), "pthread_join": (2, False),
    "pthread_mutex_lock": (1, False), "pthread_mutex_unlock": (1, False),

    # 环境
    "getenv": (1, False), "setenv": (3, False), "unsetenv": (1, False),
    "execve": (3, False), "execvp": (2, False),

    # 类型转换
    "atoi": (1, False), "atol": (1, False), "strtol": (3, False),
    "strtoul": (3, False), "strtod": (2, False),

    # 运行时
    "setjmp": (1, False), "longjmp": (2, False),
    "alloca": (1, False),

    # 系统
    "getpid": (0, False), "getppid": (0, False),
    "sleep": (1, False), "usleep": (1, False),
    "sysconf": (1, False),

    # C++
    "_Znwm": (1, False),  # operator new
    "_ZdlPv": (1, False), # operator delete
    "__cxa_atexit": (3, False),
}

def get_sig_map():
    return SIGS
