"""函数签名数据库 — (参数名列表, 返回值类型, 是否可变参)"""

SIGS = {
    # 内存
    "malloc": (["size"], "void*", False),
    "calloc": (["nmemb", "size"], "void*", False),
    "realloc": (["ptr", "size"], "void*", False),
    "free": (["ptr"], "void", False),

    # 字符串
    "strlen": (["s"], "size_t", False),
    "strcmp": (["s1", "s2"], "int", False),
    "strncmp": (["s1", "s2", "n"], "int", False),
    "strcpy": (["dst", "src"], "char*", False),
    "strncpy": (["dst", "src", "n"], "char*", False),
    "strcat": (["dst", "src"], "char*", False),
    "strchr": (["s", "c"], "char*", False),
    "strstr": (["haystack", "needle"], "char*", False),
    "strdup": (["s"], "char*", False),
    "memset": (["s", "c", "n"], "void*", False),
    "memcpy": (["dst", "src", "n"], "void*", False),
    "memmove": (["dst", "src", "n"], "void*", False),
    "memcmp": (["s1", "s2", "n"], "int", False),

    # IO
    "open": (["pathname", "flags", "mode"], "int", False),
    "creat": (["pathname", "mode"], "int", False),
    "close": (["fd"], "int", False),
    "read": (["fd", "buf", "count"], "ssize_t", False),
    "write": (["fd", "buf", "count"], "ssize_t", False),
    "lseek": (["fd", "offset", "whence"], "off_t", False),
    "printf": (["format"], "int", True),
    "fprintf": (["stream", "format"], "int", True),
    "sprintf": (["buf", "format"], "int", True),
    "snprintf": (["buf", "size", "format"], "int", True),
    "puts": (["s"], "int", False),
    "putchar": (["c"], "int", False),
    "perror": (["s"], "void", False),

    # 文件
    "fopen": (["pathname", "mode"], "FILE*", False),
    "fclose": (["stream"], "int", False),
    "fread": (["ptr", "size", "nmemb", "stream"], "size_t", False),
    "fwrite": (["ptr", "size", "nmemb", "stream"], "size_t", False),
    "fgets": (["s", "size", "stream"], "char*", False),
    "remove": (["pathname"], "int", False),
    "rename": (["oldpath", "newpath"], "int", False),

    # 时间
    "time": (["t"], "time_t", False),
    "sleep": (["seconds"], "unsigned", False),

    # 进程
    "exit": (["status"], "void", False),
    "abort": ([], "void", False),
    "fork": ([], "pid_t", False),
    "getpid": ([], "pid_t", False),
    "getenv": (["name"], "char*", False),

    # 数学
    "abs": (["j"], "int", False),
    "rand": ([], "int", False),
    "srand": (["seed"], "void", False),
    "atoi": (["nptr"], "int", False),
    "atol": (["nptr"], "long", False),
}


def get_sig_map():
    """返回 Rust SigDb.load() 兼容格式"""
    return SIGS
