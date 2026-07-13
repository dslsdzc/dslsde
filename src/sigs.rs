/// dslsde — 函数签名数据库
///
/// 内嵌签名，无外部格式依赖。
/// 每条签名: 函数名, 参数名列表, 返回值类型, 是否可变参

pub struct FuncSig {
    pub name: &'static str,
    pub args: &'static [&'static str],
    pub ret: &'static str,
    pub variadic: bool,
}

pub static SIGS: &[FuncSig] = &[
    // 内存
    FuncSig { name: "malloc", args: &["size"], ret: "void*", variadic: false },
    FuncSig { name: "calloc", args: &["nmemb", "size"], ret: "void*", variadic: false },
    FuncSig { name: "realloc", args: &["ptr", "size"], ret: "void*", variadic: false },
    FuncSig { name: "free", args: &["ptr"], ret: "void", variadic: false },
    // 字符串
    FuncSig { name: "strlen", args: &["s"], ret: "size_t", variadic: false },
    FuncSig { name: "strcmp", args: &["s1", "s2"], ret: "int", variadic: false },
    FuncSig { name: "strncmp", args: &["s1", "s2", "n"], ret: "int", variadic: false },
    FuncSig { name: "strcpy", args: &["dst", "src"], ret: "char*", variadic: false },
    FuncSig { name: "strncpy", args: &["dst", "src", "n"], ret: "char*", variadic: false },
    FuncSig { name: "strcat", args: &["dst", "src"], ret: "char*", variadic: false },
    FuncSig { name: "strchr", args: &["s", "c"], ret: "char*", variadic: false },
    FuncSig { name: "strstr", args: &["haystack", "needle"], ret: "char*", variadic: false },
    FuncSig { name: "strdup", args: &["s"], ret: "char*", variadic: false },
    FuncSig { name: "memset", args: &["s", "c", "n"], ret: "void*", variadic: false },
    FuncSig { name: "memcpy", args: &["dst", "src", "n"], ret: "void*", variadic: false },
    FuncSig { name: "memmove", args: &["dst", "src", "n"], ret: "void*", variadic: false },
    FuncSig { name: "memcmp", args: &["s1", "s2", "n"], ret: "int", variadic: false },
    // IO
    FuncSig { name: "open", args: &["pathname", "flags", "mode"], ret: "int", variadic: false },
    FuncSig { name: "creat", args: &["pathname", "mode"], ret: "int", variadic: false },
    FuncSig { name: "close", args: &["fd"], ret: "int", variadic: false },
    FuncSig { name: "read", args: &["fd", "buf", "count"], ret: "ssize_t", variadic: false },
    FuncSig { name: "write", args: &["fd", "buf", "count"], ret: "ssize_t", variadic: false },
    FuncSig { name: "lseek", args: &["fd", "offset", "whence"], ret: "off_t", variadic: false },
    FuncSig { name: "stat", args: &["pathname", "statbuf"], ret: "int", variadic: false },
    FuncSig { name: "fstat", args: &["fd", "statbuf"], ret: "int", variadic: false },
    FuncSig { name: "printf", args: &["format"], ret: "int", variadic: true },
    FuncSig { name: "fprintf", args: &["stream", "format"], ret: "int", variadic: true },
    FuncSig { name: "sprintf", args: &["buf", "format"], ret: "int", variadic: true },
    FuncSig { name: "snprintf", args: &["buf", "size", "format"], ret: "int", variadic: true },
    FuncSig { name: "puts", args: &["s"], ret: "int", variadic: false },
    FuncSig { name: "putchar", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "perror", args: &["s"], ret: "void", variadic: false },
    // 文件
    FuncSig { name: "fopen", args: &["pathname", "mode"], ret: "FILE*", variadic: false },
    FuncSig { name: "fclose", args: &["stream"], ret: "int", variadic: false },
    FuncSig { name: "fread", args: &["ptr", "size", "nmemb", "stream"], ret: "size_t", variadic: false },
    FuncSig { name: "fwrite", args: &["ptr", "size", "nmemb", "stream"], ret: "size_t", variadic: false },
    FuncSig { name: "fgets", args: &["s", "size", "stream"], ret: "char*", variadic: false },
    FuncSig { name: "fputs", args: &["s", "stream"], ret: "int", variadic: false },
    FuncSig { name: "fprintf", args: &["stream", "format"], ret: "int", variadic: true },
    FuncSig { name: "remove", args: &["pathname"], ret: "int", variadic: false },
    FuncSig { name: "rename", args: &["oldpath", "newpath"], ret: "int", variadic: false },
    // 时间
    FuncSig { name: "time", args: &["t"], ret: "time_t", variadic: false },
    FuncSig { name: "clock", args: &[], ret: "clock_t", variadic: false },
    FuncSig { name: "sleep", args: &["seconds"], ret: "unsigned", variadic: false },
    FuncSig { name: "usleep", args: &["usec"], ret: "int", variadic: false },
    // 进程
    FuncSig { name: "exit", args: &["status"], ret: "void", variadic: false },
    FuncSig { name: "abort", args: &[], ret: "void", variadic: false },
    FuncSig { name: "fork", args: &[], ret: "pid_t", variadic: false },
    FuncSig { name: "execve", args: &["path", "argv", "envp"], ret: "int", variadic: false },
    FuncSig { name: "getpid", args: &[], ret: "pid_t", variadic: false },
    FuncSig { name: "getenv", args: &["name"], ret: "char*", variadic: false },
    // 数学
    FuncSig { name: "abs", args: &["j"], ret: "int", variadic: false },
    FuncSig { name: "rand", args: &[], ret: "int", variadic: false },
    FuncSig { name: "srand", args: &["seed"], ret: "void", variadic: false },
    FuncSig { name: "atoi", args: &["nptr"], ret: "int", variadic: false },
    FuncSig { name: "atol", args: &["nptr"], ret: "long", variadic: false },
    FuncSig { name: "atoll", args: &["nptr"], ret: "long long", variadic: false },
    FuncSig { name: "strtol", args: &["nptr", "endptr", "base"], ret: "long", variadic: false },
    // 类型判断
    FuncSig { name: "isdigit", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "isalpha", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "isalnum", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "isspace", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "toupper", args: &["c"], ret: "int", variadic: false },
    FuncSig { name: "tolower", args: &["c"], ret: "int", variadic: false },
    // 错误
    FuncSig { name: "errno", args: &[], ret: "int", variadic: false },
    FuncSig { name: "strerror", args: &["errnum"], ret: "char*", variadic: false },
    // 线程
    FuncSig { name: "pthread_create", args: &["thread", "attr", "start_routine", "arg"], ret: "int", variadic: false },
    FuncSig { name: "pthread_join", args: &["thread", "retval"], ret: "int", variadic: false },
    FuncSig { name: "pthread_mutex_lock", args: &["mutex"], ret: "int", variadic: false },
    FuncSig { name: "pthread_mutex_unlock", args: &["mutex"], ret: "int", variadic: false },
];

/// 查找函数签名
pub fn lookup(name: &str) -> Option<&'static FuncSig> {
    let base = name.split(|c: char| c == '@' || c == '(' || c == '.').next().unwrap_or(name);
    SIGS.iter().find(|s| s.name == base)
}
