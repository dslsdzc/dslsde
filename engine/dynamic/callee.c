// dslsde — LD_PRELOAD 函数调用注入器
// 编译: gcc -shared -fPIC -o libcallee.so callee.c -ldl
// 使用: LD_PRELOAD=libcallee.so TARGET_FUNC=0x403910 ./binary

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// 要调用的目标函数 (类型: void func(void*, void*, int))
typedef void (*target_func_t)(void*, void*, int);

__attribute__((constructor))
void call_target() {
    const char *func_addr_str = getenv("TARGET_FUNC");
    if (!func_addr_str) return;

    unsigned long long addr = strtoull(func_addr_str, NULL, 16);
    if (addr == 0) return;

    fprintf(stderr, "[dslsde] Calling function at 0x%llx\n", addr);

    target_func_t func = (target_func_t)addr;
    // 用空参数调用（函数可能崩溃但会被 trace 捕获）
    func(NULL, NULL, 0);

    fprintf(stderr, "[dslsde] Function returned\n");
}
