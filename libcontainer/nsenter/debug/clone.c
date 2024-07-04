#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

#define FIBER_STACK 8192
int a;
void *stack;

int do_something() {
    a = 10;
    printf("This is son, the pid is:%d, the a is: %d\n", getpid(), a);
    free(stack);
    exit(1);
}

int main() {
    void *stack;
    a = 1;
    stack = malloc(FIBER_STACK); // 为子进程申请系统堆栈
    if (!stack) {
        printf("The stack failed\n");
        exit(0);
    }
    printf("creating son thread!!!\n");
    clone(&do_something, (char *)stack + FIBER_STACK, CLONE_VM | CLONE_VFORK, 0); // 创建子线程
    printf("This is father, my pid is: %d, the a is: %d\n", getpid(), a);
    exit(1);
}
// 运行的结果：
//
// son的PID：10692；
//
// father的PID：10691；
//
// parent和son中的a都为10；所以证明他们公用了一份变量a，是指针的复制，而不是值的复制。
