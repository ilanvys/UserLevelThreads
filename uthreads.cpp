#include "uthreads.h"
#include <iostream>
#include <list>
#include <csetjmp>
#include <csignal>
#include <sys/time.h>

using std::list;

typedef unsigned long address_t;
#define JB_SP 6
#define JB_PC 7
#define THREAD_SWITCHED 2
#define KEEP_INTERVAL 0

enum class State{
    RUNNING = 1,
    BLOCKED = 2,
    TERMINATED = 3,
    SLEEPING = 4
};

struct Thread {
    int tid;
    int running_quantum_counter;
    sigjmp_buf env;
    char* st;
    bool is_sleeping;
    bool is_blocked;
    int quantum_left;
};

struct sigaction sa = {0};
struct itimerval timer;
int available_tid[MAX_THREAD_NUM + 1] = {0};
int quantum_counter;
sigset_t mask;
std::list<Thread*> ready_q; // first element is in running state.
std::list<Thread*> pending_list;


// Helper functions
address_t translate_address(address_t addr)
{
    address_t ret;
    asm volatile("xor    %%fs:0x30,%0\n"
                 "rol    $0x11,%0\n"
            : "=g" (ret)
            : "0" (addr));
    return ret;
}

int find_smallest_tid() {
    for (int i = 0; i <= MAX_THREAD_NUM; ++i) {
        if (available_tid[i] == 0) {
            return i;
        }
    }
    std::cerr << "thread library error: MAX_THREAD_NUM exceeded\n";

    return -1;
}

int reset_timer(int quantum_usecs) {
    if (quantum_usecs == KEEP_INTERVAL) {
        quantum_usecs = timer.it_interval.tv_usec;
    }
    timer.it_value = {0, quantum_usecs};
    timer.it_interval = {0, quantum_usecs};

    if (setitimer(ITIMER_VIRTUAL, &timer, nullptr) < 0)
    {
        std::cerr << "thread library error: setitimer error\n";
        return -1;
    }

    return 0;
}

void update_sleeping_threads() {
    for (auto thread_ptr : pending_list) {
        if (thread_ptr->is_sleeping) {
            thread_ptr->quantum_left--;
            if (thread_ptr->quantum_left == 0) {
                thread_ptr->is_sleeping = false;
            }
        }
    }

    list<Thread*>::iterator it = pending_list.begin();
    while (it != pending_list.end()) {
        if (!(*it)->is_sleeping && !(*it)->is_blocked) {
            ready_q.push_back(*it);
            it = pending_list.erase(it);
            continue;
        }
        it++;
    }
}

int thread_state_switch(State st) {
    sigprocmask(SIG_BLOCK, &mask, NULL);
    quantum_counter++;

    Thread* curr_thread = ready_q.front();
    if (st == State::TERMINATED) {
        ready_q.pop_front();
    }
    if (st == State::RUNNING) {
        ready_q.push_back(ready_q.front());
        ready_q.pop_front();
    }
    if (st == State::SLEEPING || st == State::BLOCKED) {
        pending_list.push_back(ready_q.front());
        ready_q.pop_front();
    }
    if (st != State::TERMINATED) {
        int ret_val = sigsetjmp(curr_thread->env, 1);

        if (ret_val == THREAD_SWITCHED) {
            ready_q.front()->running_quantum_counter++;
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }

    update_sleeping_threads();
    reset_timer(KEEP_INTERVAL);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    siglongjmp(ready_q.front()->env, THREAD_SWITCHED);
}

void timer_handler(int sig)
{
    thread_state_switch(State::RUNNING);
}

int uthread_init(int quantum_usecs) {
    if (quantum_usecs <= 0) {
        std::cerr << "thread library error: non-positive quantum_usecs\n";
        return -1;
    }
    // Prepare mask set
    sigemptyset(&mask);
    sigaddset(&mask, SIGVTALRM);

    // Make the main thread
    Thread* main_thread = new Thread;
    main_thread->tid = 0;
    main_thread->is_sleeping = false;
    main_thread->is_blocked = false;
    main_thread->quantum_left = 0;

    sigsetjmp(main_thread->env,  1);
    ready_q.push_front(main_thread);
    available_tid[0]++;

    // create time management
    quantum_counter = 1;
    main_thread->running_quantum_counter = 1;

    // Install timer_handler as the signal handler for SIGVTALRM.
    sa.sa_handler = &timer_handler;
    if (sigaction(SIGVTALRM, &sa, nullptr) < 0)
    {
        std::cerr << "thread library error: error in creating sigaction\n"<< std::flush;
        return -1;
    }
    if (reset_timer(quantum_usecs) < 0) {
        return -1;
    }

    return 0;
}

int uthread_spawn(thread_entry_point entry_point) {
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if ((ready_q.size() + pending_list.size()) == (MAX_THREAD_NUM)) {
        std::cerr << "thread library error: MAX_THREAD_NUM exceeded\n";
        return -1;
    }
    if (entry_point == nullptr) {
        std::cerr << "thread library error: invalid entry point\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        return -1;
    }

    char* stack = new char[STACK_SIZE];
    int tid = find_smallest_tid();
    available_tid[tid]++;

    Thread* new_thread = new Thread;
    new_thread->tid = tid;
    new_thread->st = stack;
    new_thread->is_sleeping = false;
    new_thread->is_blocked = false;
    new_thread->quantum_left = 0;
    new_thread->running_quantum_counter = 0;

    address_t sp = (address_t) stack + STACK_SIZE - sizeof(address_t);
    address_t pc = (address_t) entry_point;
    sigsetjmp(new_thread->env, 1);
    new_thread->running_quantum_counter++;
    ((new_thread->env)->__jmpbuf)[JB_SP] = translate_address(sp);
    ((new_thread->env)->__jmpbuf)[JB_PC] = translate_address(pc);
    sigemptyset(&(new_thread->env)->__saved_mask);

    ready_q.push_back(new_thread);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    return tid;
}

int uthread_terminate(int tid) {
    sigprocmask(SIG_BLOCK, &mask, NULL);

    if(tid < 0 || tid > MAX_THREAD_NUM){
        std::cerr << "thread library error: tid " << tid << " not valid\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);
        return -1;
    }
    // Terminate all threads including main
    if (tid == 0) {
        for (auto it = ready_q.begin(); it != ready_q.end(); ++it) {
            Thread* thread = *it;
            if (thread->tid != 0) {
                free(thread->st);

            }
            delete thread;
        }
        for (auto it = pending_list.begin(); it != pending_list.end(); ++it) {
            Thread* thread = *it;
            free(thread->st);
            delete thread;
        }
        exit(0);
    }

    // Terminate current thread
    if (tid == ready_q.front()->tid) {
        available_tid[tid]--;
        Thread* thread_ptr = ready_q.front();
        delete thread_ptr->st;
        delete thread_ptr;
        thread_state_switch(State::TERMINATED);

        return 0;
    }

    // terminate thread in ready position
    for (auto thread_ptr : ready_q) {
        if (thread_ptr->tid == tid) {
            available_tid[tid]--;
            ready_q.remove(thread_ptr);
            delete thread_ptr->st;
            delete thread_ptr;
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }
    for (auto thread_ptr : pending_list) {
        if (thread_ptr->tid == tid) {
            available_tid[tid]--;
            pending_list.remove(thread_ptr);
            delete thread_ptr->st;
            delete thread_ptr;
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }
    std::cerr << "thread library error: tid " << tid << " not found\n";
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    return -1;
}

int uthread_block(int tid){
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if(tid < 0 || tid > MAX_THREAD_NUM){
        std::cerr << "thread library error: tid " << tid << " not valid\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    if (tid == 0){
        std::cerr << "thread library error: cannot block main thread\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    if (available_tid[tid] == 0){
        std::cerr << "thread library error: tid " << tid << " not found, cannot block\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    if (ready_q.front()->tid == tid){
        ready_q.front()->is_blocked = true;
        thread_state_switch(State::BLOCKED);

        return 0;
    }
    for (auto thread_ptr : ready_q) {
        if (thread_ptr->tid == tid) {
            thread_ptr->is_blocked = true;
            pending_list.push_back(thread_ptr);
            ready_q.remove(thread_ptr);
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }
    for (auto thread_ptr : pending_list) {
        if (thread_ptr->tid == tid) {
            thread_ptr->is_blocked = true;
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    return 0;
}

int uthread_resume(int tid){
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if(tid < 0 || tid > MAX_THREAD_NUM){
        std::cerr << "thread library error: tid " << tid << " not valid\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    if (available_tid[tid] == 0) {
        std::cerr << "thread library error: tid " << tid << " not found, cannot resume\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    if (tid == 0) {
        std::cerr << "thread library error: tid " << tid << " is not valid\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }

    for (Thread* thread_ptr : pending_list) {
        if (thread_ptr->tid == tid) {
            thread_ptr->is_blocked = false;
            if (!thread_ptr->is_sleeping) {
                ready_q.push_back(thread_ptr);
                pending_list.remove(thread_ptr);
            }
            sigprocmask(SIG_UNBLOCK, &mask, NULL);

            return 0;
        }
    }

    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    return 0;
}

int uthread_sleep(int num_quantums){
    sigprocmask(SIG_BLOCK, &mask, NULL);
    if (ready_q.front()->tid == 0){
        std::cerr << "thread library error: cannot block main thread\n";
        sigprocmask(SIG_UNBLOCK, &mask, NULL);

        return -1;
    }
    ready_q.front()->is_sleeping = true;
    ready_q.front()->quantum_left = num_quantums;

    thread_state_switch(State::SLEEPING);
    sigprocmask(SIG_UNBLOCK, &mask, NULL);

    return 0;
}

int uthread_get_tid(){
    return ready_q.front()->tid;
}

int uthread_get_total_quantums(){
    return quantum_counter;
}

int uthread_get_quantums(int tid){
    sigprocmask(SIG_BLOCK, &mask, NULL);

    for (auto thread : ready_q) {
        if(thread->tid == tid){
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
            return thread->running_quantum_counter;
        }
    }
    for (auto thread : pending_list) {
        if(thread->tid == tid){
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
            return thread->running_quantum_counter;
        }
    }

    std::cerr << "thread library error: tid " << tid << " not found\n";
    sigprocmask(SIG_UNBLOCK, &mask, NULL);
    return -1;
}
