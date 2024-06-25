struct threadq;

struct threadq *threadq_init(void);
void threadq_destroy(struct threadq **pq);

struct threadq_worker;

#define THREADQ_SHUTDOWN (void*)(-1)

/*
 * Create a new thread with start routine `start`. The thread will be
 * given a `struct threadq_worker *` argument, and begin in an idle
 * state waiting for a `threadq_worker_send()` or `threadq_worker_join()`
 * call from the coordinator.
 */
struct threadq_worker *threadq_worker_init(void *(*start)(void *));
void *threadq_worker_join(struct threadq_worker *w);
void threadq_worker_destroy(struct threadq_worker **pw);

void threadq_worker_send_work(struct threadq_worker *w, void *data);
void *threadq_worker_recv_result(struct threadq_worker *w);

void *threadq_worker_recv_work(struct threadq_worker *w);
void threadq_worker_send_result(struct threadq_worker *w, void *data);

void threadq_add(struct threadq *q, struct threadq_worker *w);
struct threadq_worker *threadq_next(struct threadq *q);
