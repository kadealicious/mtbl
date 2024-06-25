#include <stdlib.h>
#include <stdbool.h>
#include <pthread.h>
#include <assert.h>
#include "threadq.h"

struct threadq_worker {
	pthread_mutex_t m;
	pthread_cond_t c;
	bool running;

	pthread_t thr;
	void *data;

	struct threadq_worker *next;
};

struct threadq {
	pthread_mutex_t m;
	pthread_cond_t c;

	struct threadq_worker *head, **ptail;
};

struct threadq *
threadq_init(void)
{
	struct threadq *q = calloc(1, sizeof(*q));

	pthread_mutex_init(&q->m, NULL);
	pthread_cond_init(&q->c, NULL);
	q->ptail = &q->head;
	return q;
}

void
threadq_destroy(struct threadq **pq)
{
	struct threadq *q = *pq;

	if (q == NULL) return;
	assert(q->head == NULL);
	pthread_mutex_destroy(&q->m);
	pthread_cond_destroy(&q->c);
	free(q);

	*pq = NULL;
}

struct threadq_worker;

/*
 * Create a new thread with start routine `start`. The thread will be
 * given a `struct threadq_worker *` argument, and begin in an idle
 * state waiting for a `threadq_worker_send()` or `threadq_worker_join()`
 * call from the coordinator.
 */
struct threadq_worker *
threadq_worker_init(void *(*start)(void *))
{
	struct threadq_worker *w = calloc(1, sizeof(*w));

	pthread_mutex_init(&w->m, NULL);
	pthread_cond_init(&w->c, NULL);

	pthread_create(&w->thr, NULL, start, w);
	return w;
}

void *
threadq_worker_join(struct threadq_worker *w)
{
	void *ret;

	threadq_worker_send_work(w, NULL);
	pthread_join(w->thr, &ret);

	return ret;
}

void
threadq_worker_destroy(struct threadq_worker **pw)
{
	struct threadq_worker *w = *pw;

	pthread_mutex_destroy(&w->m);
	pthread_cond_destroy(&w->c);
	free(w);

	*pw = NULL;
}

void
threadq_worker_send_work(struct threadq_worker *w, void *data)
{
	pthread_mutex_lock(&w->m);
	w->data = data;
	w->running = true;
	pthread_cond_signal(&w->c);
	pthread_mutex_unlock(&w->m);
}

void *
threadq_worker_recv_work(struct threadq_worker *w)
{
	pthread_mutex_lock(&w->m);
	while (!w->running)
		pthread_cond_wait(&w->c, &w->m);
	pthread_mutex_unlock(&w->m);
	return w->data;
}

void
threadq_worker_send_result(struct threadq_worker *w, void *data)
{
	pthread_mutex_lock(&w->m);
	w->data = data;
	w->running = false;
	pthread_cond_signal(&w->c);
	pthread_mutex_unlock(&w->m);
}

void *
threadq_worker_recv_result(struct threadq_worker *w)
{
	pthread_mutex_lock(&w->m);
	while (w->running)
		pthread_cond_wait(&w->c, &w->m);
	pthread_mutex_unlock(&w->m);
	return w->data;
}

void
threadq_add(struct threadq *q, struct threadq_worker *w)
{
	pthread_mutex_lock(&q->m);
	w->next = NULL;
	if (q->head == NULL)
		pthread_cond_signal(&q->c);
	*q->ptail = w;
	q->ptail = &w->next;
	pthread_mutex_unlock(&q->m);
}

struct threadq_worker *
threadq_next(struct threadq *q)
{
	struct threadq_worker *w;

	pthread_mutex_lock(&q->m);
	while (q->head == NULL)
		pthread_cond_wait(&q->c, &q->m);
	w = q->head;
	q->head = q->head->next;
	if (q->head == NULL)
		q->ptail = &q->head;
	pthread_mutex_unlock(&q->m);

	return w;
}
