/*
 * Copyright (c) 2012, 2014-2016 by Farsight Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mtbl-private.h"
#include "bytes.h"

#include <pthread.h>
#include "threadq.h"

#include "libmy/ubuf.h"

struct mtbl_writer_options {
	mtbl_compression_type		compression_type;
	int				compression_level;
	size_t				block_size;
	size_t				block_restart_interval;
	size_t				thread_count;
};

struct mtbl_writer {
	int				fd;
	struct mtbl_metadata		m;
	struct block_builder		*data;
	struct block_builder		*index;

	struct mtbl_writer_options	opt;

	size_t				open_thread_count;
	struct threadq*			ready_threads;
	struct threadq*			writing_threads;
	pthread_t			writer_thread;

	ubuf				*last_key;
	uint64_t			last_offset;

	bool				closed;
	bool				pending_index_entry;
	uint64_t			pending_offset;
};

struct mtbl_writer_compression_job {
	mtbl_compression_type	comp_type;
	int			comp_level;

	uint8_t*		raw_block;
	size_t			raw_block_size;
};

struct mtbl_writer_compression_result {
	uint8_t*		comp_block;
	size_t			comp_block_size;
};

static void _mtbl_writer_finish(struct mtbl_writer *);
static void _mtbl_writer_flush(struct mtbl_writer *);
static void _mtbl_writer_writeblock(
	struct mtbl_writer *,
	struct block_builder *,
	mtbl_compression_type, 
	bool is_index_block);

static size_t _write_block(int fd, uint8_t *block, size_t block_size);
static void _write_all(int fd, const uint8_t *block, size_t block_size);
static void _compress_block(
	uint8_t *src_block,
	size_t src_size,
	uint8_t **dst_block,
	size_t *dst_size,
	mtbl_compression_type,
	int comp_level);
static void _update_metadata(
	struct mtbl_writer *,
	size_t bytes_written,
	bool is_index_block);

static void* _mtbl_writer_compressionthread(void *worker_thread);
static void* _mtbl_writer_writerthread(void *writer);
static void _mtbl_writer_shutdown_threads(struct mtbl_writer *);
static void _mtbl_writer_start_threads(struct mtbl_writer *);

struct mtbl_writer_options *
mtbl_writer_options_init(void)
{
	struct mtbl_writer_options *opt;
	opt = my_calloc(1, sizeof(*opt));
	opt->compression_type = DEFAULT_COMPRESSION_TYPE;
	opt->compression_level = DEFAULT_COMPRESSION_LEVEL;
	opt->block_size = DEFAULT_BLOCK_SIZE;
	opt->block_restart_interval = DEFAULT_BLOCK_RESTART_INTERVAL;
	opt->thread_count = DEFAULT_WRITER_THREAD_COUNT;
	return (opt);
}

void
mtbl_writer_options_destroy(struct mtbl_writer_options **opt)
{
	if (*opt) {
		free(*opt);
		*opt = NULL;
	}
}

void
mtbl_writer_options_set_compression(struct mtbl_writer_options *opt,
				    mtbl_compression_type compression_type)
{
	assert(compression_type == MTBL_COMPRESSION_NONE	||
	       compression_type == MTBL_COMPRESSION_SNAPPY	||
	       compression_type == MTBL_COMPRESSION_ZLIB	||
	       compression_type == MTBL_COMPRESSION_LZ4		||
	       compression_type == MTBL_COMPRESSION_LZ4HC	||
	       compression_type == MTBL_COMPRESSION_ZSTD
	);
	opt->compression_type = compression_type;
}

void
mtbl_writer_options_set_compression_level(struct mtbl_writer_options *opt,
					  int compression_level)
{
	opt->compression_level = compression_level;
}

void
mtbl_writer_options_set_block_size(struct mtbl_writer_options *opt,
				   size_t block_size)
{
	if (block_size < MIN_BLOCK_SIZE)
		block_size = MIN_BLOCK_SIZE;
	opt->block_size = block_size;
}

void
mtbl_writer_options_set_block_restart_interval(struct mtbl_writer_options *opt,
					       size_t block_restart_interval)
{
	opt->block_restart_interval = block_restart_interval;
}

void
mtbl_writer_options_set_thread_count(struct mtbl_writer_options *opt,
				     size_t thread_count)
{
	opt->thread_count = thread_count;
}

struct mtbl_writer *
mtbl_writer_init_fd(int orig_fd, const struct mtbl_writer_options *opt)
{
	struct mtbl_writer *w;
	int fd;

	fd = dup(orig_fd);
	assert(fd >= 0);
	w = my_calloc(1, sizeof(*w));
	if (opt == NULL) {
		w->opt.compression_type = DEFAULT_COMPRESSION_TYPE;
		w->opt.compression_level = DEFAULT_COMPRESSION_LEVEL;
		w->opt.block_size = DEFAULT_BLOCK_SIZE;
		w->opt.block_restart_interval = DEFAULT_BLOCK_RESTART_INTERVAL;
		w->opt.thread_count = DEFAULT_WRITER_THREAD_COUNT;
	} else {
		memcpy(&w->opt, opt, sizeof(*opt));
	}
	w->fd = fd;
	// Start writing from the current offset. This allows mtbl's callers
	// to reserve some initial bytes in the file.
	w->last_offset = lseek(fd, 0, SEEK_CUR);
	w->pending_offset = w->last_offset;
	w->last_key = ubuf_init(256);
	w->m.file_version = MTBL_FORMAT_V2;
	w->m.compression_algorithm = w->opt.compression_type;
	w->m.data_block_size = w->opt.block_size;
	w->data = block_builder_init(w->opt.block_restart_interval);
	w->index = block_builder_init(w->opt.block_restart_interval);

	// Create compression thread queues and a writer thread.
	if (w->opt.thread_count > 0)
		_mtbl_writer_start_threads(w);

	return (w);
}

struct mtbl_writer *
mtbl_writer_init(const char *fname, const struct mtbl_writer_options *opt)
{
	struct mtbl_writer *w;
	int fd;

	fd = open(fname, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0644);
	if (fd < 0)
		return (NULL);
	w = mtbl_writer_init_fd(fd, opt);
	close(fd);
	return (w);
}

void
mtbl_writer_destroy(struct mtbl_writer **w)
{
	if (*w == NULL) return;

	if (!(*w)->closed) {	
		_mtbl_writer_finish(*w);
		close((*w)->fd);
	}

	block_builder_destroy(&((*w)->data));
	block_builder_destroy(&((*w)->index));
	ubuf_destroy(&(*w)->last_key);

	free(*w);
	*w = NULL;
}

mtbl_res
mtbl_writer_add(struct mtbl_writer *w,
		const uint8_t *key, size_t len_key,
		const uint8_t *val, size_t len_val)
{
	assert(!w->closed);
	if (w->m.count_entries > 0) {
		if (!(bytes_compare(key, len_key,
				    ubuf_data(w->last_key), ubuf_size(w->last_key)) > 0))
		{
			return (mtbl_res_failure);
		}
	}

	size_t estimated_block_size = block_builder_current_size_estimate(w->data);
	estimated_block_size += 3*5 + len_key + len_val;

	if (estimated_block_size >= w->opt.block_size)
		_mtbl_writer_flush(w);

	if (w->pending_index_entry) {
		uint8_t enc[10];
		size_t len_enc;
		assert(block_builder_empty(w->data));
		bytes_shortest_separator(w->last_key, key, len_key);
		len_enc = mtbl_varint_encode64(enc, w->last_offset);
		/*
		fprintf(stderr, "%s: writing index entry, key= '%s' (%zd) val= %" PRIu64 "\n",
			__func__, ubuf_data(w->last_key), ubuf_size(w->last_key), w->last_offset);
		*/
		block_builder_add(w->index,
				  ubuf_data(w->last_key), ubuf_size(w->last_key),
				  enc, len_enc);
		w->pending_index_entry = false;
	}

	ubuf_reset(w->last_key);
	ubuf_append(w->last_key, key, len_key);

	w->m.count_entries += 1;
	w->m.bytes_keys += len_key;
	w->m.bytes_values += len_val;
	block_builder_add(w->data, key, len_key, val, len_val);
	return (mtbl_res_success);
}

static void
_mtbl_writer_finish(struct mtbl_writer *w)
{
	_mtbl_writer_flush(w);
	assert(!w->closed);
	w->closed = true;

	if (w->pending_index_entry) {
		/* XXX use short successor */
		uint8_t enc[10];
		size_t len_enc;
		len_enc = mtbl_varint_encode64(enc, w->last_offset);
		/*
		fprintf(stderr, "%s: writing index entry, key= '%s' (%zd) val= %" PRIu64 "\n",
			__func__, ubuf_data(w->last_key), ubuf_size(w->last_key), w->last_offset);
		*/
		block_builder_add(w->index,
				  ubuf_data(w->last_key), ubuf_size(w->last_key),
				  enc, len_enc);
		w->pending_index_entry = false;
	}

	// Destroy our threads and write the final index block to disk.
	if (w->opt.thread_count > 0)
		_mtbl_writer_shutdown_threads(w);
	_mtbl_writer_writeblock(w, w->index, MTBL_COMPRESSION_NONE, true);
}

static void
_mtbl_writer_flush(struct mtbl_writer *w)
{
	assert(!w->closed);
	if (block_builder_empty(w->data))
		return;
	assert(!w->pending_index_entry);

	_mtbl_writer_writeblock(w, w->data, w->opt.compression_type, false);
	w->pending_index_entry = true;
}

static void
_mtbl_writer_writeblock(struct mtbl_writer *w,
			struct block_builder *b,
			mtbl_compression_type comp_type, 
			bool is_index_block)
{
	assert(w->m.file_version == MTBL_FORMAT_V2);

	/* If threading is disabled OR we are trying to write the index block 
	 * to disk, we will handle this block non-concurrently. */
	if (w->opt.thread_count == 0 || is_index_block) {
		
		uint8_t *raw_block = NULL;
		uint8_t *comp_block = NULL;
		size_t raw_size = 0;
		size_t comp_size = 0;

		// Compress, write to disk, and update metadata about the block.
		block_builder_finish(b, &raw_block, &raw_size);
		_compress_block(raw_block, raw_size, &comp_block, &comp_size, 
				comp_type, w->opt.compression_level);
		size_t bytes_written = _write_block(w->fd, comp_block, comp_size);
		_update_metadata(w, bytes_written, is_index_block);

		// Cleanup.
		block_builder_reset(b);
		free(raw_block);
		if (comp_type != MTBL_COMPRESSION_NONE)
			free(comp_block);
	} else {

		// Get the next available worker thread.
		struct threadq_worker *wrk = threadq_next(w->ready_threads);
		struct mtbl_writer_compression_job* job = calloc(1, sizeof(*job));

		// Prepare the job!
		job->comp_type = comp_type;
		job->comp_level = w->opt.compression_level;
		block_builder_finish(b, &job->raw_block, &job->raw_block_size);

		/* Once compression finishes, the writer thread will 
		 * automagically receive up the block and write it to disk. */
		threadq_worker_send_work(wrk, job);
		threadq_add(w->writing_threads, wrk); 
	}
}

static void
_compress_block(uint8_t* src_block,
		size_t src_size, 
		uint8_t** dst_block, 
		size_t* dst_size, 
		mtbl_compression_type comp_type, 
		int comp_level)
{
	mtbl_res res;

	if (comp_type == MTBL_COMPRESSION_NONE) {
		*dst_block = src_block;
		*dst_size = src_size;
		res = mtbl_res_success;

	} else if (comp_level == DEFAULT_COMPRESSION_LEVEL) {
		res = mtbl_compress(comp_type, src_block, src_size, dst_block, 
				    dst_size);
	} else {
		res = mtbl_compress_level(comp_type, comp_level, src_block, 
					  src_size, dst_block, dst_size);
	}

	assert(res == mtbl_res_success);
}

static size_t
_write_block(int fd, uint8_t *block, size_t block_size)
{
	const uint32_t crc = htole32(mtbl_crc32c(block, block_size));
	size_t len_length;
	uint8_t len[10];
	len_length = mtbl_varint_encode64(len, block_size);

	_write_all(fd, (const uint8_t *) len, len_length);
	_write_all(fd, (const uint8_t *) &crc, sizeof(crc));
	_write_all(fd, block, block_size);

	const size_t bytes_written = (len_length + sizeof(crc) + block_size);
	return bytes_written;
}

static void
_write_all(int fd, const uint8_t *buf, size_t size)
{
	assert(size > 0);

	while (size) {
		ssize_t bytes_written;

		bytes_written = write(fd, buf, size);
		if (bytes_written < 0 && errno == EINTR)
			continue;
		if (bytes_written <= 0) {
			fprintf(stderr, "%s: write() failed: %s\n", __func__,
				strerror(errno));
			assert(bytes_written > 0);
		}
		buf += bytes_written;
		size -= bytes_written;
	}
}

static void
_update_metadata(struct mtbl_writer *w, size_t bytes_written, bool is_index_block)
{
	w->last_offset = w->pending_offset;
	w->pending_offset += bytes_written;
	
	// Data blocks store different metadata than index blocks.
	if (!is_index_block) {
		w->m.bytes_data_blocks += bytes_written;
		w->m.count_data_blocks += 1;
	} else {
		w->m.index_block_offset = w->pending_offset - bytes_written;
		w->m.bytes_index_block = bytes_written;
		
		uint8_t tbuf[MTBL_METADATA_SIZE];
		metadata_write(&w->m, tbuf);
		_write_all(w->fd, tbuf, sizeof(tbuf));
	}
}

static void *
_mtbl_writer_compressionthread(void *arg)
{
	struct threadq_worker *wrk = arg;
	struct mtbl_writer_compression_job *job;
	struct mtbl_writer_compression_result *res;

	/* If we ever receive work == NULL, that means the shutdown signal 
	 * was passed to that thread (and there is no more work to be done). */
	while ((job = threadq_worker_recv_work(wrk)) != NULL) {
		if ((void *)job == THREADQ_SHUTDOWN) {
			threadq_worker_send_result(wrk, NULL);
			continue;
		}

		/* Copy data block from job to result, then compress the block 
		 * in result.  Finally, send the compressed block back to the 
		 * worker thread and dispose of the job block (if no compression 
		 * is used, the job's data_block pointer is reused in the result). */
		res = calloc(1, sizeof(*res));	
		_compress_block(
			job->raw_block,
			job->raw_block_size, 
			&res->comp_block,
			&res->comp_block_size, 
			job->comp_type,
			job->comp_level
		);
		threadq_worker_send_result(wrk, res);

		if (job->comp_type != MTBL_COMPRESSION_NONE)
			free(job->raw_block);
		free(job);
	}

	return NULL;
}

static void *
_mtbl_writer_writerthread(void *arg)
{
	struct mtbl_writer *w = arg;

	while (true) {

		struct threadq_worker *wrk;
		struct mtbl_writer_compression_result *res;

		/* Retrieve the next compressed block to be written to disk and 
		 * place its thread back into the ready queue. */
		wrk = threadq_next(w->writing_threads);
		res = threadq_worker_recv_result(wrk);
		threadq_add(w->ready_threads, wrk);

		// a NULL work result indicates that shutdown has started.
		if (res == NULL) {
			break;
		}

		/* Write block to disk and update mtbl_writer with the total 
		 * number of bytes written. */
		size_t bytes;
		bytes = _write_block(w->fd, res->comp_block, res->comp_block_size);
		_update_metadata(w, bytes, false);

		free(res->comp_block);
		free(res);
	}

	return NULL;
}

static void
_mtbl_writer_start_threads(struct mtbl_writer* w) {
	
	/* Ready thread queue -> Threads waiting to receive work.
	 * Writing thread queue -> Threads that have been sent work and are 
	 * 			   either still working or are waiting for their 
	 * 			   results to be received by the writer thread. */
	w->ready_threads = threadq_init();
	w->writing_threads = threadq_init();

	for (size_t i = 0; i < w->opt.thread_count; i++) {
		struct threadq_worker* wrk;
		wrk = threadq_worker_init(_mtbl_writer_compressionthread);
		threadq_add(w->ready_threads, wrk);
		w->open_thread_count++;
	}
	
	// The writer thread receives and writes finished data blocks to disk.
	pthread_create(&w->writer_thread, NULL, _mtbl_writer_writerthread, w);
}

static void
_mtbl_writer_shutdown_threads(struct mtbl_writer *w) {
	
	// Get the next available ready thread and send it the shutdown signal.
	struct threadq_worker* wrk_shutdown = threadq_next(w->ready_threads);
	threadq_worker_send_work(wrk_shutdown, THREADQ_SHUTDOWN);
	threadq_add(w->writing_threads, wrk_shutdown);

	pthread_join(w->writer_thread, NULL);
	
	/* Close all ready threads (threads in the writing queue will eventually 
	 * become ready). */
	while (w->open_thread_count > 0) {
		struct threadq_worker* wrk = threadq_next(w->ready_threads);
		threadq_worker_join(wrk);
		threadq_worker_destroy(&wrk);
		w->open_thread_count--;
	}

	threadq_destroy(&(w->ready_threads));
	threadq_destroy(&(w->writing_threads));
}
