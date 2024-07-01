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

	// Compression threads; see thread_count in mtbl_writer_options.
	size_t				open_thread_count;
	struct threadq*			ready_threads;
	struct threadq*			writing_threads;

	// Thread for copying compressed blocks into the writer.
	pthread_t			writer_thread;
	pthread_mutex_t			writer_m;
	pthread_cond_t			writer_c;

	ubuf				*last_key;
	uint64_t			last_offset;

	bool				closed;
	bool				pending_index_entry;
	uint64_t			pending_offset;
};

struct mtbl_writer_compression_job {
	bool			is_data_block;

	mtbl_compression_type	compression_type;
	int			compression_level;

	uint8_t*		raw_data;
	size_t			raw_data_size;
};

struct mtbl_writer_compression_result {
	bool			is_data_block;

	uint8_t*		compressed_data;
	size_t			compressed_data_size;
};

static void _mtbl_writer_finish(struct mtbl_writer *);
static void _mtbl_writer_flush(struct mtbl_writer *);
static void _write_all(int fd, const uint8_t *, size_t);

static void _mtbl_writer_writeblock(
	struct mtbl_writer *,
	struct block_builder *,
	mtbl_compression_type);
static void _mtbl_writer_writeblock_threads(
	struct mtbl_writer *, 
        struct block_builder *,
        mtbl_compression_type);
static void _mtbl_writer_writeblock_nothreads(
	struct mtbl_writer *, 
        struct block_builder *,
        mtbl_compression_type);

static void _mtbl_writer_compressblock(
	uint8_t *src_block,
	size_t src_size,
	uint8_t **dst_block,
	size_t *dst_size,
	mtbl_compression_type,
	int compression_level);

static void* _mtbl_writer_compressionthread(void *worker_thread);
static void* _mtbl_writer_writerthread(void *writer);
static void _mtbl_writer_shutdown_threads(struct mtbl_writer **);
static void _mtbl_writer_start_threads(struct mtbl_writer **);

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
		_mtbl_writer_start_threads(&w);

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
		if ((*w)->opt.thread_count > 0)
			_mtbl_writer_shutdown_threads(w);
		close((*w)->fd);
	}

	printf("Data blocks: %lu %lu\n", (*w)->m.bytes_data_blocks, (*w)->m.count_data_blocks);
	printf("Index block: %lu %lu\n", (*w)->m.bytes_index_block, (*w)->m.index_block_offset);

	block_builder_destroy(&((*w)->data));
	block_builder_destroy(&((*w)->index));
	ubuf_destroy(&(*w)->last_key);

	free(*w);
	*w = NULL;
	printf("Writer destroyed!\n");
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

	_mtbl_writer_writeblock(w, w->index, MTBL_COMPRESSION_NONE);
}

static void
_mtbl_writer_flush(struct mtbl_writer *w)
{
	assert(!w->closed);
	if (block_builder_empty(w->data))
		return;
	assert(!w->pending_index_entry);

	_mtbl_writer_writeblock(w, w->data, w->opt.compression_type);
	w->pending_index_entry = true;
}

static void
_mtbl_writer_writeblock(struct mtbl_writer *w,
			struct block_builder *b,
			mtbl_compression_type compression_type)
{
	assert(w->m.file_version == MTBL_FORMAT_V2);

	if (w->opt.thread_count == 0) {
		_mtbl_writer_writeblock_nothreads(w, b, compression_type);
	} else {
		_mtbl_writer_writeblock_threads(w, b, compression_type);
	}
}

static void
_mtbl_writer_writeblock_nothreads(struct mtbl_writer *w, 
                                  struct block_builder *b,
                        	  mtbl_compression_type compression_type)
{
	uint8_t *raw_contents = NULL, *block_contents = NULL;
	size_t raw_contents_size = 0, block_contents_size = 0;

	block_builder_finish(b, &raw_contents, &raw_contents_size);
	_mtbl_writer_compressblock(
		raw_contents,
		raw_contents_size, 
		&block_contents,
		&block_contents_size,
		compression_type,
		w->opt.compression_level
	);

	const uint32_t crc = htole32(mtbl_crc32c(block_contents, block_contents_size));
	size_t len_length;
	uint8_t len[10];
	len_length = mtbl_varint_encode64(len, block_contents_size);

	_write_all(w->fd, (const uint8_t *) len, len_length);
	_write_all(w->fd, (const uint8_t *) &crc, sizeof(crc));
	_write_all(w->fd, block_contents, block_contents_size);

	const size_t bytes_written = (len_length + sizeof(crc) + block_contents_size);
	w->last_offset = w->pending_offset;
	w->pending_offset += bytes_written;
	
	// Data blocks have different side-effects than index blocks.
	bool is_data_block = (w->data == b) ? true : false;
	if (is_data_block) {
		w->m.bytes_data_blocks += bytes_written;
		w->m.count_data_blocks += 1;
	} else {
		w->m.index_block_offset = w->pending_offset - bytes_written;
		w->m.bytes_index_block = bytes_written;
		
		uint8_t tbuf[MTBL_METADATA_SIZE];
		metadata_write(&w->m, tbuf);
		_write_all(w->fd, tbuf, sizeof(tbuf));
	}

	block_builder_reset(b);
	free(raw_contents);
	if (compression_type != MTBL_COMPRESSION_NONE)
		free(block_contents);
}

static void
_mtbl_writer_writeblock_threads(struct mtbl_writer *w, 
                        	struct block_builder *b,
                        	mtbl_compression_type compression_type)
{
	/* Send the next compression thread in the ready queue our current job, 
	 * then add it to the writing queue so it can be written to disk once 
	 * it has arrived at the top of the queue (and its work is done). */
	struct threadq_worker *wrk = threadq_next(w->ready_threads);
	struct mtbl_writer_compression_job* job = calloc(1, sizeof(*job));

	/* The index block's write has different side-effects than the data 
	 * blocks', so the writer thread must be made aware of this. */
	if (b == w->index) {
		job->is_data_block = false;
	} else {
		job->is_data_block = true;
	}

	job->compression_type = compression_type;
	job->compression_level = w->opt.compression_level;
	block_builder_finish(b, &job->raw_data, &job->raw_data_size);

	// printf("Job size when block built: %lu\n", job->raw_data_size);
	threadq_worker_send_work(wrk, job);
	threadq_add(w->writing_threads, wrk);
 
	/* Once compression finishes, the writer thread will automatically receive 
	 * up the block and write it to disk. */
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
		 * worker thread and dispose of the job block.  This result can 
		 * later be retrieved by calling threadq_worker_recv_result() 
		 * on this same worker thread. */
		res = calloc(1, sizeof(*res));
		
		printf("Compressing...\n");
		_mtbl_writer_compressblock(
			job->raw_data,
			job->raw_data_size, 
			&res->compressed_data,
			&res->compressed_data_size, 
			job->compression_type,
			job->compression_level
		);

		res->is_data_block = job->is_data_block;
		threadq_worker_send_result(wrk, res);
		
		// If no compression, the raw_data pointer is reused in res.
		if (job->compression_type != MTBL_COMPRESSION_NONE)
			free(job->raw_data);
		free(job);
		printf("Compressed!\n");
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

		if (res == NULL) {
			break;
		}

		/* Gather the compressed data the writer thread retrieved and write it 
		 * out to disk. */
		printf("Writing to disk...\n");

		const uint32_t crc = htole32(mtbl_crc32c(res->compressed_data, 
							 res->compressed_data_size));
		size_t len_length;
		uint8_t len[10];
		len_length = mtbl_varint_encode64(len, res->compressed_data_size);

		// printf("Block size when being written: %lu\n", w->data_block_size);
		_write_all(w->fd, (const uint8_t *) len, len_length);
		_write_all(w->fd, (const uint8_t *) &crc, sizeof(crc));
		_write_all(w->fd, res->compressed_data, res->compressed_data_size);

		const size_t bytes_written = (len_length + sizeof(crc) + res->compressed_data_size);

		w->last_offset = w->pending_offset;
		w->pending_offset += bytes_written;
	
		// Data blocks have different side-effects than the index block.
		if (res->is_data_block) {
			block_builder_reset(w->data);
			w->m.bytes_data_blocks += bytes_written;
			w->m.count_data_blocks += 1;
		} else {
			block_builder_reset(w->index);
			w->m.index_block_offset = w->pending_offset - bytes_written;
			w->m.bytes_index_block = bytes_written;
			
			uint8_t tbuf[MTBL_METADATA_SIZE];
			metadata_write(&w->m, tbuf);
			_write_all(w->fd, tbuf, sizeof(tbuf));
		}

		printf("Written to disk!\n");

		free(res->compressed_data);
		free(res);
	}

	printf("Writing has finished!\n");
	return NULL;
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
_mtbl_writer_compressblock(uint8_t* src_block,
			   size_t src_size, 
			   uint8_t** dst_block, 
			   size_t* dst_size, 
			   mtbl_compression_type compression_type, 
			   int compression_level)
{
	if (compression_type == MTBL_COMPRESSION_NONE) {
		*dst_block = src_block;
		*dst_size = src_size;

	} else if (compression_level == DEFAULT_COMPRESSION_LEVEL) {
		mtbl_res compression_result = mtbl_compress(
			compression_type,
			src_block,
			src_size,
			dst_block,
			dst_size
		);
		assert(compression_result == mtbl_res_success);
	} else {
		mtbl_res compression_result = mtbl_compress_level(
			compression_type,
			compression_level,
			src_block,
			src_size,
			dst_block,
			dst_size
		);
		assert(compression_result == mtbl_res_success);
	}
}

static void
_mtbl_writer_start_threads(struct mtbl_writer** w) {
	
	/* Ready thread queue -> All threads waiting to receive work.
	 * Writing thread queue -> Threads that have been sent work. */
	(*w)->ready_threads = threadq_init();
	(*w)->writing_threads = threadq_init();

	for (size_t i = 0; i < (*w)->opt.thread_count; i++) {
		struct threadq_worker* wrk = threadq_worker_init(_mtbl_writer_compressionthread);
		threadq_add((*w)->ready_threads, wrk);
		(*w)->open_thread_count++;
	}
	
	/* The writer thread takes finished work from the writing thread queue 
	 * and writes it to disk! */
	pthread_create(&(*w)->writer_thread, NULL, _mtbl_writer_writerthread, *w);
	pthread_mutex_init(&(*w)->writer_m, NULL);
	pthread_cond_init(&(*w)->writer_c, NULL);
	printf("Created %lu compression threads!\n", (*w)->open_thread_count);
}

static void
_mtbl_writer_shutdown_threads(struct mtbl_writer** w) {
	
	// Get the next available ready thread and send it the shutdown signal.
	struct threadq_worker* wrk_shutdown = threadq_next((*w)->ready_threads);
	threadq_worker_send_work(wrk_shutdown, THREADQ_SHUTDOWN);
	threadq_add((*w)->writing_threads, wrk_shutdown);

	pthread_join((*w)->writer_thread, NULL);
	pthread_mutex_destroy(&(*w)->writer_m);
	pthread_cond_destroy(&(*w)->writer_c);
	
	// Close all ready threads (writing threads will eventually become ready).
	while ((*w)->open_thread_count > 0) {
		struct threadq_worker* wrk = threadq_next((*w)->ready_threads);
		threadq_worker_join(wrk);
		threadq_worker_destroy(&wrk);
		(*w)->open_thread_count--;
	}
	threadq_destroy(&((*w)->ready_threads));
	threadq_destroy(&((*w)->writing_threads));
}
