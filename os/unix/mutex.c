/*
 * Copyright (c) 2016 Sound <sound@sagaforce.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
#include <stdlib.h>
#include <pthread.h>
#include "os/mutex.h"

struct mutex_data
{
	pthread_mutex_t mutex;
};

os_mutex_t os_mutex_create()
{
	struct mutex_data *data = (struct mutex_data *)malloc(sizeof(struct mutex_data));
	if(!data) return NULL;
	
	if(pthread_mutex_init(&data->mutex, NULL) != 0) return NULL;
	
	return data;
}

void os_mutex_destroy(os_mutex_t mutex)
{
	struct mutex_data *data = (struct mutex_data *)mutex;
	
	pthread_mutex_destroy(&data->mutex);
	
	free(data);
}

int os_mutex_lock(os_mutex_t mutex)
{
	struct mutex_data *data = (struct mutex_data *)mutex;
	return pthread_mutex_lock(&data->mutex);
}

int os_mutex_unlock(os_mutex_t mutex)
{
	struct mutex_data *data = (struct mutex_data *)mutex;
	return pthread_mutex_unlock(&data->mutex);
}
