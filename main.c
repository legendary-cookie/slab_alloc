#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct kmem_bufctl {
  struct kmem_bufctl *next;
  void *ptr;
  struct kmem_slab *parent_slab;
};

struct kmem_slab {
  struct kmem_slab *next, *prev;
  struct kmem_bufctl *freelist;
  int refcount;
};

struct kmem_cache {
  size_t size;
  size_t bufctl_object_size;
  char *name;
  struct kmem_slab *nodes;
};

struct kmem_slab *kmem_slab_create(struct kmem_cache *cache) {
  struct kmem_bufctl *buf = (struct kmem_bufctl *)malloc(4096);
  if (!buf)
    return NULL;

  buf->next = NULL;

  struct kmem_slab *slab =
      (struct kmem_slab *)(((uintptr_t)buf + 4096) - sizeof(struct kmem_slab));

  slab->next = NULL;
  slab->refcount = 0;
  slab->freelist = buf;

  if (!cache->nodes) {
    cache->nodes = slab;
  } else {
    slab->next = cache->nodes;
    cache->nodes = slab;
  }

  return slab;
}

bool kmem_cache_grow(struct kmem_cache *cache, int count) {
  for (int i = 0; i < count; i++) {
    struct kmem_slab *slab = kmem_slab_create(cache);

    struct kmem_bufctl *buf = slab->freelist;

    size_t elements = cache->bufctl_object_size / cache->size;
    struct kmem_bufctl *tail = buf;

    for (int i = 0; i < elements; i++) {
      uintptr_t offset = ((uintptr_t)buf) + (cache->size * i);
      struct kmem_bufctl *new = (struct kmem_bufctl *)offset;
      new->parent_slab = slab;
      new->ptr = (void *)offset;

      if (!tail)
        buf = new;
      else
        tail->next = new;

      tail = new;
    }

    tail->next = NULL;
  }

  return true;
}

struct kmem_cache *kmem_cache_create(char *name, size_t size) {
  struct kmem_cache *cache = (struct kmem_cache *)malloc(4096);

  cache->name = name;
  cache->size = size;
  cache->bufctl_object_size = 4096 - sizeof(struct kmem_cache);
  cache->nodes = NULL;

  kmem_cache_grow(cache, 1);

  return cache;
}

void *kmem_cache_alloc(struct kmem_cache *cache) {
  if (!cache || !cache->nodes)
    return NULL;

  for (struct kmem_slab *slab = cache->nodes; slab != NULL; slab = slab->next) {
    if (!slab->freelist)
      continue;

    void *ptr = slab->freelist->ptr;

    slab->freelist = slab->freelist->next;

    slab->refcount++;
    return ptr;
  }

  bool success = kmem_cache_grow(cache, 1);
  if (!success) {
    return NULL;
  }

  return kmem_cache_alloc(cache);
}

void kmem_cache_free(struct kmem_cache *cache, void *ptr) {
  if (!ptr || !cache)
    return;

  for (struct kmem_slab *slab = cache->nodes; slab != NULL; slab = slab->next) {
    if (!slab->freelist)
      continue;

    slab->refcount--;

    *((void **)ptr) = slab->freelist;
    slab->freelist = ptr;
    return;
  }
}

void kmem_cache_destroy(struct kmem_cache *cache) {
  if (!cache)
    return;

  for (struct kmem_slab *slab = cache->nodes; slab != NULL; slab = slab->next) {
    if (slab->refcount != 0) {
      printf("TRIED TO FREE SLAB IN USE!\n");
      for (;;) {
      }
    }

    free(slab->freelist);
  }
  memset(cache, 0, sizeof(struct kmem_cache));
  free((void *)cache);
}

int main() {
  struct kmem_cache *c = kmem_cache_create("test", 32);
  for (size_t i = 0; i < 10; i++) {
    void *p = kmem_cache_alloc(c);
    kmem_cache_free(c, p);
  }
  kmem_cache_destroy(c);
  return 0;
}
