/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "qat_mem_utils.h"

#include <pthread.h>
#include "org_apache_hadoop.h"

static int mem_inited = 0;
static int ref_count = 0;
static pthread_mutex_t mem_mutex = PTHREAD_MUTEX_INITIALIZER;

#ifdef UNIX
static CpaStatus (*dlsym_osalMemInitialize)(char* path);
static void* (*dlsym_osalMemAllocContiguousNUMA)(UINT32 size, UINT32 node, UINT32 alignment);
static void (*dlsym_osalMemFreeNUMA)(void* ptr);
static UINT64 (*dlsym_osalVirtToPhysNUMA)(void* pVirtAddress);
static void (*dlsym_osalMemDestroy)(void);
#endif

void loadQatMemSymbols(JNIEnv *env, void *qat)
{
#ifdef UNIX
  dlerror();  // Clear any existing error
  LOAD_DYNAMIC_SYMBOL(dlsym_osalMemInitialize, env, qat,  \
                      "osalMemInitialize");
  LOAD_DYNAMIC_SYMBOL(dlsym_osalMemAllocContiguousNUMA, env, qat,  \
                      "osalMemAllocContiguousNUMA");
  LOAD_DYNAMIC_SYMBOL(dlsym_osalMemFreeNUMA, env, qat,  \
                      "osalMemFreeNUMA");
  LOAD_DYNAMIC_SYMBOL(dlsym_osalVirtToPhysNUMA, env, qat,  \
                      "osalVirtToPhysNUMA");
  LOAD_DYNAMIC_SYMBOL(dlsym_osalMemDestroy, env, qat,  \
                      "osalMemDestroy");
#endif

  jthrowable jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError",  \
        "Cannot load Intel QuickAssist Technology library.");
    return;
  }
}

static CpaStatus cryptoMemInit(void)
{
  CpaStatus status = CPA_STATUS_SUCCESS;

  pthread_mutex_lock(&mem_mutex);

  if (!mem_inited) {
    mem_inited = 1;
    ref_count = 0;
    status = dlsym_osalMemInitialize(NULL);
  }

  pthread_mutex_unlock(&mem_mutex);

  return status;
}

static void cryptoMemDestroy(void)
{
  pthread_mutex_lock(&mem_mutex);

  if (mem_inited) {
    mem_inited = 0;
    dlsym_osalMemDestroy();
  }

  pthread_mutex_unlock(&mem_mutex);
}

void *cryptoMemAlloc(size_t memsize)
{
  CpaStatus status = CPA_STATUS_SUCCESS;

  if (!mem_inited) {
    status = cryptoMemInit();
    if (status != CPA_STATUS_SUCCESS) {
      return NULL;
    }
  }

  pthread_mutex_lock(&mem_mutex);
  ref_count++;
  pthread_mutex_unlock(&mem_mutex);

  return dlsym_osalMemAllocContiguousNUMA(memsize, 0, QAT_BYTE_ALIGNMENT);
}

void cryptoMemFree(void* ptr)
{
  pthread_mutex_lock(&mem_mutex);

  if ((NULL != ptr) && mem_inited) {
    dlsym_osalMemFreeNUMA(ptr);
    ref_count--;
  }

  pthread_mutex_unlock(&mem_mutex);

  if (ref_count == 0 && mem_inited) {
    cryptoMemDestroy();
  }
}

void *copyAllocMemory(void *ptr, size_t size)
{
  void *nptr;

  if ((nptr = cryptoMemAlloc(size)) == NULL) {
    return NULL;
  }
  memcpy(nptr, ptr, size);
  return nptr;
}

void copyFreeMemory(void *uptr, void *kptr, int size)
{
  memcpy (uptr, kptr, size);
  cryptoMemFree(kptr);
}

CpaPhysicalAddr cryptoMemV2P(void *v)
{
  return (CpaPhysicalAddr)dlsym_osalVirtToPhysNUMA(v);
}
