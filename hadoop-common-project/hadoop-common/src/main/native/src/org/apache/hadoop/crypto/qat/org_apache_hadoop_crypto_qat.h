/*
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

#ifndef ORG_APACHE_HADOOP_CRYPTO_QAT_H
#define ORG_APACHE_HADOOP_CRYPTO_QAT_H

#include "org_apache_hadoop_crypto.h"

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"

#include "qat_utils.h"

/* Qat ctx structure declaration */
typedef struct qat_ctx_t
{
  CpaCySymSessionCtx sessionCtx;     /* session context */
  CpaInstanceHandle instanceHandle;

  /* the memory for the private meta data must be allocated as contiguous
   * memory. The cpaCyBufferListGetMetaSize() will return the size (in
   * bytes) for memory allocation routine to allocate the private meta data
   * memory
   */
  void *pSrcMetaData;   /* source meta data pointer */
  void *pDstMetaData;   /* destination meta data pointer */

  void* iv;
  int ivLength;

  struct CpaBufferListQueue *bufferListQueue;
  struct CpaCySymOpDataQueue *opDataQueue;

  int padding_len;

  CpaFlatBuffer* paddingFlatBuffer[IV_LENGTH];
} qat_ctx;

struct op_done
{
  pthread_mutex_t mutex;
  pthread_cond_t cond;

  int numReq;
  int numResp;

  char *output;
  int output_offset;

  int padding_len;
  qat_ctx *context;
};

#define QATCONTEXT(context) ((qat_ctx*)((ptrdiff_t)(context)))
#define QAT_CRYPTO_NUM_POLLING_RETRIES 5
#define POLL_PERIOD_IN_NS 100
#define QAT_RETRY_BACKOFF_MODULO_DIVISOR 8

#endif //ORG_APACHE_HADOOP_CRYPTO_QAT_H
