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

#include "org_apache_hadoop_crypto_qat.h"
#include "qat_mem_utils.h"
#include "qat_parseconf.h"
#include "org_apache_hadoop_crypto_qat_QatCipher.h"

#include <string.h>
#include <pthread.h>
#include <unistd.h>

#define PACKET_SIZE (64 * 1024)

DEFINE_INIT_QUEUE(CpaBufferList)
DEFINE_INIT_QUEUE(CpaCySymOpData)
DEFINE_CLEAR_QUEUE(CpaBufferList)
DEFINE_CLEAR_QUEUE(CpaCySymOpData)
DEFINE_ENQUEUE(CpaBufferList)
DEFINE_ENQUEUE(CpaCySymOpData)
DEFINE_DEQUEUE(CpaBufferList)
DEFINE_DEQUEUE(CpaCySymOpData)

#ifdef UNIX
static CpaStatus (*dlsym_cpaCySymPerformOp)(const CpaInstanceHandle, void *,  \
                  const CpaCySymOpData *, const CpaBufferList *, CpaBufferList *,  \
                  CpaBoolean *);
static CpaStatus (*dlsym_icp_sal_userStartMultiProcess)(const char *pProcessName,  \
                  CpaBoolean limitDevAccess);
static CpaStatus (*dlsym_icp_sal_userStop)(void);
static CpaStatus (*dlsym_cpaCyGetNumInstances)(Cpa16U *pNumInstances);
static CpaStatus (*dlsym_cpaCyGetInstances)(Cpa16U numInstances,  \
                  CpaInstanceHandle *cyInstances);
static CpaStatus (*dlsym_cpaCySetAddressTranslation)(const CpaInstanceHandle instanceHandle,  \
                  CpaVirtualToPhysical virtual2Physical);
static CpaStatus (*dlsym_cpaCyStartInstance)(CpaInstanceHandle instanceHandle);
static CpaStatus (*dlsym_cpaCySymSessionCtxGetSize)(const CpaInstanceHandle instanceHandle,  \
                  const CpaCySymSessionSetupData *pSessionSetupData,  \
                  Cpa32U *pSessionCtxSizeInBytes);
static CpaStatus (*dlsym_cpaCySymInitSession)(const CpaInstanceHandle instanceHandle,  \
                  const CpaCySymCbFunc pSymCb,  \
                  const CpaCySymSessionSetupData *pSessionSetupData,  \
                  CpaCySymSessionCtx sessionCtx);
static CpaStatus (*dlsym_cpaCyBufferListGetMetaSize)(const CpaInstanceHandle instanceHandle,  \
                  Cpa32U numBuffers,  \
                  Cpa32U *pSizeInBytes);
static CpaStatus (*dlsym_icp_sal_CyPollInstance)(CpaInstanceHandle instanceHandle,  \
                  Cpa32U response_quota);
static void *qat = NULL;
#endif

CpaInstanceHandle *qatInstanceHandles = NULL;
static Cpa16U numInstances = 0;
static int currInst = 0;
static pthread_mutex_t qat_instance_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_t *icp_polling_threads;

void calculateIV(unsigned char* initIV, long counter, unsigned char* IV) {
  int i = IV_LENGTH; // IV length
  int j = 0; // counter bytes index
  int sum = 0;
  while (i-- > 0) {
    sum = ((*(initIV + i)) & 0xff) + (sum >> 8);
    if (j++ < 8) {
      sum += counter & 0xff;
      counter >>= 8;
    }
    *(IV + i) = (unsigned char*) sum;
  }
}

void initOpDone(struct op_done *opDone) 
{
  int sts = 1;

  if (!opDone) {
    return;
  }

  sts = pthread_mutex_init(&(opDone->mutex), NULL);
  if (sts != 0) {
    printf("pthread_mutex_init failed - sts = %d. Continuing anyway.\n", sts);
  }
  sts = pthread_cond_init(&(opDone->cond), NULL);
  if (sts != 0) {
    printf("pthread_cond_init failed - sts = %d. Continuing anyway.\n", sts);
  }
  opDone->numResp = 0;
  opDone->numReq = 0;
  opDone->output = NULL;
  opDone->output_offset = 0;
  opDone->context = NULL;
  opDone->padding_len = 0;
}

void cleanupOpDone(struct op_done *opDone) 
{
  int sts = 1;

  if (!opDone) {
    return;
  }

  sts = pthread_mutex_destroy(&(opDone->mutex));
  if (sts != 0) {
    printf("pthread_mutex_destroy failed - sts = %d. Continuing anyway. %d\n", sts, errno);
  }
  sts = pthread_cond_destroy(&(opDone->cond));
  if (sts != 0) {
    printf("pthread_cond_destroy failed - sts = %d. Continuing anyway.\n", sts);
  }
}

int waitForOpToComplete(struct op_done *opDone, int loopNum) 
{
  struct timespec ts;
  int rc=1;
  int timer_rc = 0;

  if (!opDone) {
    return rc;
  }

  rc = pthread_mutex_lock(&(opDone->mutex));
  if (rc != 0) {
    printf("pthread_mutex_lock failed - rc = %d.\n", rc);
    return 1;
  }

  clock_gettime(CLOCK_REALTIME, &ts);
  ts.tv_sec += 5;
  while (opDone->numResp != loopNum) {
    timer_rc = pthread_cond_timedwait(&(opDone->cond), &(opDone->mutex), &ts);
    if (timer_rc != 0) {
      printf("pthread_cond_timedwait: %s, opDone->numResp: %d, loopNum: %d\n",
          strerror(timer_rc), opDone->numResp, loopNum);
      break;
    }
  }
  rc = pthread_mutex_unlock(&(opDone->mutex));
  if (rc != 0) {
    printf("pthread_mutex_unlock failed - rc = %d\n", rc);
  }
  if (rc || timer_rc)
    return 1;
  return 0;
}

void qat_crypto_callbackFn(void *callbackTag, CpaStatus status,
                    const CpaCySymOp operationType, void *pOpData,
                    CpaBufferList *pDstBuffer, CpaBoolean verifyResult)
{
  struct op_done *opDone = (struct op_done *)callbackTag;
  int sts = 1;

  if (!opDone) {
    return;
  }

  sts = pthread_mutex_lock(&(opDone->mutex));
  if (sts != 0) {
    printf("pthread_mutex_lock failed - sts = %d. Continuing anyway.\n", sts);
  }

  opDone->numResp++;
  if (!zero_copy) {
    memcpy(opDone->output + opDone->output_offset,
        pDstBuffer->pBuffers[0].pData + opDone->padding_len,
        pDstBuffer->pBuffers[0].dataLenInBytes - opDone->padding_len);
  }
  opDone->output_offset += (pDstBuffer->pBuffers[0].dataLenInBytes - opDone->padding_len);
  opDone->padding_len = 0;

  ENQUEUE(opDone->context->opDataQueue, pOpData, CpaCySymOpData);
  ENQUEUE(opDone->context->bufferListQueue, pDstBuffer, CpaBufferList);

  if (opDone->numReq == opDone->numResp) {
    sts = pthread_cond_signal(&(opDone->cond));
    if (sts != 0) {
      printf("pthread_cond_signal failed - sts = %d. Continuing anyway.\n", sts);
    }
  }

  sts = pthread_mutex_unlock(&(opDone->mutex));
  if (sts != 0) {
    printf("pthread_mutex_unlock failed - sts = %d. Continuing anyway.\n", sts);
  }
}

static void thread_bind(pthread_t *thread, int coreID) 
{
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(coreID, &cpuset);

  pthread_setaffinity_np(*thread, sizeof(cpu_set_t), &cpuset);
}

/* Translates virtual address to hardware physical address */
static CpaPhysicalAddr realVirtualToPhysical(void *virtualAddr)
{
  return cryptoMemV2P(virtualAddr);
}

static inline void incr_curr_inst(void)
{
  pthread_mutex_lock(&qat_instance_mutex);
  currInst = (currInst + 1) % numInstances;
  pthread_mutex_unlock(&qat_instance_mutex);
}

static CpaInstanceHandle get_next_inst(void)
{
  CpaInstanceHandle instanceHandle;
  instanceHandle = qatInstanceHandles[currInst];
  incr_curr_inst();
  return instanceHandle;
}

static unsigned long int getQatPollInterval(void)
{
  return POLL_PERIOD_IN_NS;
}

static void *sendPoll_ns(void *ih)
{
  CpaInstanceHandle instanceHandle;
  struct timespec reqTime;
  struct timespec remTime;
  unsigned int retry_count = 0; /*to prevent too much time drift*/

  instanceHandle = (CpaInstanceHandle) ih;
  if (instanceHandle == NULL) {
    return NULL;
  }

  reqTime.tv_sec = 0;

  while (1) {
    reqTime.tv_nsec = getQatPollInterval();
    /* Poll for 0 means process all packets on the instance */
    dlsym_icp_sal_CyPollInstance(instanceHandle, 0);

    retry_count = 0;
    do {
      retry_count++;
      nanosleep(&reqTime, &remTime);
      reqTime.tv_nsec = remTime.tv_nsec;
      if (unlikely((errno < 0) && (EINTR != errno))) {
        // WARN("WARNING nanosleep system call failed: errno %i\n", errno);
        break;
      }
    } while ((retry_count <= QAT_CRYPTO_NUM_POLLING_RETRIES) && (errno == EINTR));
  }

  return NULL;
}

void createPollingThread(pthread_t *pollingThread, CpaInstanceHandle instanceHandle)
{
  pthread_attr_t attr;
  CpaStatus cpaStatus = CPA_STATUS_FAIL;
  CpaInstanceInfo2 instanceInfo2;
  struct sched_param param;
  int status = pthread_attr_init(&attr);
  if (status != 0) {
    goto create_thread;
  }
  status = pthread_attr_setinheritsched(&attr, PTHREAD_EXPLICIT_SCHED);
  if (status != 0) {
    pthread_attr_destroy(&attr);
    goto create_thread;
  }
  status = pthread_attr_setschedpolicy(&attr, SCHED_OTHER);
  if (status != 0) {
    pthread_attr_destroy(&attr);
    goto create_thread;
  }

  memset(&param, 0, sizeof(param));
  param.sched_priority = 0;
  status = pthread_attr_setschedparam(&attr, &param);
  if (status != 0) {
    pthread_attr_destroy(&attr);
    goto create_thread;
  }
  status = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
  if (status != 0) {
    pthread_attr_destroy(&attr);
    goto create_thread;
  }

  status = pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
  if (status != 0) {
    pthread_attr_destroy(&attr);
    goto create_thread;
  }

create_thread:
  if (status == 0) {
    pthread_create(pollingThread, &attr, sendPoll_ns, instanceHandle);
    pthread_attr_destroy(&attr);
  } else {
    pthread_create(pollingThread, NULL, sendPoll_ns, instanceHandle);
  }

  cpaStatus = cpaCyInstanceGetInfo2(instanceHandle, &instanceInfo2);
  if (cpaStatus == CPA_STATUS_SUCCESS) {
    thread_bind(pollingThread, instanceInfo2.nodeAffinity);
  } else {
    thread_bind(pollingThread, 0);
  }
} 

static void loadQatSymbols(JNIEnv *env)
{
  char msg[1000];
#ifdef UNIX
  qat = dlopen(HADOOP_QAT_LIBRARY, RTLD_LAZY | RTLD_GLOBAL);
#endif

  if (!qat) {
    snprintf(msg, sizeof(msg), "Cannot load %s (%s)!", HADOOP_QAT_LIBRARY,  \
        dlerror());
    THROW(env, "java/lang/UnsatisfiedLinkError", msg);
    return;
  }

#ifdef UNIX
  dlerror();  // Clear any existing error
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCySymPerformOp, env, qat,  \
                      "cpaCySymPerformOp");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCyGetNumInstances, env, qat,  \
                      "cpaCyGetNumInstances");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCyGetInstances, env, qat,  \
                      "cpaCyGetInstances");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCySetAddressTranslation, env, qat,  \
                      "cpaCySetAddressTranslation");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCyStartInstance, env, qat,  \
                      "cpaCyStartInstance");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCySymSessionCtxGetSize, env, qat,  \
                      "cpaCySymSessionCtxGetSize");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCySymInitSession, env, qat,  \
                      "cpaCySymInitSession");
  LOAD_DYNAMIC_SYMBOL(dlsym_cpaCyBufferListGetMetaSize, env, qat,  \
                      "cpaCyBufferListGetMetaSize");
  LOAD_DYNAMIC_SYMBOL(dlsym_icp_sal_userStartMultiProcess, env, qat,  \
                      "icp_sal_userStartMultiProcess");
  LOAD_DYNAMIC_SYMBOL(dlsym_icp_sal_userStop, env, qat,  \
                        "icp_sal_userStop");
  LOAD_DYNAMIC_SYMBOL(dlsym_icp_sal_CyPollInstance, env, qat,  \
                      "icp_sal_CyPollInstance");
#endif

  jthrowable jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->DeleteLocalRef(env, jthr);
    THROW(env, "java/lang/UnsatisfiedLinkError",  \
        "Cannot load Intel QuickAssist Technology library.");
    return;
  }
}

static void initQatInstances(JNIEnv *env, char* configSectionName)
{
  char msg[1000];
  int instNum;
  CpaStatus status = CPA_STATUS_SUCCESS;
  CpaBoolean limitDevAccess = CPA_FALSE;

  checkLimitDevAccessValue((int *)&limitDevAccess, configSectionName);

  /* Initialize the QAT hardware */
  status = dlsym_icp_sal_userStartMultiProcess(
      configSectionName, limitDevAccess);
  if (status != CPA_STATUS_SUCCESS) {
    snprintf(msg, sizeof(msg), "Error occurred when initialize QAT hardware, \
        icp_sal_userStartMultiProcess failed, status=%d.", status);
    THROW(env, "java/lang/InternalError", msg);
    return;
  }

  /* Get the number of available instances */
  status = dlsym_cpaCyGetNumInstances(&numInstances);
  if (status != CPA_STATUS_SUCCESS || numInstances <= 0) {
    snprintf(msg, sizeof(msg), "Error occurred when initialize QAT hardware, \
        cpaCyGetNumInstances failed, status=%d, numInstances=%d.",
        status, numInstances);
    THROW(env, "java/lang/InternalError", msg);
    return;
  }

  /* Allocate memory for the instance handle array */
  qatInstanceHandles = (CpaInstanceHandle *) malloc(
      numInstances * sizeof(CpaInstanceHandle));
  if (qatInstanceHandles == NULL) {
    THROW(env, "java/lang/OutOfMemoryError",
        "Error occurred when initialize QAT hardware, malloc failed for instance handles");
    return;
  }

  /* Allocate memory for the polling threads */
  icp_polling_threads = (pthread_t *) malloc(numInstances * sizeof(pthread_t));
  if (icp_polling_threads == NULL) {
    free(qatInstanceHandles);
    THROW(env, "java/lang/OutOfMemoryError",  \
        "Error occurred when initialize QAT hardware, malloc failed for polling threads");
    return;
  }

  /* Get the Crypto instances */
  status = dlsym_cpaCyGetInstances(numInstances, qatInstanceHandles);
  if (status != CPA_STATUS_SUCCESS) {
    free(qatInstanceHandles);
    free(icp_polling_threads);
    snprintf(msg, sizeof(msg), "Error occurred when initialize QAT hardware, \
        cpaCyGetInstances failed, status=%d.", status);
    THROW(env, "java/lang/InternalError", msg);
    return;
  }

  /* Set translation function and start each instance */
  for (instNum = 0; instNum < numInstances; instNum++) {
    /* Set the address translation function */
    status = dlsym_cpaCySetAddressTranslation(qatInstanceHandles[instNum],
        realVirtualToPhysical);
    if (status != CPA_STATUS_SUCCESS) {
      free(qatInstanceHandles);
      free(icp_polling_threads);
      snprintf(msg, sizeof(msg), "Error occurred when initialize QAT hardware, \
          cpaCySetAddressTranslation failed, status=%d.", status);
      THROW(env, "java/lang/InternalError", msg);
      return;
    }

    /* Start the instances */
    status = dlsym_cpaCyStartInstance(qatInstanceHandles[instNum]);
    if (status != CPA_STATUS_SUCCESS) {
      free(qatInstanceHandles);
      free(icp_polling_threads);
      snprintf(msg, sizeof(msg), "Error occurred when initialize QAT hardware, \
          cpaCyStartInstance failed, status=%d", status);
      THROW(env, "java/lang/InternalError", msg);
      return;
    }

    /* Create the polling threads */
    createPollingThread(&(icp_polling_threads[instNum]), qatInstanceHandles[instNum]);
  }

  currInst = 0;
}

JNIEXPORT void JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_initIDs
    (JNIEnv *env, jclass clazz, jbyteArray configSection)
{
  jbyte *jconfigSection = (*env)->GetByteArrayElements(env, configSection, NULL);
  if (jconfigSection == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get bytes array for configSection");
    return;
  }

  loadQatSymbols(env);
  loadQatMemSymbols(env, qat);
  initQatInstances(env, (char *)jconfigSection);

  (*env)->ReleaseByteArrayElements(env, configSection, jconfigSection, 0);

  jthrowable jthr = (*env)->ExceptionOccurred(env);
  if (jthr) {
    (*env)->Throw(env, jthr);
    return;
  }
}

static qat_ctx *qatCtxAlloc() {
  qat_ctx *context = (qat_ctx *) malloc(sizeof(qat_ctx));
  memset(context, 0, sizeof(qat_ctx));
  return context;
}

static void qatCtxCleanup(qat_ctx *context) {
  int i;

  if (context == NULL) {
    return;
  }

  if (context->sessionCtx) {
    cryptoMemFree(context->sessionCtx);
    context->sessionCtx = NULL;
  }
  if (context->pSrcMetaData) {
    cryptoMemFree(context->pSrcMetaData);
    context->pSrcMetaData = NULL;
  }
  if (context->pDstMetaData) {
      cryptoMemFree(context->pDstMetaData);
      context->pDstMetaData = NULL;
    }
  if (context->iv) {
    free(context->iv);
    context->iv = NULL;
  }

  CLEAR_QUEUE(context->bufferListQueue, CpaBufferList);
  context->bufferListQueue = NULL;
  CLEAR_QUEUE(context->opDataQueue, CpaCySymOpData);
  context->opDataQueue = NULL;

  for (i = 0; i < IV_LENGTH; i++) {
    if (context->paddingFlatBuffer[i] != NULL) {
      if (context->paddingFlatBuffer[i]->pData != NULL) {
        cryptoMemFree(context->paddingFlatBuffer[i]->pData);
      }
      free(context->paddingFlatBuffer[i]);
    }
  }
}

JNIEXPORT jlong JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_initContext
    (JNIEnv *env, jclass clazz, jint alg, jint padding)
{
  if (alg != AES_CTR) {
    THROW(env, "java/security/NoSuchAlgorithmException", NULL);
    return (jlong)0;
  }
  if (padding != NOPADDING) {
    THROW(env, "javax/crypto/NoSuchPaddingException", NULL);
    return (jlong)0;
  }

  // Create and initialize a qat_ctx
  qat_ctx *qatContext = qatCtxAlloc();
  if (qatContext == NULL) {
    THROW(env, "java/lang/OutOfMemoryError", NULL);
    return (jlong)0;
  }

  return JLONG(qatContext);
}

JNIEXPORT jlong JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_init
    (JNIEnv *env, jobject object, jlong ctx, jint mode, jint alg, jint padding,
    jbyteArray key, jbyteArray iv)
{
  qat_ctx *context = NULL;
  CpaCySymSessionSetupData *sessionSetupData = NULL;
  Cpa32U sessionCtxSize = 0;
  Cpa32U srcMetaSize = 0, dstMetaSize = 0;
  CpaInstanceHandle instanceHandle;
  CpaStatus status = 0;
  CpaCySymSessionCtx pSessionCtx = NULL;
  void *pSrcMetaData = NULL, *pDstMetaData = NULL;
  void *pIv = NULL;
  char errClass[100];
  char errMsg[200];
  int i = 0;
  int jKeyLen = (*env)->GetArrayLength(env, key);
  int jIvLen = (*env)->GetArrayLength(env, iv);
  if (jKeyLen != KEY_LENGTH_128 && jKeyLen != KEY_LENGTH_256) {
    snprintf(errClass, sizeof(errClass), "java/lang/IllegalArgumentException");
    snprintf(errMsg, sizeof(errMsg), "Invalid key length.");
    goto error;
  }
  if (jIvLen != IV_LENGTH) {
    snprintf(errClass, sizeof(errClass), "java/lang/IllegalArgumentException");
    snprintf(errMsg, sizeof(errMsg), "Invalid iv length.");
    goto error;
  }

  context = QATCONTEXT(ctx);
  if (context == 0) {
    // Create and initialize a qat_ctx
    context = qatCtxAlloc();
    if (!context) {
      snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
      snprintf(errMsg, sizeof(errMsg), "Allocate qat_context failed.");
      goto error;
    }
    memset(context, 0, sizeof(qat_ctx));
  } else {
    qatCtxCleanup(context);
  }

  jbyte *jKey = (*env)->GetByteArrayElements(env, key, NULL);
  if (jKey == NULL) {
    snprintf(errClass, sizeof(errClass), "java/lang/InternalError");
    snprintf(errMsg, sizeof(errMsg), "Cannot get bytes array for key.");
    goto error;
  }
  jbyte *jIv = (*env)->GetByteArrayElements(env, iv, NULL);
  if (jIv == NULL) {
    snprintf(errClass, sizeof(errClass), "java/lang/InternalError");
    snprintf(errMsg, sizeof(errMsg), "Cannot get bytes array for iv.");
    goto error;
  }

  /* Populate the session setup structure for the operation required */
  sessionSetupData = (CpaCySymSessionSetupData*) malloc(
      sizeof(CpaCySymSessionSetupData));
  if (sessionSetupData == NULL) {
    snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
    snprintf(errMsg, sizeof(errMsg), "Allocate session setup structure failed.");
    goto error;
  }
  sessionSetupData->sessionPriority = CPA_CY_PRIORITY_HIGH;
  sessionSetupData->symOperation = CPA_CY_SYM_OP_CIPHER;
  sessionSetupData->cipherSetupData.cipherAlgorithm = CPA_CY_SYM_CIPHER_AES_CTR;
  sessionSetupData->cipherSetupData.cipherKeyLenInBytes = (Cpa32U) jKeyLen;
  sessionSetupData->cipherSetupData.pCipherKey = (Cpa8U *) jKey;
  sessionSetupData->verifyDigest = CPA_FALSE;
  if (mode == ENCRYPT_MODE) {
    sessionSetupData->cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_ENCRYPT;
  } else {
    sessionSetupData->cipherSetupData.cipherDirection =
        CPA_CY_SYM_CIPHER_DIRECTION_DECRYPT;
  }

  /* Determine size of session context to allocate */
  instanceHandle = get_next_inst();
  status = dlsym_cpaCySymSessionCtxGetSize(instanceHandle,
      sessionSetupData, &sessionCtxSize);
  if (status != CPA_STATUS_SUCCESS) {
    snprintf(errClass, sizeof(errClass), "java/lang/InternalError");
    snprintf(errMsg, sizeof(errMsg),
        "cpaCySymSessionCtxGetSize failed, status=%d.", status);
    goto error;
  }

  /* Allocate session context */
  pSessionCtx = (CpaCySymSessionCtx) cryptoMemAlloc(sessionCtxSize);
  if (pSessionCtx == NULL) {
    snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
    snprintf(errMsg, sizeof(errMsg), "cryptoMemAlloc CpaCySymSessionCtx failed, size = %d", sessionCtxSize);
    goto error;
  }

  /* Initialize the cipher session */
  status = dlsym_cpaCySymInitSession(instanceHandle, qat_crypto_callbackFn, sessionSetupData,
      pSessionCtx);
  free(sessionSetupData);
  sessionSetupData = NULL;

  /* Maximum number of CpaFlatBuffer in the CpaBufferList is 2. */
  status = dlsym_cpaCyBufferListGetMetaSize(instanceHandle, 2, &srcMetaSize);
  if (status != CPA_STATUS_SUCCESS) {
    snprintf(errClass, sizeof(errClass), "java/lang/InternalError");
    snprintf(errMsg, sizeof(errMsg),
        "cpaCyBufferListGetMetaSize failed, status=%d.", status);
    goto error;
  }

  if (srcMetaSize) {
    pSrcMetaData = cryptoMemAlloc(srcMetaSize);
    if (!pSrcMetaData) {
      snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
      snprintf(errMsg, sizeof(errMsg), "cryptoMemAlloc MetaData failed, size = %d", srcMetaSize);
      goto error;
    }
  } else {
    pSrcMetaData = NULL;
  }

  /* Maximum number of CpaFlatBuffer in the CpaBufferList is 2. */
  status = dlsym_cpaCyBufferListGetMetaSize(instanceHandle, 2, &dstMetaSize);
  if (status != CPA_STATUS_SUCCESS) {
    snprintf(errClass, sizeof(errClass), "java/lang/InternalError");
    snprintf(errMsg, sizeof(errMsg),
        "cpaCyBufferListGetMetaSize failed, status=%d.", status);
    goto error;
  }

  if (dstMetaSize) {
    pDstMetaData = cryptoMemAlloc(dstMetaSize);
    if (!pDstMetaData) {
      snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
      snprintf(errMsg, sizeof(errMsg), "cryptoMemAlloc MetaData failed, size = %d", dstMetaSize);
      goto error;
    }
  } else {
    pDstMetaData = NULL;
  }

  pIv = malloc(jIvLen);
  if (pIv == NULL) {
    snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
    snprintf(errMsg, sizeof(errMsg), "Allocate iv failed.");
    goto error;
  }
  memcpy(pIv, jIv, jIvLen);

  for (i = 0; i < IV_LENGTH -1; i++) {
    context->paddingFlatBuffer[i] = (CpaFlatBuffer*) malloc(sizeof(CpaFlatBuffer));
    if (context->paddingFlatBuffer[i] == NULL) {
      snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
      snprintf(errMsg, sizeof(errMsg), "Allocate CpaFlatBuffer failed.");
      goto error;
    }
    context->paddingFlatBuffer[i]->pData = (Cpa8U *)cryptoMemAlloc(IV_LENGTH);
    if (context->paddingFlatBuffer[i]->pData == NULL) {
      snprintf(errClass, sizeof(errClass), "java/lang/OutOfMemoryError");
      snprintf(errMsg, sizeof(errMsg), "Allocate padding space failed.");
      goto error;
    }
    context->paddingFlatBuffer[i]->dataLenInBytes = i;
  }

  INIT_QUEUE(&(context->bufferListQueue), CpaBufferList);
  INIT_QUEUE(&(context->opDataQueue), CpaCySymOpData);

  context->sessionCtx = pSessionCtx;
  context->pSrcMetaData = pSrcMetaData;
  context->pDstMetaData = pDstMetaData;
  context->instanceHandle = instanceHandle;
  context->ivLength = IV_LENGTH;
  context->iv = pIv;
  context->padding_len = 0;

  (*env)->ReleaseByteArrayElements(env, key, jKey, 0);
  (*env)->ReleaseByteArrayElements(env, iv, jIv, 0);

  return JLONG(context);

error:
  free(context);
  (*env)->ReleaseByteArrayElements(env, key, jKey, 0);
  (*env)->ReleaseByteArrayElements(env, iv, jIv, 0);
  free(sessionSetupData);
  cryptoMemFree(pSessionCtx);
  cryptoMemFree(pSrcMetaData);
  cryptoMemFree(pDstMetaData);

  for (i = 0; i < IV_LENGTH; i++) {
    if (context->paddingFlatBuffer[i] != NULL) {
      if (context->paddingFlatBuffer[i]->pData != NULL) {
        cryptoMemFree(context->paddingFlatBuffer[i]->pData);
      }
      free(context->paddingFlatBuffer[i]);
    }
  }

  THROW(env, errClass, errMsg);
  return (jlong)0;
}

static int check_update_max_output_len(int input_len, int max_output_len)
{
  if (max_output_len >= input_len) {
    return 1;
  }
  return 0;
}

/* Wrapper around cpaCySymPerformOp which handles retries for us. */
CpaStatus myPerformOp(const CpaInstanceHandle instanceHandle,
                      void *pCallbackTag,
                      const CpaCySymOpData *pOpData,
                      const CpaBufferList *pSrcBuffer,
                      CpaBufferList *pDstBuffer, CpaBoolean *pVerifyResult)
{
  CpaStatus status;
  unsigned long int ulPollInterval = getQatPollInterval();
  unsigned int retries = 0;

  do {
    status = dlsym_cpaCySymPerformOp(instanceHandle, pCallbackTag, pOpData,
        pSrcBuffer, pDstBuffer, pVerifyResult);
    if (status == CPA_STATUS_RETRY) {
      pthread_yield();
      if (retries >= QAT_CRYPTO_NUM_POLLING_RETRIES) {
        break;
      }
      retries++;
      usleep(ulPollInterval + (retries % QAT_RETRY_BACKOFF_MODULO_DIVISOR));
    }
  } while (status == CPA_STATUS_RETRY);

  return status;
}

CpaBufferList* allocBufferList(struct CpaBufferListQueue *queue)
{
  CpaBufferList *bufferList = NULL;
  CpaFlatBuffer *flatBuffer = NULL;
  int flatBufferSize;

  if (DEQUEUE(queue, &bufferList, CpaBufferList) != 0) {
    if (zero_copy) {
      flatBufferSize = 2;
    } else {
      flatBufferSize = 1;
    }
    bufferList = (CpaBufferList *)malloc(sizeof(CpaBufferList) + sizeof(CpaFlatBuffer) * flatBufferSize);
    if (bufferList == NULL) {
      return NULL;
    }

    memset(bufferList, 0, sizeof(CpaBufferList) + sizeof(CpaFlatBuffer) * flatBufferSize);
    flatBuffer = (CpaFlatBuffer *) (bufferList + 1);

    bufferList->numBuffers = flatBufferSize;
    bufferList->pBuffers = flatBuffer;
    bufferList->pUserData = NULL;

    if (!zero_copy) {
      bufferList->pBuffers[0].pData = (Cpa8U *)cryptoMemAlloc(PACKET_SIZE);
      if (bufferList->pBuffers[0].pData == NULL) {
        free(bufferList);
        return NULL;
      }
    }
  }

  return bufferList;
}

CpaCySymOpData* allocOpData(struct CpaCySymOpDataQueue *queue)
{
  CpaCySymOpData *pOpData = NULL;

  if (DEQUEUE(queue, &pOpData, CpaCySymOpData) != 0) {
    pOpData = (CpaCySymOpData *)cryptoMemAlloc(sizeof(CpaCySymOpData) + IV_LENGTH);
    if (pOpData == NULL) {
      return NULL;
    }

    memset(pOpData, 0, sizeof(CpaCySymOpData) + IV_LENGTH);
    pOpData->pIv = (Cpa8U *)(pOpData + 1);
    pOpData->packetType = CPA_CY_SYM_PACKET_TYPE_FULL;
    /* Starting point for cipher processing - given as number of bytes from
       start of data in the source buffer. The result of the cipher operation
       will be written back into the output buffer starting at this location. */
    pOpData->cryptoStartSrcOffsetInBytes = 0;
    /* Starting point for hash processing - given as number of bytes from start
       of packet in source buffer. */
    pOpData->hashStartSrcOffsetInBytes = 0;
    /* The message length, in bytes, of the source buffer that the hash will be
       computed on.  */
    pOpData->messageLenToHashInBytes = 0;
    /* Pointer to the location where the digest result either exists or will be
       inserted. */
    pOpData->pDigestResult = NULL;
    /* Pointer to Additional Authenticated Data (AAD) needed for authenticated
       cipher mechanisms - CCM and GCM. For other authentication mechanisms
       this pointer is ignored. */
    pOpData->pAdditionalAuthData = NULL;
    /* The message length, in bytes, of the source buffer that the crypto
       operation will be computed on. This must be a multiple to the block size
       if a block cipher is being used. */
    pOpData->messageLenToCipherInBytes = 0;
    /* Cipher IV length in bytes.  Determines the amount of valid IV data
       pointed to by the pIv parameter. */
    pOpData->ivLenInBytes = (Cpa32U) IV_LENGTH;
  }

  return pOpData;
}

JNIEXPORT jint JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_update
    (JNIEnv *env, jobject object, jlong ctx, jobject input, jint input_offset,
    jint input_len, jobject output, jint output_offset, jint max_output_len)
{
  CpaStatus status = 0;
  CpaBufferList *pBufferList;
  CpaBufferList *pSrcBufferList, *pDstBufferList;
  CpaCySymOpData *pOpData;
  CpaBoolean verifyDigest = CPA_FALSE;
  qat_ctx *context = QATCONTEXT(ctx);

  int padding_len = context->padding_len;
  int numReq = (padding_len + input_len - 1) / (PACKET_SIZE) + 1;
  int inputLenForLastReq = (padding_len + input_len - 1) % (PACKET_SIZE) + 1;
  int rc, i, in_len, actual_in_len;
  struct op_done opDone;
  unsigned char *input_bytes, *output_bytes;
  void *pData;
  struct CpaBufferListQueue* queue;

  if (!check_update_max_output_len(input_len, max_output_len)) {
    THROW(env, "javax/crypto/ShortBufferException",  \
        "Output buffer is not sufficient.");
    return 0;
  }

  input_bytes = (*env)->GetDirectBufferAddress(env, input);
  output_bytes = (*env)->GetDirectBufferAddress(env, output);
  if (input_bytes == NULL || output_bytes == NULL) {
    THROW(env, "java/lang/InternalError", "Cannot get buffer address.");
    return 0;
  }

  initOpDone(&opDone);
  opDone.numReq = numReq;
  opDone.output = output_bytes;
  opDone.output_offset = output_offset;
  opDone.context = context;
  opDone.padding_len = padding_len;

  if (zero_copy) {
    INIT_QUEUE(&queue, CpaBufferList);
  }

  for (i = 0; i < numReq; i++) {
    if (i < numReq - 1) {
      in_len = PACKET_SIZE;
    } else {
      in_len = inputLenForLastReq;
    }
    actual_in_len = in_len - padding_len;

    pSrcBufferList = allocBufferList(context->bufferListQueue);
    if (!zero_copy) {
      pDstBufferList = pSrcBufferList;
    } else {
      pDstBufferList = allocBufferList(context->bufferListQueue);
    }
    if (pSrcBufferList == NULL || pDstBufferList == NULL) {
      THROW(env, "java/lang/OutOfMemoryError","Error when allocate CpaBufferList\n");
      return 0;
    }
    pSrcBufferList->pPrivateMetaData = context->pSrcMetaData;
    pDstBufferList->pPrivateMetaData = context->pDstMetaData;

    pOpData = allocOpData(context->opDataQueue);
    if (pOpData == NULL) {
      THROW(env, "java/lang/OutOfMemoryError","Error when allocate CpaCySymOpData\n");
      return 0;
    }
    pOpData->sessionCtx = context->sessionCtx;
    pOpData->messageLenToCipherInBytes = in_len;
    calculateIV(context->iv, (context->padding_len + i * PACKET_SIZE) / IV_LENGTH, pOpData->pIv);

    if (zero_copy) {
      ENQUEUE(queue, pSrcBufferList, CpaBufferList);
      if (padding_len > 0) {
        pSrcBufferList->numBuffers = 2;
        pSrcBufferList->pBuffers[0].pData = context->paddingFlatBuffer[padding_len]->pData;
        pSrcBufferList->pBuffers[0].dataLenInBytes = context->paddingFlatBuffer[padding_len]->dataLenInBytes;
        pSrcBufferList->pBuffers[1].pData = input_bytes + input_offset;
        pSrcBufferList->pBuffers[1].dataLenInBytes = actual_in_len;

        pDstBufferList->numBuffers = 2;
        pDstBufferList->pBuffers[0].pData = context->paddingFlatBuffer[padding_len]->pData;
        pDstBufferList->pBuffers[0].dataLenInBytes = context->paddingFlatBuffer[padding_len]->dataLenInBytes;
        pDstBufferList->pBuffers[1].pData = output_bytes + output_offset;
        pDstBufferList->pBuffers[1].dataLenInBytes = actual_in_len;
      } else if (padding_len == 0) {
        pSrcBufferList->numBuffers = 1;
        pSrcBufferList->pBuffers[0].pData = input_bytes + input_offset;
        pSrcBufferList->pBuffers[0].dataLenInBytes = in_len;

        pDstBufferList->numBuffers = 1;
        pDstBufferList->pBuffers[0].pData = output_bytes + output_offset;
        pDstBufferList->pBuffers[0].dataLenInBytes = in_len;
      }
    } else {
      pData = pSrcBufferList->pBuffers[0].pData;
      memcpy(pData + padding_len, input_bytes + input_offset, actual_in_len);
      pSrcBufferList->pBuffers[0].dataLenInBytes = in_len;
    }

    status = myPerformOp(context->instanceHandle, &opDone, pOpData,
        pSrcBufferList, pDstBufferList, &verifyDigest);
    if (status != CPA_STATUS_SUCCESS) {
      cleanupOpDone(&opDone);
      THROW(env, "java/lang/InternalError", "myPerformOp failed.");
      return 0;
    }

    input_offset += actual_in_len;
    output_offset += actual_in_len;
    padding_len = 0;
  }
  calculateIV(context->iv, (context->padding_len + input_len) / IV_LENGTH, context->iv);
  context->padding_len = (context->padding_len + input_len) % IV_LENGTH;

  rc = waitForOpToComplete(&opDone, numReq);
  cleanupOpDone(&opDone);

  if (zero_copy) {
    while (DEQUEUE(queue, &pBufferList, CpaBufferList) == 0) {
      ENQUEUE(context->bufferListQueue, pBufferList, CpaBufferList);
    }
  }

  if (rc != 0) {
    return 0;
  } else {
    return input_len;
  }
}

JNIEXPORT jint JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_doFinal
    (JNIEnv *env, jobject object, jlong ctx, jobject output, jint offset,
    jint max_output_len)
{
  qat_ctx *context = QATCONTEXT(ctx);
  if (context) {
    qatCtxCleanup(context);
  }

  return 0;
}

JNIEXPORT void JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_clean
    (JNIEnv *env, jobject object, jlong ctx)
{
  qat_ctx *context = QATCONTEXT(ctx);
  if (context) {
    qatCtxCleanup(context);
    free(context);
  }
}

JNIEXPORT void JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_stopQat
    (JNIEnv *env, jclass clazz)
{
  dlsym_icp_sal_userStop();
}

JNIEXPORT jstring JNICALL Java_org_apache_hadoop_crypto_qat_QatCipher_getLibraryName
    (JNIEnv *env, jclass clazz)
{
#ifdef UNIX
  if (dlsym_cpaCySymPerformOp) {
    Dl_info dl_info;
    if (dladdr(
        dlsym_cpaCySymPerformOp,
        &dl_info)) {
      return (*env)->NewStringUTF(env, dl_info.dli_fname);
    }
  }

  return (*env)->NewStringUTF(env, HADOOP_QAT_LIBRARY);
#endif
}
