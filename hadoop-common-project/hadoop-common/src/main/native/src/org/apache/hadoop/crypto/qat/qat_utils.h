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
#ifndef QAT_UTILS_DOT_H
#define QAT_UTILS_DOT_H

#include "cpa.h"
#include "cpa_types.h"
#include "cpa_cy_sym.h"

#include <stdio.h>
#include <pthread.h>
#include <errno.h>

static int zero_copy = 1;

#define DECLARE(NodeType)                                                           \
  struct NodeType##Node {struct NodeType##Node *next; NodeType *value;};            \
  struct NodeType##Queue {struct NodeType##Node *front; struct NodeType##Node *rear; pthread_mutex_t mutex;};

#define DEFINE_INIT_QUEUE(NodeType)                                                 \
  void initQueue##NodeType(struct NodeType##Queue **queue)                          \
  {                                                                                 \
    int sts;                                                                        \
    *queue = (struct NodeType##Queue *)malloc(sizeof(struct NodeType##Queue));      \
    (*queue)->front = (*queue)->rear = NULL;                                        \
    sts = pthread_mutex_init(&((*queue)->mutex), NULL);                             \
    if (sts != 0) {                                                                 \
      printf("pthread_mutex_init failed - sts = %d. Continuing anyway.\n", sts);    \
    }                                                                               \
  }

#define DEFINE_CLEAR_QUEUE(NodeType)                                                \
  void clearQueue##NodeType(struct NodeType##Queue *queue)                          \
  {                                                                                 \
    struct NodeType##Node *front, *next;                                            \
    if (queue == NULL) {                                                            \
      return;                                                                       \
    }                                                                               \
                                                                                    \
    front = queue->front;                                                           \
    while (front != NULL) {                                                         \
      next = front->next;                                                           \
      free##NodeType##Node(front);                                                  \
      front = next;                                                                 \
    }                                                                               \
                                                                                    \
    if (pthread_mutex_destroy(&(queue->mutex)) != 0) {                              \
      printf("pthread_mutex_destroy failed. Continuing anyway: %d\n", errno);       \
    }                                                                               \
                                                                                    \
    free(queue);                                                                    \
  }

#define DEFINE_ENQUEUE(NodeType)                                                    \
  void enQueue##NodeType(struct NodeType##Queue *queue, NodeType *value)            \
  {                                                                                 \
    struct NodeType##Node *node =                                                   \
      (struct NodeType##Node *)malloc(sizeof(struct NodeType##Node));               \
    node->value = value;                                                            \
    node->next = NULL;                                                              \
                                                                                    \
    int rc;                                                                         \
    rc = pthread_mutex_lock(&(queue->mutex));                                       \
    if (rc != 0) {                                                                  \
      printf("pthread_mutex_lock failed - rc = %d.\n", rc);                         \
      return;                                                                       \
    }                                                                               \
                                                                                    \
    if (queue->rear == NULL) {                                                      \
      queue->front = node;                                                          \
      queue->rear = node;                                                           \
    } else {                                                                        \
      queue->rear->next = node;                                                     \
      queue->rear = node;                                                           \
    }                                                                               \
                                                                                    \
    rc = pthread_mutex_unlock(&(queue->mutex));                                     \
    if (rc != 0) {                                                                  \
      printf("pthread_mutex_unlock failed - rc = %d.\n", rc);                       \
      return;                                                                       \
    }                                                                               \
  }

#define DEFINE_DEQUEUE(NodeType)                                                    \
  int deQueue##NodeType(struct NodeType##Queue *queue, NodeType **value)            \
  {                                                                                 \
    struct NodeType##Node *node = NULL;                                             \
    int rc = pthread_mutex_lock(&(queue->mutex));                                   \
                                                                                    \
    if (rc != 0) {                                                                  \
      printf("pthread_mutex_lock failed - rc = %d.\n", rc);                         \
      return -1;                                                                    \
    }                                                                               \
                                                                                    \
    if (queue->rear != NULL) {                                                      \
      if (queue->front == queue->rear) {                                            \
        node = queue->front;                                                        \
        queue->front = NULL;                                                        \
        queue->rear = NULL;                                                         \
      } else {                                                                      \
        node = queue->front;                                                        \
        queue->front = queue->front->next;                                          \
      }                                                                             \
    }                                                                               \
                                                                                    \
    rc = pthread_mutex_unlock(&(queue->mutex));                                     \
    if (rc != 0) {                                                                  \
      printf("pthread_mutex_unlock failed - rc = %d.\n", rc);                       \
    }                                                                               \
                                                                                    \
    if (node != NULL) {                                                             \
      *value = node->value;                                                         \
      free(node);                                                                   \
      return 0;                                                                     \
    } else {                                                                        \
      return -1;                                                                    \
    }                                                                               \
  }

#define INIT_QUEUE(queue, NodeType) initQueue##NodeType(queue)
#define CLEAR_QUEUE(queue, NodeType) clearQueue##NodeType(queue)
#define ENQUEUE(queue, value, NodeType) enQueue##NodeType(queue, value)
#define DEQUEUE(queue, value, NodeType) deQueue##NodeType(queue, value)

DECLARE(CpaBufferList);
DECLARE(CpaCySymOpData);

void freeCpaBufferListNode(struct CpaBufferListNode *node);
void freeCpaCySymOpDataNode(struct CpaCySymOpDataNode *node);

#endif //QAT_UTILS_DOT_H
