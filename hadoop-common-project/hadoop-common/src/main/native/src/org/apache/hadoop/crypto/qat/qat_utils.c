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
#include "qat_utils.h"

void freeCpaBufferListNode(struct CpaBufferListNode *node)
{
  CpaBufferList* bufferList = NULL;

  if (node == NULL) {
    return;
  }

  bufferList = node->value;
  if (bufferList != NULL) {
    if (!zero_copy) {
      if (bufferList->pBuffers != NULL) {
        if (bufferList->pBuffers[0].pData != NULL) {
          cryptoMemFree(bufferList->pBuffers[0].pData);
        }
      }
    }
    free(bufferList);
  }

  free(node);
}

void freeCpaCySymOpDataNode(struct CpaCySymOpDataNode *node)
{
  CpaCySymOpData* opData = NULL;

  if (node == NULL) {
    return;
  }

  opData = node->value;
  if (opData != NULL) {
    cryptoMemFree(opData);
  }

  free(node);
}
