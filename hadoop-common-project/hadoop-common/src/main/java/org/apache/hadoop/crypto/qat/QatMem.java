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
package org.apache.hadoop.crypto.qat;

import java.nio.ByteBuffer;

public class QatMem {
  private static boolean inited = false;

  private static void ensureInitialized() {
    if (inited) {
      return;
    }

    synchronized (QatMem.class) {
      String initfailureReason = null;
      if (!inited) {
        try {
          // trigger initialization of QAT
          Class.forName(QatCipher.class.getName());
        } catch (ClassNotFoundException e) {
          initfailureReason = e.getMessage();
        }
        if (initfailureReason == null) {
          initfailureReason = QatCipher.getLoadingFailureReason();
        }
        if (initfailureReason != null) {
          throw new RuntimeException(initfailureReason);
        }
        inited = true;
      }
    }
  }

  public static ByteBuffer allocate(int capacity) {
    ensureInitialized();
    return allocateInternal(capacity);
  }

  public static void release(ByteBuffer buffer) {
    if (buffer == null) {
      return;
    }

    releaseInternal(buffer);
  }

  private native static ByteBuffer allocateInternal(int capacity);

  private native static void releaseInternal(ByteBuffer buffer);
}
