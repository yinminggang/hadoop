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
#ifndef QAT_PARSECONF_DOT_H
#define QAT_PARSECONF_DOT_H

#include <stdio.h>

/* The maximum amount of characters allowed per line in the
   config file*/
#define CONF_MAX_LINE_LENGTH 160

/* The number of arguments when we split a line of the form:
   "<arg1> = <arg2>" */
#define CONF_PARAM_EXP_NUM_ARGS 2

/* The maximum length of the path and filename to where the driver
   configuration file is stored */
#define CONF_MAX_PATH 1024

#define CONF_FIND_KEY_KEY_FOUND 2
#define CONF_FIND_KEY_SECTION_FOUND 1
#define CONF_FIND_KEY_FAILED 0

/***********************************************************************
 * function:
 *         confCryptoFindKeyValue(char * filename
 *                          char * sectionName, char * keyName
 *                          char * keyValue, size_t keyValueSize)
 * @description
 *     This function will open the config file at the supplied path.
 *     Parse the config file for the specified section and then parse
 *     for the specified key name. If the key name is found then the
 *     function will return 1 and copy the associated key value into
 *     the string supplied as the keyValue parameter. If the key
 *     name is not found then the function will return 0 and the
 *     keyValue string will not be populated.
 * @param[in] filename - a string containing the path and filename of
 *                       the config file to parse.
 * @param[in] sectionName - a string containing the section name to
 *                          match.
 * @param[in] keyName - a string containing the key name we are
 *                      trying to match.
 * @param[in, out] keyValue - This parameter should be passed in as
 *                            an allocated string. If a match is found
 *                            for the sectionName and keyName then the
 *                            key value associated with the key name
 *                            will be copied into this string.
 * @param[in] keyValueSize - the size of the allocated string passed
 *                           in as keyValue. This allows size checking
 *                           so we don't try and copy a key value that
 *                           is too large into the keyValue string.
 * @retval int - Return 2 if a key value was found.
 *               Return 1 if the section was found
 *               Return 0 if the key value nor section was not found or any errors occured.
 *
 **********************************************************************/

int confCryptoFindKeyValue(char * fileName,
                     char * sectionName, char * keyName,
                    char * keyValue, size_t keyValueSize);

 /***********************************************************************
  * function:
  *         checkLimitDevAccessValue(int * limitDevAccess,
  *                                  char * section_name);
  * @description
  *     This function will go through config files of running QA devices
  *     and look for value of LimitDevAccess parameter in the section, whose name
  *     is given in the section_name parameter. The value of LimitDevAccess found
  *     in first config file that contains section_name section. If the first config
  *     file that contains section_name section does not have LimitDevAccess set, then
  *     it is assumed that LimitDevAccess=1
  * @param[out] limitDevAccess - pointer to where the returned LimitDevAccess value
  *                             will be stored
  * @param[in] sectionName - a string containing the section name to
  *                          match.
  * @retval int - Return 1 the LimitDevAccess value was found.
  *               Return 0 the LimitDevAccess could not be found, zero is returned in
  *                         limitDevAccess
  *
  **********************************************************************/

int checkLimitDevAccessValue(int * limitDevAccess, char * section_name);

#endif // QAT_PARSECONF_DOT_H

