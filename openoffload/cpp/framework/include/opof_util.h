// Copyright (C) 2020 Palo Alto Networks Intellectual Property. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
#ifndef OPOF_UTIL_H
#define OPOF_UTIL_H
#ifdef __cplusplus
extern "C" {
#endif
#include <arpa/inet.h>
//#include <sys/types.h>          
//#include <sys/socket.h>
#include <inttypes.h>

#include "opof.h"
#include "opof_error.h"

#ifdef __cplusplus
}
#endif
#include "opof_grpc.h"

int get_key(const char *filename, char *key);

void convertSessionRequest2cpp(sessionRequest_t *request_c, sessionRequest *request);
void convertAddSessionResponse2c(addSessionResponse_t *response_c, addSessionResponse *response);
void convertSessionResponse2c(sessionResponse *responsecpp, sessionResponse_t *responsec);
void convertSessionResponse2cpp(sessionResponse *responsecpp, sessionResponse_t *responsec);
void convertSessionRequest2c(sessionRequest &request, sessionRequest_t *request_c);
void convertNextHop2cpp(
  const struct nextHopParameters_t *nextHop_c,
  nextHopParameters *nextHop_pb);
void convertNextHop2c(
  const nextHopParameters *nextHop_pb,
  struct nextHopParameters_t *nextHop_c);
void convertNextHopResponse2c(
  const nextHopResponse *responsecpp, 
  struct nextHopResponse_t *responsec);
void convertNextHopResponse2cpp(
  const struct nextHopResponse_t *responsec,
  nextHopResponse *responsecpp);
void convertPerLinkActionParams2cpp(
  const struct perLinkActionParameters_t *params_c,
  perLinkActionParameters *params_pb);
void convertPerLinkActionParams2c(
  const perLinkActionParameters *params_pb,
  struct perLinkActionParameters_t *params_c);
#endif
