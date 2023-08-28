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

/**
* \defgroup utilities
*
* \brief gRPC Utilities for C/C++ Library
*
* The utilities are used to map clases and structs between C/C++. In addition any 
* common operations between the client and server implementations.
*
*/

extern "C" {
#include <stdio.h>
#include "opof.h"
}

#include "opof_util.h"
#include "opof_grpc.h"

static void convertMacRewrite2cpp(
  const struct macRewrite_t * rewrite_c,
  MACRewrite * rewrite_pb)
{
  rewrite_pb->mutable_srcmac()->assign(&rewrite_c->srcMac[0], &rewrite_c->srcMac[6]);
  rewrite_pb->mutable_dstmac()->assign(&rewrite_c->dstMac[0], &rewrite_c->dstMac[6]);
}

static void convertMacRewrite2c(
  const MACRewrite * rewrite_pb,
  struct macRewrite_t * rewrite_c)
{
  if (rewrite_pb->srcmac().length() >= 6 && rewrite_pb->dstmac().length() >= 6) {
    memcpy(rewrite_c->srcMac, &rewrite_pb->srcmac()[0], 6);
    memcpy(rewrite_c->dstMac, &rewrite_pb->dstmac()[0], 6);
  }
}

static void convertNat2cpp(
  const struct nat_t * nat_c,
  NAT * nat_pb)
{
  nat_pb->set_nattype((NAT_TYPE)nat_c->natType);
  nat_pb->set_ipversion((IP_VERSION)nat_c->ipver);
  if (nat_c->ipver == _IPV6){
    nat_pb->mutable_ipv6()->assign(&nat_c->ipv6.s6_addr[0], &nat_c->ipv6.s6_addr[16]);
  } else {
    nat_pb->set_ipv4(nat_c->ipv4.s_addr);
  }
  nat_pb->set_protocolid((PROTOCOL_ID)nat_c->proto);
  nat_pb->set_port(nat_c->port);
}

static void convertNat2c(
  const NAT * nat_pb,
  struct nat_t * nat_c)
{
  nat_c->natType = (NAT_TYPE_T)nat_pb->nattype();
  nat_c->ipver = (IP_VERSION_T)nat_pb->ipversion();
  if (nat_c->ipver == _IPV6) {
    memcpy(nat_c->ipv6.s6_addr, &nat_pb->ipv6()[0], 16);
  } else {
    nat_c->ipv4.s_addr = nat_pb->ipv4();
  }
  nat_c->proto = (PROTOCOL_ID_T)nat_pb->protocolid();
  nat_c->port = nat_pb->port();
}

void convertNextHop2cpp(
  const struct nextHopParameters_t *nextHop_c,
  nextHopParameters *nextHop_pb)
{
    if (nextHop_c->macRewriteEnable) {
      convertMacRewrite2cpp(&nextHop_c->macRewrite, nextHop_pb->mutable_macrewrite());
    } else {
      nextHop_pb->clear_macrewrite();
    }

    if (nextHop_c->natEnable) {
      convertNat2cpp(&nextHop_c->nat, nextHop_pb->mutable_nat());
    } else {
      nextHop_pb->clear_nat();
    }
    nextHop_pb->set_vlan(nextHop_c->vlan);
}

void convertNextHop2c(
  const nextHopParameters *nextHop_pb,
  struct nextHopParameters_t *nextHop_c)
{
    nextHop_c->macRewriteEnable = nextHop_pb->has_macrewrite();
    
    if (nextHop_c->macRewriteEnable)
    {
      convertMacRewrite2c(&nextHop_pb->macrewrite(),  &nextHop_c->macRewrite);
    }

    nextHop_c->natEnable = nextHop_pb->has_nat();
    
    if (nextHop_c->natEnable)
    {
      nextHop_c->natEnable = true;
      convertNat2c(&nextHop_pb->nat(),  &nextHop_c->nat);
    }
    
    nextHop_c->vlan = nextHop_pb->vlan();
}

static void convertActionParams2cpp(
  const struct actionParameters_t * actionParams_c, 
  actionParameters * actionParams_pb)
{
    actionParams_pb->set_actiontype((ACTION_TYPE)actionParams_c->actionType);
    
    // obsolete: actionNextHop, actionNextHopV6

    actionParams_pb->set_nexthopid_inlif(actionParams_c->nextHopId_inLif);
    actionParams_pb->set_nexthopid_outlif(actionParams_c->nextHopId_outLif);
}

static void convertActionParams2c(
  const actionParameters * actionParams_pb,
  struct actionParameters_t * actionParams_c)
{
    actionParams_c->actionType = (ACTION_VALUE_T)actionParams_pb->actiontype();

    // obsolete: actionNextHop, actionNextHopV6

    actionParams_c->nextHopId_inLif = actionParams_pb->nexthopid_inlif();
    actionParams_c->nextHopId_outLif = actionParams_pb->nexthopid_outlif();
}

/** \ingroup utilities
*
* \brief Covert a C SessionRequest_t to a C++ sessionRequest Class instance
*
* \param *request_c   The sessionRequest_t struct to convert
*
* \param *request     The sessionRequest object to create
*
* \return void
*/
void convertSessionRequest2cpp(sessionRequest_t *request_c, sessionRequest *request){
    std::string s;
    request->set_sessionid(request_c->sessId);
    request->set_inlif(request_c->inlif);
    request->set_outlif(request_c->outlif);
    request->set_encaptype((TUNNEL_TYPE)request_c->encapType);
    request->set_vlan_inlif(request_c->vlan_inLif);
    request->set_vlan_outlif(request_c->vlan_outLif);
    request->set_ipversion((IP_VERSION)request_c->ipver);
    request->set_sourceport((unsigned int)request_c->srcPort);
    if (request_c->ipver == _IPV6){
       s.assign(request_c->srcIPV6.s6_addr, request_c->srcIPV6.s6_addr+ 16);
      request->set_sourceipv6(s);
    } else {
      request->set_sourceip(request_c->srcIP.s_addr);
    } 
    if (request_c->ipver == _IPV6){
      s.assign(request_c->dstIPV6.s6_addr, request_c->dstIPV6.s6_addr+ 16);
      request->set_destinationipv6(s);
    } else {
      request->set_destinationip(request_c->dstIP.s_addr);
    } 
    request->set_destinationport((unsigned int)request_c->dstPort);
    request->set_protocolid((PROTOCOL_ID)request_c->proto);
    convertActionParams2cpp(&request_c->actionParams, request->mutable_action());
    request->set_cachetimeout(request_c->cacheTimeout);
}
/** \ingroup utilities
*
* \brief Covert a C SessionRequest_t to a C++ sessionRequest Class instance
*
* \param *request_c   The sessionRequest_t struct to convert
*
* \param *request     The sessionRequest object to create
*
* \return void
*/
void convertAddSessionResponse2c(addSessionResponse_t *response_c, addSessionResponse *response){
  sessionResponseError responseError;
  //response_c->requestStatus = (REQUEST_STATUS_T)response->requeststatus();
  if (response->responseerror_size() > 0){
    response_c->number_errors = response->responseerror_size();
    for (int i=0; i< response_c->number_errors; i++){
      responseError = response->responseerror(i);
      response_c->sessionErrors[i].sessionId = responseError.sessionid();
      response_c->sessionErrors[i].errorStatus = responseError.errorstatus();
    }
  } else {
    response_c->number_errors = 0;
  }
}
/** \ingroup utilities
*
* \brief Covert a C SessionRequest_t to a C++ sessionRequest Class instance
*
* \param *request_c   The sessionRequest_t struct to convert
*
* \param *request     The sessionRequest object to create
*
* \return void
*/
void convertSessionResponse2c(sessionResponse *responsecpp, sessionResponse_t *responsec){

  responsec->sessionId = responsecpp->sessionid();
  responsec->requestStatus = (REQUEST_STATUS_T)responsecpp->requeststatus();
  responsec->sessionState = (SESSION_STATE_T)responsecpp->sessionstate();
  responsec->sessionCloseCode = (SESSION_CLOSE_T)responsecpp->sessionclosecode();
  responsec->inPackets = responsecpp->inpackets();
  responsec->outPackets = responsecpp->outpackets();
  responsec->inBytes = responsecpp->inbytes();
  responsec->outBytes = responsecpp->outbytes();
}

void convertSessionResponse2cpp(sessionResponse *responsecpp, sessionResponse_t *responsec){
  responsecpp->set_sessionid(responsec->sessionId);
  responsecpp->set_requeststatus((REQUEST_STATUS)responsec->requestStatus);
  responsecpp->set_sessionstate((SESSION_STATE)responsec->sessionState);
  responsecpp->set_sessionclosecode((SESSION_CLOSE_CODE)responsec->sessionCloseCode);
  responsecpp->set_inpackets(responsec->inPackets);
  responsecpp->set_outpackets(responsec->outPackets);
  responsecpp->set_inbytes(responsec->inBytes);
  responsecpp->set_outbytes(responsec->outBytes);
}
void convertSessionRequest2c(sessionRequest &request, sessionRequest_t *request_c){
    actionParameters action;
    std::vector<uint8_t> char_array(16, 0);
    request_c->sessId = request.sessionid();
    request_c->inlif = request.inlif();
    request_c->outlif = request.outlif();
    request_c->encapType = (TUNNEL_TYPE_T)request.encaptype();
    request_c->vlan_inLif = request.vlan_inlif();
    request_c->vlan_outLif = request.vlan_outlif();
    request_c->ipver = (IP_VERSION_T)request.ipversion();
    if (request_c->ipver == _IPV6){
      char_array.assign(request.sourceipv6().begin(), request.sourceipv6().end());
      memcpy(request_c->srcIPV6.s6_addr,&char_array[0],16);
    } else {
      request_c->srcIP.s_addr = request.sourceip();
    }
    if (request_c->ipver == _IPV6){
      char_array.assign(request.destinationipv6().begin(), request.destinationipv6().end());
       memcpy(request_c->dstIPV6.s6_addr,&char_array[0],16);
    } else {
      request_c->dstIP.s_addr = request.destinationip();
    }
    request_c->srcPort = (unsigned short)request.sourceport();
    request_c->dstPort = (unsigned short)request.destinationport();
    request_c->proto = (PROTOCOL_ID_T)request.protocolid();
    convertActionParams2c(&request.action(), &request_c->actionParams);
    request_c->cacheTimeout = request.cachetimeout();
 }

void convertNextHopResponse2c(
  const nextHopResponse *responsecpp, 
  struct nextHopResponse_t *responsec)
{
  responsec->nextHopId = responsecpp->nexthopid();
  responsec->errorStatus = responsecpp->errorstatus();
}

void convertNextHopResponse2cpp(
  const struct nextHopResponse_t *responsec,
  nextHopResponse *responsecpp)
{
  responsecpp->set_nexthopid(responsec->nextHopId);
  responsecpp->set_errorstatus(responsec->errorStatus);
}
