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
  nat_pb->set_ipv4(nat_c->ipv4.s_addr);
  nat_pb->mutable_ipv6()->assign(&nat_c->ipv6.s6_addr[0], &nat_c->ipv6.s6_addr[16]);
  nat_pb->set_port(nat_c->port);
}

static void convertNat2c(
  const NAT * nat_pb,
  struct nat_t * nat_c)
{
  nat_c->ipv4.s_addr = nat_pb->ipv4();
  if (nat_pb->ipv6().length() >= 16) {
    memcpy(nat_c->ipv6.s6_addr, &nat_pb->ipv6()[0], 16);
  }
  nat_c->port = nat_pb->port();
}

static void convertActionParams2cpp(
  const struct actionParameters_t * actionParams_c, 
  openoffload::v1::actionParameters * actionParams_pb)
{
    actionParams_pb->set_actiontype((ACTION_TYPE)actionParams_c->actionType);
    
    // obsolete: actionNextHop, actionNextHopV6

    if (actionParams_c->macRewriteEnable) {
      convertMacRewrite2cpp(&actionParams_c->macRewrite_inLif,  actionParams_pb->mutable_macrewrite_inlif());
      convertMacRewrite2cpp(&actionParams_c->macRewrite_outLif, actionParams_pb->mutable_macrewrite_outlif());
    }
    if (actionParams_c->natEnable) {
      convertNat2cpp(&actionParams_c->srcNat_outLif, actionParams_pb->mutable_srcnat_outlif());
      convertNat2cpp(&actionParams_c->dstNat_inLif,  actionParams_pb->mutable_dstnat_inlif());
    }
    actionParams_pb->set_vlan_inlif(actionParams_c->vlan_inLif);
    actionParams_pb->set_vlan_outlif(actionParams_c->vlan_outLif);
}

static void convertActionParams2c(
  const openoffload::v1::actionParameters * actionParams_pb,
  struct actionParameters_t * actionParams_c)
{
    actionParams_c->actionType = (ACTION_VALUE_T)actionParams_pb->actiontype();

    // obsolete: actionNextHop, actionNextHopV6

    if (actionParams_pb->has_macrewrite_inlif() &&
        actionParams_pb->has_macrewrite_outlif())
    {
      actionParams_c->macRewriteEnable = true;
      convertMacRewrite2c(&actionParams_pb->macrewrite_inlif(),  &actionParams_c->macRewrite_inLif);
      convertMacRewrite2c(&actionParams_pb->macrewrite_outlif(), &actionParams_c->macRewrite_outLif);
    }

    if (actionParams_pb->has_srcnat_outlif() &&
        actionParams_pb->has_dstnat_inlif())
    {
      actionParams_c->natEnable = true;
      convertNat2c(&actionParams_pb->dstnat_inlif(),  &actionParams_c->dstNat_inLif);
      convertNat2c(&actionParams_pb->srcnat_outlif(), &actionParams_c->srcNat_outLif);
    }
    actionParams_c->vlan_inLif  = actionParams_pb->vlan_inlif();
    actionParams_c->vlan_outLif = actionParams_pb->vlan_outlif();
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
