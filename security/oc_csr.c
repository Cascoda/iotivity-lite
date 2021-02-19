/*
// Copyright (c) 2018-2019 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#ifdef OC_SECURITY
#ifdef OC_PKI

#include "oc_csr.h"
#include "oc_api.h"
#include "oc_certs.h"
#include "oc_core_res.h"

void
get_csr(oc_request_t *request, oc_interface_mask_t iface_mask, void *data)
{
  (void)data;
  static bool in_progress = false;
  static bool is_cached = false;
  static unsigned char csr[4096];

  // On embedded devices, the call to oc_certs_generate_csr
  // can take longer than the time between CoAP retransmissions,
  // leading to IoTivity attempting to process multiple CSRs at the 
  // same time. This takes too long, and can cause CT1.7.8.3 to
  // time out. Therefore, we drop any CSR requests that occur 
  // while the CSR is being generated.
  //
  // Afterwards, the CSR is cached until the device is rebooted.
  if (in_progress && !is_cached)
    return;
  else
    in_progress = true;

  size_t device = request->resource->device;


  int ret = 0;
  if (!is_cached)
  {
    ret = oc_certs_generate_csr(device, csr, OC_PDU_SIZE);
    is_cached = true;
  }

  if (ret != 0) {
    oc_send_response(request, OC_STATUS_INTERNAL_SERVER_ERROR);
    is_cached = false;
    return;
  }

  oc_rep_start_root_object();
  if (iface_mask & OC_IF_BASELINE) {
    oc_process_baseline_interface(
      oc_core_get_resource_by_index(OCF_SEC_CSR, device));
  }
  oc_rep_set_text_string(root, csr, (const char *)csr);
  oc_rep_set_text_string(root, encoding, "oic.sec.encoding.pem");
  oc_rep_end_root_object();

  oc_send_response(request, OC_STATUS_OK);
  in_progress = false;
}

#else  /* OC_PKI */
typedef int dummy_declaration;
#endif /* !OC_PKI */
#endif /* OC_SECURITY */
