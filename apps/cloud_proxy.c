/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright 2017-2021 Open Connectivity Foundation
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

/* Application Design
*
* support functions:
* app_init
*  initializes the oic/p and oic/d values.
* register_resources
*  function that registers all endpoints, e.g. sets the RETRIEVE/UPDATE handlers for each end point
*
* main
*  starts the stack, with the registered resources.
*
* Each resource has:
*  global property variables (per resource path) for:
*    the property name
*       naming convention: g_<path>_RESOURCE_PROPERTY_NAME_<propertyname>
*    the actual value of the property, which is typed from the json data type
*      naming convention: g_<path>_<propertyname>
*  global resource variables (per path) for:
*    the path in a variable:
*      naming convention: g_<path>_RESOURCE_ENDPOINT
*
*  handlers for the implemented methods (get/post)
*   get_<path>
*     function that is being called when a RETRIEVE is called on <path>
*     set the global variables in the output
*   post_<path>
*     function that is being called when a UPDATE is called on <path>
*     checks the input data
*     if input data is correct
*       updates the global variables
*
*/
/*
 tool_version          : 20200103
 input_file            : ../device_output/out_codegeneration_merged.swagger.json
 version of input_file :
 title of input_file   : server_lite_446
*/

#include "oc_api.h"
#include "port/oc_clock.h"
#include <signal.h>

#ifdef OC_CLOUD
#include "oc_cloud.h"
#endif
#if defined(OC_IDD_API)
#include "oc_introspection.h"
#endif

#ifdef __linux__
/* linux specific code */
#include <pthread.h>
#ifndef NO_MAIN
static pthread_mutex_t mutex;
static pthread_cond_t cv;
static struct timespec ts;
#endif /* NO_MAIN */
#endif

#ifdef WIN32
/* windows specific code */
#include <windows.h>
static CONDITION_VARIABLE cv;   /* event loop variable */
static CRITICAL_SECTION cs;     /* event loop variable */
#endif

#define btoa(x) ((x)?"true":"false")

#define MAX_STRING 30           /* max size of the strings. */
#define MAX_PAYLOAD_STRING 65   /* max size strings in the payload */
#define MAX_ARRAY 10            /* max size of the array */
/* Note: Magic numbers are derived from the resource definition, either from the example or the definition.*/

volatile int quit = 0;          /* stop variable, used by handle_signal */
#define MAX_URI_LENGTH (30)

static oc_endpoint_t* discovered_server;
//static oc_separate_response_t array_response;
//static oc_string_t name; 

static const char* cis = "coap+tcp://127.0.0.1:5683";
static const char* auth_code = "test";
static const char* sid = "00000000-0000-0000-0000-000000000001";
static const char* apn = "plgd";
static const char* device_name = "CloudProxy";


/* global property variables for path: "d2dserverlist" */
static char* g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist = "d2dserverlist"; /* the name for the attribute */

/* array d2dserverlist  This Property maintains the list of the D2D Device's connection info i.e. {Device ID, Resource URI, end points} *//* array of objects */
struct _d2dserverlist_d2dserverlist_t
{
  char di[MAX_PAYLOAD_STRING];  /* Format pattern according to IETF RFC 4122. */
  char eps_s[MAX_PAYLOAD_STRING];  /* the OCF Endpoint information of the target Resource */
  char eps[MAX_PAYLOAD_STRING];  /* the OCF Endpoint information of the target Resource */
  char href[MAX_PAYLOAD_STRING];  /* This is the target URI, it can be specified as a Relative Reference or fully-qualified URI. */

};
struct _d2dserverlist_d2dserverlist_t g_d2dserverlist_d2dserverlist[MAX_ARRAY];
int g_d2dserverlist_d2dserverlist_array_size = 0;



typedef struct
{
  oc_request_t* request;
  oc_separate_response_t array_response;
} proxy_data_t;



static char* g_d2dserverlist_RESOURCE_PROPERTY_NAME_di = "di"; /* the name for the attribute */
char g_d2dserverlist_di[MAX_PAYLOAD_STRING] = """"; /* current value of property "di" Format pattern according to IETF RFC 4122. *//* registration data variables for the resources */

/* global resource variables for path: d2dserverlist */
static char* g_d2dserverlist_RESOURCE_ENDPOINT = "d2dserverlist"; /* used path for this resource */
static char* g_d2dserverlist_RESOURCE_TYPE[MAX_STRING] = { "oic.r.d2dserverlist" }; /* rt value (as an array) */
int g_d2dserverlist_nr_resource_types = 1;



void
print_rep(oc_rep_t* rep, bool pretty_print)
{
  char* json;
  size_t json_size;
  json_size = oc_rep_to_json(rep, NULL, 0, pretty_print);
  json = (char*)malloc(json_size + 1);
  oc_rep_to_json(rep, json, json_size + 1, pretty_print);
  printf("%s\n", json);
  free(json);
}




static void url_to_udn(const char* url, char* udn)
{
  strcpy(udn, &url[1]);
  udn[OC_UUID_LEN - 1] = '\0';
}


static void url_to_local_url(const char* url, char* local_url)
{
  strcpy(local_url, &url[OC_UUID_LEN]);
}

static void anchor_to_udn(const char* anchor, char* udn)
{
  strcpy(udn, &anchor[6]);
}

static oc_endpoint_t* is_udn_listed(char* udn)
{

  PRINT("  Finding UDN %s \n", udn);
  oc_endpoint_t* ep = discovered_server;
  while (ep != NULL) {
    char uuid[OC_UUID_LEN] = { 0 };
    oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);
    PRINT("        uuid %s\n", uuid);
    PRINT("        udn  %s\n", udn);
    if (strncmp(uuid, udn, OC_UUID_LEN) == 0) {
      return ep;
    }

    //PRINT("di = %s\n", uuid);
    //PRINTipaddr(*ep);
    //PRINT("\n"); 
    ep = ep->next;
  }
  return NULL;
}



/**
* function to set up the device.
*
*/
int
app_init(void)
{
  int ret = oc_init_platform("ocf", NULL, NULL);
  /* the settings determine the appearance of the device on the network
     can be ocf.2.2.0 (or even higher)
     supplied values are for ocf.2.2.0 */
  ret |= oc_add_device("/oic/d", "oic.d.cloudproxy", "cloud_proxy",
    "ocf.2.2.0", /* icv value */
    "ocf.res.1.3.0, ocf.sh.1.3.0",  /* dmv value */
    NULL, NULL);

#if defined(OC_IDD_API)
  FILE* fp;
  uint8_t* buffer;
  size_t buffer_size;
  const char introspection_error[] =
    "\tERROR Could not read 'server_introspection.cbor'\n"
    "\tIntrospection data not set.\n";
  fp = fopen("./server_introspection.cbor", "rb");
  if (fp) {
    fseek(fp, 0, SEEK_END);
    buffer_size = ftell(fp);
    rewind(fp);

    buffer = (uint8_t*)malloc(buffer_size * sizeof(uint8_t));
    size_t fread_ret = fread(buffer, buffer_size, 1, fp);
    fclose(fp);

    if (fread_ret == 1) {
      oc_set_introspection_data(0, buffer, buffer_size);
      PRINT("\tIntrospection data set 'server_introspection.cbor': %d [bytes]\n", (int)buffer_size);
    }
    else {
      PRINT("%s", introspection_error);
    }
    free(buffer);
  }
  else {
    PRINT("%s", introspection_error);
  }
#else
  PRINT("\t introspection via header file\n");
#endif
  return ret;
}

/**
* helper function to check if the POST input document contains
* the common readOnly properties or the resouce readOnly properties
* @param name the name of the property
* @return the error_status, e.g. if error_status is true, then the input document contains something illegal
*/
static bool
check_on_readonly_common_resource_properties(oc_string_t name, bool error_state)
{
  if (strcmp(oc_string(name), "n") == 0) {
    error_state = true;
    PRINT("   property \"n\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "if") == 0) {
    error_state = true;
    PRINT("   property \"if\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "rt") == 0) {
    error_state = true;
    PRINT("   property \"rt\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    PRINT("   property \"id\" is ReadOnly \n");
  }
  else if (strcmp(oc_string(name), "id") == 0) {
    error_state = true;
    PRINT("   property \"id\" is ReadOnly \n");
  }
  return error_state;
}


/**
* get method for "d2dserverlist" resource.
* function is called to intialize the return values of the GET method.
* initialisation of the returned values are done from the global property values.
* Resource Description:
* The RETRIEVE operation on this Resource is only allowed for appropriately privileged devices (e.g. Mediator). For all other devices the Cloud Proxy is expected to reject RETRIEVE operation attempts.
*
* @param request the request representation.
* @param interfaces the interface used for this call
* @param user_data the user data.
*/
static void
get_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)user_data;  /* variable not used */
  /* TODO: SENSOR add here the code to talk to the HW if one implements a sensor.
     the call to the HW needs to fill in the global variable before it returns to this function here.
     alternative is to have a callback from the hardware that sets the global variables.

     The implementation always return everything that belongs to the resource.
     this implementation is not optimal, but is functionally correct and will pass CTT1.2.2 */
  bool error_state = false;


  PRINT("-- Begin get_d2dserverlist: interface %d\n", interfaces);
  oc_rep_start_root_object();
  switch (interfaces) {
  case OC_IF_BASELINE:
    PRINT("   Adding Baseline info\n");
    oc_process_baseline_interface(request->resource);

    /* property (array of objects) 'd2dserverlist' */
    PRINT("   Array of objects : '%s'\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_array(root, d2dserverlist);
    for (int i = 0; i < g_d2dserverlist_d2dserverlist_array_size; i++)
    {
      oc_rep_object_array_begin_item(d2dserverlist);
      /* di ['string', 'Format pattern according to IETF RFC 4122.'] */
      oc_rep_set_text_string(d2dserverlist, di, g_d2dserverlist_d2dserverlist[i].di);
      PRINT("    string di : %d %s\n", i, g_d2dserverlist_d2dserverlist[i].di);
      /* eps ['object[]', 'the OCF Endpoint information of the target Resource'] */
    /* eps not handled */

      /* href ['string', 'This is the target URI, it can be specified as a Relative Reference or fully-qualified URI.'] */
      oc_rep_set_text_string(d2dserverlist, href, g_d2dserverlist_d2dserverlist[i].href);
      PRINT("    string href : %d %s\n", i, g_d2dserverlist_d2dserverlist[i].href);
      oc_rep_object_array_end_item(d2dserverlist);
    }
    oc_rep_close_array(root, d2dserverlist);

    break;
  case OC_IF_RW:

    /* property (array of objects) 'd2dserverlist' */
    PRINT("   Array of objects : '%s'\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_d2dserverlist);
    oc_rep_set_array(root, d2dserverlist);
    for (int i = 0; i < g_d2dserverlist_d2dserverlist_array_size; i++)
    {
      oc_rep_object_array_begin_item(d2dserverlist);
      /* di ['string', 'Format pattern according to IETF RFC 4122.'] */
      oc_rep_set_text_string(d2dserverlist, di, g_d2dserverlist_d2dserverlist[i].di);
      PRINT("    string di : %d %s\n", i, g_d2dserverlist_d2dserverlist[i].di);
      /* eps ['object[]', 'the OCF Endpoint information of the target Resource'] */
    /* eps not handled */

      /* href ['string', 'This is the target URI, it can be specified as a Relative Reference or fully-qualified URI.'] */
      oc_rep_set_text_string(d2dserverlist, href, g_d2dserverlist_d2dserverlist[i].href);
      PRINT("    string href : %d %s\n", i, g_d2dserverlist_d2dserverlist[i].href);
      oc_rep_object_array_end_item(d2dserverlist);
    }
    oc_rep_close_array(root, d2dserverlist);

    break;

  default:
    break;
  }
  oc_rep_end_root_object();
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  }
  else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End get_d2dserverlist\n");
}

/** 
*/
static bool
if_di_exist(char* di, int di_len)
{
  for (int i = 0; i < g_d2dserverlist_d2dserverlist_array_size; i++) {
    if (strncmp(g_d2dserverlist_d2dserverlist[i].di, di, di_len) == 0) {
      return true;
    }
  }
  return false;
}



/**
*  remove the di from the server list.
* current version just blanks the udn.
*/
static bool
remove_di(char* di)
{
  for (int i = 0; i < g_d2dserverlist_d2dserverlist_array_size; i++) {
    if (strncmp(g_d2dserverlist_d2dserverlist[i].di, di, strlen(di)) == 0) {
      strcpy(g_d2dserverlist_d2dserverlist[i].di, "");
      return true;
    }
  }
  return false;
}

/**
* TODO remove the blank entries by shifting everything up
* 
*/
static bool
fix_list()
{
  for (int i = 0; i < g_d2dserverlist_d2dserverlist_array_size; i++) {
// if (strlen(g_d2dserverlist_d2dserverlist[i].di) == 0) {
//      strcpy(g_d2dserverlist_d2dserverlist[i].di, "");
//      return true;
//    }
  }
  return false;
}



/**
* post method for "d2dserverlist" resource.
* The function has as input the request body, which are the input values of the POST method.
* The input values (as a set) are checked if all supplied values are correct.
* If the input values are correct, they will be assigned to the global  property values.
* Resource Description:
* The Mediator provisions the D2DServerList Resource with Device ID of the D2D Device. When the Cloud Proxy receives this request it retrieves '/oic/res' of the D2D Device, and then The Cloud Proxy completes a new entry of 'd2dserver' object with the contents of the RETRIEVE Response and adds it to D2DServerList Resource.
*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
post_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)interfaces;
  (void)user_data;
  bool error_state = false;
  PRINT("-- Begin post_d2dserverlist:\n");
  oc_rep_t* rep = request->request_payload;

  /* loop over the request document for each required input field to check if all required input fields are present */
  bool var_in_request = false;
  rep = request->request_payload;
  while (rep != NULL) {
    if (strcmp(oc_string(rep->name), g_d2dserverlist_RESOURCE_PROPERTY_NAME_di) == 0) {
      var_in_request = true;
    }
    rep = rep->next;
  }
  if (var_in_request == false)
  {
    error_state = true;
    PRINT(" required property: 'di' not in request\n");
  }
  if (g_d2dserverlist_d2dserverlist_array_size >= MAX_ARRAY)
  {
    error_state = true;
    PRINT(" array full: MAX array size %d\n", g_d2dserverlist_d2dserverlist_array_size);
  }


  /* loop over the request document to check if all inputs are ok */
  rep = request->request_payload;
  while (rep != NULL) {
    PRINT("key: (check) %s \n", oc_string(rep->name));

    error_state = check_on_readonly_common_resource_properties(rep->name, error_state);
    if (strcmp(oc_string(rep->name), g_d2dserverlist_RESOURCE_PROPERTY_NAME_di) == 0) {
      /* property "di" of type string exist in payload */
      if (rep->type != OC_REP_STRING) {
        error_state = true;
        PRINT("   property 'di' is not of type string %d \n", rep->type);
      }
      if (strlen(oc_string(rep->value.string)) >= (MAX_PAYLOAD_STRING - 1))
      {
        error_state = true;
        PRINT("   property 'di' is too long %d expected: MAX_PAYLOAD_STRING-1 \n", (int)strlen(oc_string(rep->value.string)));
      }
      if (if_di_exist(oc_string(rep->value.string), (int)strlen(oc_string(rep->value.string)))) {
        error_state = true;
        PRINT("   property 'di' exist %s \n", oc_string(rep->value.string));
      }

    }
    rep = rep->next;
  }
  /* if the input is ok, then process the input document and assign the global variables */
  if (error_state == false)
  {
    switch (interfaces) {
    default: {
      /* loop over all the properties in the input document */
      oc_rep_t* rep = request->request_payload;
      while (rep != NULL) {
        PRINT("key: (assign) %s \n", oc_string(rep->name));
        /* no error: assign the variables */

        if (strcmp(oc_string(rep->name), g_d2dserverlist_RESOURCE_PROPERTY_NAME_di) == 0) {
          /* assign "di" */
          PRINT("  property 'di' : %s\n", oc_string(rep->value.string));
          strncpy(g_d2dserverlist_di, oc_string(rep->value.string), MAX_PAYLOAD_STRING - 1);
          strncpy(g_d2dserverlist_d2dserverlist[g_d2dserverlist_d2dserverlist_array_size].di, g_d2dserverlist_di, MAX_PAYLOAD_STRING - 1);
          g_d2dserverlist_d2dserverlist_array_size++;
        }
        rep = rep->next;
      }
      /* set the response */
      PRINT("Set response \n");
      oc_rep_start_root_object();
      /*oc_process_baseline_interface(request->resource); */

      PRINT("   %s : %s\n", g_d2dserverlist_RESOURCE_PROPERTY_NAME_di, g_d2dserverlist_di);
      oc_rep_set_text_string(root, di, g_d2dserverlist_di);

      oc_rep_end_root_object();
      /* TODO: ACTUATOR add here the code to talk to the HW if one implements an actuator.
       one can use the global variables as input to those calls
       the global values have been updated already with the data from the request */
      oc_send_response(request, OC_STATUS_CHANGED);
    }
    }
  }
  else
  {
    PRINT("  Returning Error \n");
    /* TODO: add error response, if any */
    //oc_send_response(request, OC_STATUS_NOT_MODIFIED);
    oc_send_response(request, OC_STATUS_BAD_REQUEST);
  }
  PRINT("-- End post_d2dserverlist\n");
}



/**
* delete method for "d2dserverlist" resource.
* Resource Description:
* The Mediator can remove a specific d2dserver entry for maintenance purpose
*
* @param request the request representation.
* @param interfaces the used interfaces during the request.
* @param user_data the supplied user data.
*/
static void
delete_d2dserverlist(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  (void)request;
  (void)interfaces;
  (void)user_data;
  bool error_state = false;

  /* query name 'di' type: 'string'*/
  char* _di = NULL; /* not null terminated  */
  int _di_len = oc_get_query_value(request, "di", &_di);
  if (_di_len != -1) {
    bool query_ok = false;
    /* input check  ^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$ */

    if (query_ok == false) error_state = true;

    /* TODO: use the query value to tailer the response*/
    PRINT(" query value 'di': %.*s\n", _di_len, _di);
    if (if_di_exist(_di, _di_len)) {
      // remove it
      PRINT(" FOUND = TRUE \n");
    }
    else {
      // not in the list
      error_state = true;
    }

    /* TODO: use the query value to tailer the response*/
  }
  if (error_state == false) {
    oc_send_response(request, OC_STATUS_OK);
  }
  else {
    oc_send_response(request, OC_STATUS_BAD_OPTION);
  }
  PRINT("-- End delete_d2dserverlist\n");
}


/**
* register all the resources to the stack
* this function registers all application level resources:
* - each resource path is bind to a specific function for the supported methods (GET, POST, PUT)
* - each resource is
*   - secure
*   - observable
*   - discoverable
*   - used interfaces, including the default interface.
*     default interface is the first of the list of interfaces as specified in the input file
*/
void
register_resources(void)
{

  PRINT("Register Resource with local path \"d2dserverlist\"\n");
  oc_resource_t* res_d2dserverlist = oc_new_resource(NULL, g_d2dserverlist_RESOURCE_ENDPOINT, g_d2dserverlist_nr_resource_types, 0);
  PRINT("     number of Resource Types: %d\n", g_d2dserverlist_nr_resource_types);
  for (int a = 0; a < g_d2dserverlist_nr_resource_types; a++) {
    PRINT("     Resource Type: \"%s\"\n", g_d2dserverlist_RESOURCE_TYPE[a]);
    oc_resource_bind_resource_type(res_d2dserverlist, g_d2dserverlist_RESOURCE_TYPE[a]);
  }

  oc_resource_bind_resource_interface(res_d2dserverlist, OC_IF_BASELINE); /* oic.if.baseline */
  oc_resource_bind_resource_interface(res_d2dserverlist, OC_IF_RW); /* oic.if.rw */
  oc_resource_set_default_interface(res_d2dserverlist, OC_IF_RW);
  PRINT("     Default OCF Interface: 'oic.if.rw'\n");
  oc_resource_set_discoverable(res_d2dserverlist, true);
  /* periodic observable
     to be used when one wants to send an event per time slice
     period is 1 second */
  oc_resource_set_periodic_observable(res_d2dserverlist, 1);
  /* set observable
     events are send when oc_notify_observers(oc_resource_t *resource) is called.
    this function must be called when the value changes, preferable on an interrupt when something is read from the hardware. */
    /*oc_resource_set_observable(res_d2dserverlist, true); */

  oc_resource_set_request_handler(res_d2dserverlist, OC_DELETE, delete_d2dserverlist, NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_GET, get_d2dserverlist, NULL);
  oc_resource_set_request_handler(res_d2dserverlist, OC_POST, post_d2dserverlist, NULL);
  // no cloud registration.
  // only local device registration
  oc_add_resource(res_d2dserverlist);
  // testing 
  //oc_cloud_add_resource(res_d2dserverlist);
}

#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
void
random_pin_cb(const unsigned char* pin, size_t pin_len, void* data)
{
  (void)data;
  PRINT("\n====================\n");
  PRINT("Random PIN: %.*s\n", (int)pin_len, pin);
  PRINT("====================\n");
}
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */

void
factory_presets_cb(size_t device, void* data)
{
  (void)device;
  (void)data;
#if defined(OC_SECURITY) && defined(OC_PKI)
  /* code to include an pki certificate and root trust anchor */
#include "oc_pki.h"
#include "pki_certs.h"
  int credid =
    oc_pki_add_mfg_cert(0, (const unsigned char*)my_cert, strlen(my_cert), (const unsigned char*)my_key, strlen(my_key));
  if (credid < 0) {
    PRINT("ERROR installing PKI certificate\n");
  }
  else {
    PRINT("Successfully installed PKI certificate\n");
  }

  if (oc_pki_add_mfg_intermediate_cert(0, credid, (const unsigned char*)int_ca, strlen(int_ca)) < 0) {
    PRINT("ERROR installing intermediate CA certificate\n");
  }
  else {
    PRINT("Successfully installed intermediate CA certificate\n");
  }

  if (oc_pki_add_mfg_trust_anchor(0, (const unsigned char*)root_ca, strlen(root_ca)) < 0) {
    PRINT("ERROR installing root certificate\n");
  }
  else {
    PRINT("Successfully installed root certificate\n");
  }

  oc_pki_set_security_profile(0, OC_SP_BLACK, OC_SP_BLACK, credid);
#else
  PRINT("No PKI certificates installed\n");
#endif /* OC_SECURITY && OC_PKI */
}


/**
* intializes the global variables
* registers and starts the handler

*/
void
initialize_variables(void)
{
  /* initialize global variables for resource "d2dserverlist" */
  /* initialize array "d2dserverlist" : This Property maintains the list of the D2D Device's connection info i.e. {Device ID, Resource URI, end points} */
  memset((void*)&g_d2dserverlist_d2dserverlist, 0, sizeof(struct _d2dserverlist_d2dserverlist_t));
  //strncpy(g_d2dserverlist_d2dserverlist[0].di, "", MAX_PAYLOAD_STRING - 1);
  //strncpy(g_d2dserverlist_d2dserverlist[0].href, "", MAX_PAYLOAD_STRING - 1);

  g_d2dserverlist_d2dserverlist_array_size = 0;

  strcpy(g_d2dserverlist_di, "");  /* current value of property "di" Format pattern according to IETF RFC 4122. */

  /* set the flag for NO oic/con resource. */
  oc_set_con_res_announced(false);

}


static bool is_vertical(char* resource_type)
{
  int size_rt = (int)strlen(resource_type);
  //PRINT("  is_vertical: %d %s\n", size_rt, resource_type); 

  if (strncmp(resource_type, "oic.d.", 6) == 0)
    return false;

  // these should be false, but they are in the clear, so usefull for debugging.
  if (size_rt == 10 && strncmp(resource_type, "oic.wk.res", 10) == 0)
    return true;
  if (size_rt == 8 && strncmp(resource_type, "oic.wk.p", 8) == 0)
    return true;
  if (size_rt == 8 && strncmp(resource_type, "oic.wk.d", 8) == 0)
    return true;


  if (size_rt == 11 && strncmp(resource_type, "oic.r.roles", 11) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.cred", 10) == 0)
    return false;
  if (size_rt == 11 && strncmp(resource_type, "oic.r.pstat", 11) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.doxm", 10) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.sdi", 9) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.ael", 9) == 0)
    return false;
  if (size_rt == 9 && strncmp(resource_type, "oic.r.csr", 9) == 0)
    return false;
  if (size_rt == 10 && strncmp(resource_type, "oic.r.acl2", 10) == 0)
    return false;
  if (size_rt == 8 && strncmp(resource_type, "oic.r.sp", 8) == 0)
    return false;
  if (size_rt == 20 && strncmp(resource_type, "oic.wk.introspection", 20) == 0)
    return false;
  if (size_rt == 19 && strncmp(resource_type, "oic.r.d2dserverlist", 19) == 0)
    return false;
  if (size_rt == 19 && strncmp(resource_type, "oic.r.coapcloudconf", 19) == 0)
      return false;

  return true;
}



static void
get_local_resource_response(oc_client_response_t* data)
{
  oc_rep_t * value_list=NULL;
  oc_request_t * request=NULL;
  oc_separate_response_t* delay_response;
 

  delay_response = data->user_data;
 

  PRINT(" get_local_resource_response: \n");
  PRINT(" RESPONSE: " );
  oc_parse_rep(data->_payload, (int) data->_payload_len, &value_list);
  print_rep(value_list, false);

  memcpy(delay_response->buffer, data->_payload, (int)data->_payload_len);
  delay_response->len = data->_payload_len;

  oc_send_separate_response(delay_response, data->code);
 
}

static void
get_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{
  char url[MAX_URI_LENGTH*2];
  char local_url[MAX_URI_LENGTH * 2];
  char local_udn[OC_UUID_LEN * 2];
  oc_endpoint_t* local_server;

  oc_separate_response_t* delay_response = NULL;

  
  delay_response = malloc(sizeof(oc_separate_response_t));
  memset(delay_response, 0, sizeof(oc_separate_response_t));


  strcpy(url, oc_string(request->resource->uri));
  PRINT(" get_resource %s", url);
  url_to_udn(url, local_udn);
  local_server = is_udn_listed(local_udn);
  url_to_local_url(url, local_url );
  PRINT("       local udn: %s\n", local_udn);
  PRINT("       local url: %s\n", local_url);

  oc_set_separate_response_buffer(delay_response);
  oc_indicate_separate_response(request, delay_response);
  oc_do_get(local_url, local_server, NULL, &get_local_resource_response, LOW_QOS, delay_response);
  PRINT("       DISPATCHED\n");

}

static void
post_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{

}


static void
delete_resource(oc_request_t* request, oc_interface_mask_t interfaces, void* user_data)
{

}

static oc_discovery_flags_t
discovery(const char* anchor, const char* uri, oc_string_array_t types,
  oc_interface_mask_t iface_mask, oc_endpoint_t* endpoint,
  oc_resource_properties_t bm, bool x, void* user_data)
{
  (void)user_data;
  (void)bm;
  int i;
  char url [MAX_URI_LENGTH];
  char udn[200];
  char udn_url[200];
  int nr_resource_types = 0;

  size_t uri_len = strlen(uri);
  uri_len = (uri_len >= MAX_URI_LENGTH) ? MAX_URI_LENGTH - 1 : uri_len;
 // PRINT("-----DISCOVERYCB %s %s nr_resourcetypes=%zd\n", anchor, uri, oc_string_array_get_allocated_size(types));

  nr_resource_types = (int)oc_string_array_get_allocated_size(types);

  for (i = 0; i < nr_resource_types; i++) {
    char* t = oc_string_array_get_item(types, i);

    if (is_vertical(t)) {
      //oc_string_t ep_string;
      PRINT("  To REGISTER: %s\n", t);

      anchor_to_udn(anchor, udn);
      PRINT("  UDN '%s'\n", udn);

      if (is_udn_listed(udn) == NULL) {
        // add new server to the list
        PRINT("  ADDING UDN '%s'\n", udn);
        oc_endpoint_list_copy(&discovered_server, endpoint);
      }
      strncpy(url, uri, uri_len);
      url[uri_len] = '\0';
      
      PRINT("  Resource %s hosted at endpoints:\n", url);
      oc_endpoint_t* ep = endpoint;
      while (ep != NULL) {
        char uuid[OC_UUID_LEN] = { 0 };
        oc_uuid_to_str(&ep->di, uuid, OC_UUID_LEN);

        PRINT( "di = %s\n",  uuid);
        PRINTipaddr(*ep);
        PRINT("\n");
        ep = ep->next;
      }
      strcpy(udn_url, "/");
      strcat(udn_url, udn);
      strcat(udn_url, url);

      PRINT("   Register Resource with local path \"%s\"\n", udn_url);
      // oc_resource_t* new_resource = oc_new_resource(NULL, udn_url, nr_resource_types, 0);
      oc_resource_t* new_resource = oc_new_resource(udn_url, udn_url, nr_resource_types, 0);
      for (int j = 0; j < nr_resource_types; j++) {
        oc_resource_bind_resource_type(new_resource, oc_string_array_get_item(types, j));
      }

      if (iface_mask & OC_IF_BASELINE) {
        PRINT("   IF BASELINE\n");
        oc_resource_bind_resource_interface(new_resource, OC_IF_BASELINE); /* oic.if.baseline */
      }
      if (iface_mask & OC_IF_R) {
        PRINT("   IF R\n");
        oc_resource_bind_resource_interface(new_resource, OC_IF_R); /* oic.if.r */
        oc_resource_set_default_interface(new_resource, OC_IF_R);
      }
      if (iface_mask & OC_IF_RW) {
        PRINT("   IF RW\n");
        oc_resource_bind_resource_interface(new_resource, OC_IF_RW); /* oic.if.rw */
        oc_resource_set_default_interface(new_resource, OC_IF_RW);
      }
      if (iface_mask & OC_IF_A) {
        PRINT("   IF A\n");
        oc_resource_bind_resource_interface(new_resource, OC_IF_A); /* oic.if.a */
        oc_resource_set_default_interface(new_resource, OC_IF_A);
      }
      if (iface_mask & OC_IF_S) {
        PRINT("   IF S\n");
        oc_resource_bind_resource_interface(new_resource, OC_IF_S); /* oic.if.S */
        oc_resource_set_default_interface(new_resource, OC_IF_S);
      }
     
      oc_resource_set_request_handler(new_resource, OC_DELETE, delete_resource, NULL);
      oc_resource_set_request_handler(new_resource, OC_GET, get_resource, NULL);
      oc_resource_set_request_handler(new_resource, OC_POST, post_resource, NULL);

      oc_add_resource(new_resource);

      int retval = oc_cloud_add_resource(new_resource);
      PRINT("   ADD resource: %d\n", retval);

      //return OC_STOP_DISCOVERY;
    }
  }
  return OC_CONTINUE_DISCOVERY;
}

static void
issue_requests(void)
{
  oc_do_site_local_ipv6_discovery_all(&discovery, NULL);
  oc_do_realm_local_ipv6_discovery_all(&discovery, NULL);
  //oc_do_ip_discovery_all(& discovery, NULL);
  //oc_do_ip_discovery("oic.wk.res", &discovery, NULL);
}


#ifndef NO_MAIN

#ifdef WIN32
/**
* signal the event loop (windows version)
* wakes up the main function to handle the next callback
*/
static void
signal_event_loop(void)
{
  WakeConditionVariable(&cv);
}
#endif /* WIN32 */

#ifdef __linux__
/**
* signal the event loop (Linux)
* wakes up the main function to handle the next callback
*/
static void
signal_event_loop(void)
{
  pthread_mutex_lock(&mutex);
  pthread_cond_signal(&cv);
  pthread_mutex_unlock(&mutex);
}
#endif /* __linux__ */

/**
* handle Ctrl-C
* @param signal the captured signal
*/
void
handle_signal(int signal)
{
  (void)signal;
  signal_event_loop();
  quit = 1;
}

#ifdef OC_CLOUD
/**
* cloud status handler.
* handler to print out the status of the cloud connection
*/
static void
cloud_status_handler(oc_cloud_context_t* ctx, oc_cloud_status_t status,
  void* data)
{
  (void)data;
  PRINT("\nCloud Manager Status:\n");
  if (status & OC_CLOUD_REGISTERED) {
    PRINT("\t\t-Registered\n");
  }
  if (status & OC_CLOUD_TOKEN_EXPIRY) {
    PRINT("\t\t-Token Expiry: ");
    if (ctx) {
      PRINT("%d\n", oc_cloud_get_token_expiry(ctx));
    }
    else {
      PRINT("\n");
    }
  }
  if (status & OC_CLOUD_FAILURE) {
    PRINT("\t\t-Failure\n");
  }
  if (status & OC_CLOUD_LOGGED_IN) {
    PRINT("\t\t-Logged In\n");
    issue_requests();
  }
  if (status & OC_CLOUD_LOGGED_OUT) {
    PRINT("\t\t-Logged Out\n");
  }
  if (status & OC_CLOUD_DEREGISTERED) {
    PRINT("\t\t-DeRegistered\n");
  }
  if (status & OC_CLOUD_REFRESHED_TOKEN) {
    PRINT("\t\t-Refreshed Token\n");
  }
}
#endif // OC_CLOUD

/**
* main application.
* intializes the global variables
* registers and starts the handler
* handles (in a loop) the next event.
* shuts down the stack
*/
int
main(int argc, char* argv[])
{
  int init;
  oc_clock_time_t next_event;

  if (argc > 1) {
    device_name = argv[1];
    PRINT("device_name: %s\n", argv[1]);
  }
  if (argc > 2) {
    auth_code = argv[2];
    PRINT("auth_code: %s\n", argv[2]);
  }
  if (argc > 3) {
    cis = argv[3];
    PRINT("cis : %s\n", argv[3]);
  }
  if (argc > 4) {
    sid = argv[4];
    PRINT("sid: %s\n", argv[4]);
  }
  if (argc > 5) {
    apn = argv[5];
    PRINT("apn: %s\n", argv[5]);
  }




#ifdef WIN32
  /* windows specific */
  InitializeCriticalSection(&cs);
  InitializeConditionVariable(&cv);
  /* install Ctrl-C */
  signal(SIGINT, handle_signal);
#endif
#ifdef __linux__
  /* linux specific */
  struct sigaction sa;
  sigfillset(&sa.sa_mask);
  sa.sa_flags = 0;
  sa.sa_handler = handle_signal;
  /* install Ctrl-C */
  sigaction(SIGINT, &sa, NULL);
#endif

  PRINT("Used input file : \"../device_output/out_codegeneration_merged.swagger.json\"\n");
  PRINT("OCF Server name : \"cloud_proxy\"\n");

  /*
   The storage folder depends on the build system
   for Windows the projects simpleserver and cloud_server are overwritten, hence the folders should be the same as those targets.
   for Linux (as default) the folder is created in the makefile, with $target as name with _cred as post fix.
  */
#ifdef OC_SECURITY
  PRINT("Intialize Secure Resources\n");
#ifdef WIN32
#ifdef OC_CLOUD
  PRINT("\tstorage at './cloud_proxy_creds' \n");
  oc_storage_config("./cloud_proxy_creds");
#else
  PRINT("\tstorage at './simpleserver_creds' \n");
  oc_storage_config("./simpleserver_creds/");
#endif
#else
  PRINT("\tstorage at './device_builder_server_creds' \n");
  oc_storage_config("./device_builder_server_creds");
#endif

  /*intialize the variables */
  initialize_variables();

#endif /* OC_SECURITY */

  /* initializes the handlers structure */
  static const oc_handler_t handler = { .init = app_init,
                                       .signal_event_loop = signal_event_loop,
                                       .register_resources = register_resources
#ifdef OC_CLIENT
                                       ,
                                       .requests_entry = NULL //issue_requests
#endif
  };
#ifdef OC_SECURITY
#ifdef OC_SECURITY_PIN
  /* please enable OC_SECURITY_PIN
    - have display capabilities to display the PIN value
    - server require to implement RANDOM PIN (oic.sec.doxm.rdp) onboarding mechanism
  */
  oc_set_random_pin_callback(random_pin_cb, NULL);
#endif /* OC_SECURITY_PIN */
#endif /* OC_SECURITY */

  oc_set_factory_presets_cb(factory_presets_cb, NULL);

  /* start the stack */
  init = oc_main_init(&handler);

  if (init < 0) {
    PRINT("oc_main_init failed %d, exiting.\n", init);
    return init;
  }

#ifdef OC_CLOUD
  /* get the cloud context and start the cloud */
  oc_cloud_context_t* ctx = oc_cloud_get_context(0);
  if (ctx) {
    int retval;
    PRINT("Start Cloud Manager\n");
    retval = oc_cloud_manager_start(ctx, cloud_status_handler, NULL);
    PRINT("   manager status %d\n", retval);
    if (cis) {
      int retval;
      PRINT("Conf Cloud Manager\n");
      PRINT("   cis       %s\n", cis);
      PRINT("   auth_code %s\n", auth_code);
      PRINT("   sid       %s\n", sid);
      PRINT("   apn       %s\n", apn);

      retval = oc_cloud_provision_conf_resource(ctx, cis, auth_code, sid, apn);
      PRINT("   config status  %d\n", retval);
    }
  }
#endif 

  PRINT("OCF server \"cloud_proxy\" running, waiting on incoming connections.\n");

#ifdef WIN32
  /* windows specific loop */
  while (quit != 1) {
    next_event = oc_main_poll();
    if (next_event == 0) {
      SleepConditionVariableCS(&cv, &cs, INFINITE);
    }
    else {
      oc_clock_time_t now = oc_clock_time();
      if (now < next_event) {
        SleepConditionVariableCS(&cv, &cs,
          (DWORD)((next_event - now) * 1000 / OC_CLOCK_SECOND));
      }
    }
  }
#endif

#ifdef __linux__
  /* linux specific loop */
  while (quit != 1) {
    next_event = oc_main_poll();
    pthread_mutex_lock(&mutex);
    if (next_event == 0) {
      pthread_cond_wait(&cv, &mutex);
    }
    else {
      ts.tv_sec = (next_event / OC_CLOCK_SECOND);
      ts.tv_nsec = (next_event % OC_CLOCK_SECOND) * 1.e09 / OC_CLOCK_SECOND;
      pthread_cond_timedwait(&cv, &mutex, &ts);
    }
    pthread_mutex_unlock(&mutex);
  }
#endif

  /* shut down the stack */
#ifdef OC_CLOUD
  PRINT("Stop Cloud Manager\n");
  oc_cloud_manager_stop(ctx);
#endif
  oc_main_shutdown();
  return 0;
}
#endif /* NO_MAIN */
