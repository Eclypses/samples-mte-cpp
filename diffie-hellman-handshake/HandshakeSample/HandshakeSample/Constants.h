#ifndef constants_h
#define constants_h

#ifdef __cplusplus
extern "C"
{
#endif

// MTE Client ID header.
#define CLIENT_ID_HEADER "x-client-id"

  // Set Rest API URL and content settings.
  // Use this URL to run with local CSharp API.
#define REST_API_NAME "http://localhost"
  // Use this URL to run with public CSharp API.
//#define REST_API_NAME "https://dev-echo.eclypses.com"

#define PORT 27015
#define HANDSHAKE_ROUTE "api/handshake"
#define JSON_CONTENT_TYPE "application/json"
#define TEXT_CONTENT_TYPE "text/plain"

  // Result Codes.
  #define STR_SUCCESS "SUCCESS"
  #define RC_SUCCESS "000"

  #define RC_VALIDATION_ERROR "100"

  #define RC_MTE_ENCODE_ERROR "110"

  #define RC_MTE_DECODE_ERROR "120"

  #define RC_MTE_STATE_EXCEPTION "130"
  #define RC_MTE_STATE_CREATION_ERROR "131"
  #define RC_MTE_STATE_RETRIEVAL_ERROR "132"
  #define RC_MTE_STATE_SAVE_ERROR "133"
  #define RC_MTE_STATE_NOT_FOUND "134"

  #define RC_INVALID_NONCE "140"
  #define RC_INVALID_ENTROPY "141"
  #define RC_INVALID_PERSONAL "142"

  #define RC_HTTP_ERROR "300"
  #define RC_UPLOAD_EXCEPTION "301"
  #define RC_HANDSHAKE_EXCEPTION "302"
  #define RC_LOGIN_EXCEPTION "303"

#ifdef __cplusplus
}
#endif

#endif

