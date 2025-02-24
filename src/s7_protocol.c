#include "s7-protocol.h"
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <math.h> // For floating-point conversions (REAL)
#include <stdio.h>

// TPKT Header
typedef struct {
    uint8_t  version;
    uint8_t  reserved;
    uint16_t length;
} TPKTHeader;

// COTP Header
typedef struct {
    uint8_t length;
    uint8_t pduType;
    union {
        struct { // DT (Data) PDU
            uint8_t tpduNumber : 7;
            uint8_t eot : 1;
        } dt;
        struct { // CR (Connection Request)
            uint8_t  dstRef[2];
            uint8_t  srcRef[2];
            uint8_t classOption;
        } cr;
    } u;
} COTPHeader;

// S7 PDU Header
typedef struct {
    uint8_t  protocolId;
    uint8_t  messageType;
    uint16_t reserved;
    uint16_t pduReference;
    uint16_t paramLength;
    uint16_t dataLength;
} S7Header;

// S7 Read/Write Var Parameter (Request)
typedef struct {
    uint8_t functionCode;
    uint8_t itemCount;
} S7ReadWriteVarParam;

// S7 Read/Write Var Return Code (Response)
typedef struct {
    uint8_t  functionCode;
    uint8_t  itemCount;
    // Error fields are part of the S7Header in Ack-Data
} S7ReadWriteVarResponse;

//S7 PLC Control (Start/Stop Request)
typedef struct {
    uint8_t functionCode;
    uint8_t method; //0x09 for Stop, 0x04/0x05 for Start
    uint8_t unknown[6]; //fixed length
    uint16_t paramLength;

} S7PLCControlParam;

// S7 PLC Control (Response)
typedef struct {
    uint8_t functionCode;
} S7PLCControlResponse; // Response usually just contains the function code

// S7 Request Download (Request)
typedef struct {
  uint8_t functionCode;
  uint8_t subFunction; // 0x01 = Request Download, 0x03 = End Download
  uint8_t blockType;     // 'B', 'F', 'O', etc.
  uint8_t padding[5];
  uint32_t blockNumber;  // Block number (big-endian)
} S7ReqDownloadParam;

// S7 Download Block/Upload (Request)
typedef struct {
  uint8_t functionCode;
  uint8_t subFunction; // Download: 0x02, Upload: 0x01, EndUpload=0x02
} S7DownloadBlockParam;

// S7 Download/Upload (Response)
typedef struct {
  uint8_t functionCode;
  uint8_t subFunction; // Download: 0x02, Upload: 0x01, EndUpload=0x02
  uint8_t padding[3]; //usually 0
} S7DownloadUploadResponse;

// Forward declarations of parsing functions
static int parse_s7_read_var_request(const unsigned char *param, int paramLen, S7Packet *packet);
static int parse_s7_read_var_response(const unsigned char *param, int paramLen, const unsigned char *data, int dataLen, S7Packet *packet);
static int parse_s7_write_var_request(const unsigned char *param, int paramLen,  S7Packet *packet);
static int parse_s7_plc_control_request(const unsigned char *param, int paramLen, S7Packet *packet);
static int parse_s7_req_download_request(const unsigned char *param, int paramLen, S7Packet *packet);
static int parse_s7_download_block_request(const unsigned char *param, int paramLen,  S7Packet* packet);
static int parse_s7_upload_request(const unsigned char* param, int paramLen, S7Packet* packet);
static int parse_s7_download_upload_response(const unsigned char *param, int paramLen, S7Packet *packet);

// 函数指针类型 (请求)：参数为 param, paramLen, packet
typedef int (*S7ParamParserReq)(const unsigned char *param, int paramLen, S7Packet *packet);

// 函数指针类型 (响应)：参数为 param, paramLen, data, dataLen, packet
typedef int (*S7ParamParserRes)(const unsigned char *param, int paramLen, const unsigned char *data, int dataLen, S7Packet *packet);

// NEW: Function pointer type (responses WITHOUT data): param, paramLen, packet
typedef int (*S7ParamParserSimpleRes)(const unsigned char *param, int paramLen, S7Packet *packet);


// Lookup table for S7 parameter parsing functions (Job Requests)
static const struct {
    uint8_t      functionCode;
    S7ParamParserReq parser;
} s7_param_parsers_req[] = {
    {S7_FUNCTION_READ_VAR,      parse_s7_read_var_request},
    {S7_FUNCTION_WRITE_VAR,     parse_s7_write_var_request},
    {S7_FUNCTION_PLC_STOP,      parse_s7_plc_control_request},
    {S7_FUNCTION_PLC_START,     parse_s7_plc_control_request},
    {S7_FUNCTION_REQ_DOWNLOAD, parse_s7_req_download_request},
    {S7_FUNCTION_DOWNLOAD_BLOCK, parse_s7_download_block_request},
    {S7_FUNCTION_START_UPLOAD, parse_s7_upload_request},
    // Add more entries as needed
    {0, NULL} // End marker
};

// Lookup table for S7 parameter parsing functions (Ack-Data Responses)
static const struct {
    uint8_t      functionCode;
    void        *parser;  // Use void* here, we'll cast later
    int          type;     // 0 for S7ParamParserRes, 1 for S7ParamParserSimpleRes
} s7_param_parsers_res[] = {
        {S7_FUNCTION_READ_VAR,      parse_s7_read_var_response, 0},  // Has data
        {S7_FUNCTION_WRITE_VAR,     parse_s7_read_var_response, 0},  // Has data
        {S7_FUNCTION_PLC_STOP,      parse_s7_plc_control_request, 1}, // NO data
        {S7_FUNCTION_PLC_START,    parse_s7_plc_control_request, 1}, // NO data
        {S7_FUNCTION_DOWNLOAD_BLOCK, parse_s7_download_upload_response, 1}, // NO data
        {S7_FUNCTION_DOWNLOAD_ENDED, parse_s7_download_upload_response, 1}, // NO data
        {S7_FUNCTION_UPLOAD, parse_s7_download_upload_response, 1}, // NO data
        {S7_FUNCTION_END_UPLOAD, parse_s7_download_upload_response, 1}, // NO data
    // Add more entries as needed
    {0, NULL, 0} // End marker
};

// Helper function to find the appropriate parsing function
static S7ParamParserReq find_parser_req(uint8_t functionCode) {
    for (int i = 0; s7_param_parsers_req[i].parser != NULL; i++) {
        if (s7_param_parsers_req[i].functionCode == functionCode) {
            return s7_param_parsers_req[i].parser;
        }
    }
    return NULL; // No parser found for this function code
}

// Helper function to find the appropriate parsing function (for responses)
static void *find_parser_res(uint8_t functionCode, int *type) {
    for (int i = 0; s7_param_parsers_res[i].parser != NULL; i++) {
        if (s7_param_parsers_res[i].functionCode == functionCode) {
            *type = s7_param_parsers_res[i].type;
            return s7_param_parsers_res[i].parser;
        }
    }
    *type = -1; // Indicate not found
    return NULL; // No parser found for this function code
}

// S7 data type decoding helper function.  Converts S7 byte data to string.
char* s7_decode_data(const S7Item *item, char * resultBuf, size_t bufSize)
{
    if (!item || !item->data || item->dataLengthBytes == 0 || !resultBuf || bufSize == 0) {
        return NULL; // Invalid input
    }

    switch (item->transportSize)
    {
        case 0x01: // BOOL (Bit)
            snprintf(resultBuf, bufSize, "%s", (item->data[0] & (1 << (item->startOffset % 8))) ? "true" : "false");
            break;
        case 0x02: // BYTE, WORD, DWORD, INT, DINT
           if (item->length == 8) { // BYTE, S7_Char
                snprintf(resultBuf, bufSize, "0x%02X", item->data[0]);
           } else if (item->length == 16) { // WORD, INT
               uint16_t value = ntohs(*(uint16_t *)item->data);
                if (item->area == 0x1E || item->area == 0x1F) // Counter/Timer
                {
                   snprintf(resultBuf, bufSize, "%u", value); // No negative values for Counter/Timer
                }
                else
                {
                    snprintf(resultBuf, bufSize, "%d", (int16_t)value);
                }

           }
           else if (item->length == 32) {  //DWORD, DINT
              uint32_t value = ntohl(*(uint32_t*)item->data);
               if (item->area == 0x1E || item->area == 0x1F) // Counter/Timer
               {
                  snprintf(resultBuf, bufSize, "%u", value);
               }
               else
               {
                  snprintf(resultBuf, bufSize, "%d", (int32_t)value); //DINT
               }

           }
           else{
              snprintf(resultBuf, bufSize, "UnsupportedLength");
           }
            break;
        case 0x04: // REAL (Floating-point)
            if (item->dataLengthBytes == 4) { // 4 bytes for REAL
                uint32_t temp = ntohl(*(uint32_t *)item->data);
                float f;
                memcpy(&f, &temp, 4);
                snprintf(resultBuf, bufSize, "%f", f);
            }
            else
            {
                 snprintf(resultBuf, bufSize, "InvalidReal");
            }
            break;
        case 0x09: //Counter, Timer
          if (item->length == 16)
          {
              //BCD format for counter and timer value
              uint16_t value = ntohs(*(uint16_t *)item->data);
              uint16_t bcdValue = ((value >> 12) & 0x000F) * 100 + ((value >> 8) & 0x000F) * 10 + ((value >> 4) & 0x000F);
               snprintf(resultBuf, bufSize, "%u", bcdValue);

          }
          else{
             snprintf(resultBuf, bufSize, "UnsupportedLength");
          }
          break;

        default:
            snprintf(resultBuf, bufSize, "UnknownType");
            break;
    }
    return resultBuf;

}

// Function to free dynamically allocated resources in S7Packet
void s7_free_packet(S7Packet *packet) {
    if (packet) {
        if (packet->items) {
            for (int i = 0; i < packet->itemCount; i++) {
                if (packet->items[i].data) {
                    free(packet->items[i].data);
                    packet->items[i].data = NULL; // Prevent dangling pointer
                }
            }
            free(packet->items);
            packet->items = NULL; // Prevent dangling pointer
        }
         if (packet->blockData)
         {
            free(packet->blockData);
            packet->blockData = NULL;
         }
    }
}

// Parses a Read Var Request
static int parse_s7_read_var_request(const unsigned char *param, int paramLen, S7Packet *packet) {
    S7ReadWriteVarParam *readVarParam = (S7ReadWriteVarParam *)param;
    packet->functionCode = readVarParam->functionCode;
    packet->itemCount    = readVarParam->itemCount;

    packet->items = (S7Item *)malloc(sizeof(S7Item) * packet->itemCount);
    if (!packet->items) return -1;
    memset(packet->items, 0, sizeof(S7Item) * packet->itemCount);

    const unsigned char *itemData = param + sizeof(S7ReadWriteVarParam);
    for (int i = 0; i < packet->itemCount; i++) {
        if ((size_t)paramLen < sizeof(S7ReadWriteVarParam) + (i+1)*12)
        {
           s7_free_packet(packet);
           return -1;
        }
        packet->items[i].syntaxId      = *itemData++;
        packet->items[i].transportSize = *itemData++;
        packet->items[i].length        = ntohs(*(uint16_t *)itemData);
        itemData += 2;
        packet->items[i].area          = *itemData++;
        packet->items[i].dbNumber      = ntohs(*(uint16_t *)itemData);
        itemData += 2;
        packet->items[i].startOffset   = ((uint32_t)*itemData << 16) | ((uint32_t)*(itemData + 1) << 8) | *(itemData + 2);
        itemData += 3;

    }
    return 0;
}

// Parses a Read Var Response
static int parse_s7_read_var_response(const unsigned char *param, int paramLen, const unsigned char *data, int dataLen, S7Packet *packet)
{
    (void) paramLen; //消除paramLen未使用警告
     S7ReadWriteVarResponse *readVarParam = (S7ReadWriteVarResponse *)param;
    packet->functionCode = readVarParam->functionCode;
    packet->itemCount    = readVarParam->itemCount;
     packet->errorClass = param[2]; // Error class is the 3rd byte in response parameter section
     packet->errorCode  = param[3];  // Error code is the 4th byte.
     packet->items = (S7Item *)malloc(sizeof(S7Item) * packet->itemCount);
    if (!packet->items) return -1;
    memset(packet->items, 0, sizeof(S7Item) * packet->itemCount);

    // If there's an error, no need to parse item data
    if (packet->errorClass != S7_ERR_NO_ERROR || packet->errorCode != S7_ERR_NO_ERROR) {
      return 0; // Return successfully, but with error information
    }

    const unsigned char *itemData = data; //data section
    for (int i=0; i < packet->itemCount; i++)
    {

        packet->items[i].returnCode = *itemData++;
        if (packet->items[i].returnCode != 0xff) //0xff == no error
        {
          //skip the data section
          itemData +=2; //skip length field
          continue;
        }
        packet->items[i].transportSize = *itemData++;
        packet->items[i].length = ntohs(*(uint16_t *)itemData);  // Length in bytes, except for BOOL (bits)
        itemData += 2;
        packet->items[i].syntaxId = 0x12; // S7ANY
        // Calculate the data length in bytes
        uint16_t dataLengthBytes;
        if (packet->items[i].transportSize == 0x01) { // BOOL
            dataLengthBytes = (packet->items[i].length + 7) / 8;  // Convert bits to bytes
        } else {
            dataLengthBytes = packet->items[i].length;
        }
        packet->items[i].dataLengthBytes = dataLengthBytes;

        // Allocate memory for the item data and copy it
        if (dataLengthBytes > 0)
        {
          packet->items[i].data = (uint8_t*)malloc(dataLengthBytes);
          if (!packet->items[i].data) {
              s7_free_packet(packet); // Free previously allocated resources
               return -1;
          }
          if ((itemData + dataLengthBytes) > (data + dataLen)) //data section length check
          {
             s7_free_packet(packet);
             return -1;
          }
          memcpy(packet->items[i].data, itemData, dataLengthBytes);
          itemData += dataLengthBytes; // Move to the next item or end of data section
        }


    }
    return 0;

}

// Parses a Write Var Request
static int parse_s7_write_var_request(const unsigned char *param, int paramLen,  S7Packet *packet)
{
    // This is almost identical to Read Var Request, *until* you get to the data section
    int result = parse_s7_read_var_request(param, paramLen, packet); // Reuse the read_var_request parsing logic
     if (result != 0) {
        return result;
    }
     // S7 Write Var Request doesn't need to process data section here.  The data section is already handled in read_var_request
    return 0;

}

// Parses PLC Control (Start/Stop) Request
static int parse_s7_plc_control_request(const unsigned char *param, int paramLen, S7Packet *packet)
{
    S7PLCControlParam *plcControlParam = (S7PLCControlParam *)param;
    if ((size_t)paramLen < sizeof(S7PLCControlParam))
    {
       return -1;
    }
    packet->functionCode = plcControlParam->functionCode;
    // For PLC Start/Stop, we might want to store the 'method' field
    // to distinguish between Start and Stop commands.

    return 0;

}

// Parses S7 Request Download Request
static int parse_s7_req_download_request(const unsigned char *param, int paramLen, S7Packet *packet)
{
  S7ReqDownloadParam* reqDownloadParam = (S7ReqDownloadParam*)param;
   if ((size_t)paramLen < sizeof(S7ReqDownloadParam))
    {
       return -1;
    }
   packet->functionCode = reqDownloadParam->functionCode;
   packet->blockType = reqDownloadParam->blockType;
   packet->blockNumber = ntohl(reqDownloadParam->blockNumber);

  return 0;
}

// Parses S7 Download Block Request
static int parse_s7_download_block_request(const unsigned char *param, int paramLen,  S7Packet* packet)
{
  (void) paramLen;
  S7DownloadBlockParam* downloadBlockParam = (S7DownloadBlockParam*)param;
  packet->functionCode = downloadBlockParam->functionCode;

  return 0;

}

// Parses S7 Upload Request
static int parse_s7_upload_request(const unsigned char* param, int paramLen, S7Packet* packet)
{
  (void) paramLen;
  S7DownloadBlockParam* uploadBlockParam = (S7DownloadBlockParam*)param;
  packet->functionCode = uploadBlockParam->functionCode;
  return 0;
}

// Parses S7 Download and Upload Response
static int parse_s7_download_upload_response(const unsigned char *param, int paramLen, S7Packet *packet)
{
  (void) paramLen;
  S7DownloadUploadResponse* downloadUploadResp = (S7DownloadUploadResponse*)param;
  packet->functionCode = downloadUploadResp->functionCode;
  return 0;

}

int s7_protocol_init() {
    // Initialization logic, if any
    return 0;
}

int s7_protocol_parse(const unsigned char *data, int len, S7Packet *packet) {
    // 1. Parse TPKT Header
    if ((size_t)len < sizeof(TPKTHeader))  return -1;

    TPKTHeader *tpkt = (TPKTHeader *)data;
    if (tpkt->version != 3) return -1;

    int tpktLength = ntohs(tpkt->length);
    if (len < tpktLength) return -1;

    // 2. Parse COTP Header
    const unsigned char *cotpData = data + sizeof(TPKTHeader);
    COTPHeader *cotp = (COTPHeader *)cotpData;
    int cotpLength = cotp->length + 1;

    if (cotp->pduType != 0xF0 && cotp->pduType != 0xE0) {  // 0xF0: DT, 0xE0: CR
        return -1; // Not a supported COTP PDU type
    }
     // If it's a Connection Request (CR), we might want to handle it differently
    if (cotp->pduType == 0xE0) {
        // We could check for S7 communication setup here (function code 0xF0)
        // But for now, let's just continue.  You might want to add a specific
        // handler for COTP CR PDUs.
         packet->functionCode = S7_FUNCTION_SETUP_COMM; // Indicate COTP CR (Setup Communication)
         return 0; // Return, assuming we don't need to parse further for connection setup.

    }

    // 3. Parse S7 Header
    const unsigned char *s7Data = cotpData + cotpLength;
    int s7DataLength = tpktLength - sizeof(TPKTHeader) - cotpLength;
    if ((size_t)s7DataLength < sizeof(S7Header)) return -1;

    S7Header *s7Header = (S7Header *)s7Data;
    if (s7Header->protocolId != 0x32) return -1;
    packet->messageType = s7Header->messageType;
    packet->pduReference = ntohs(s7Header->pduReference); // Store PDU reference

    const unsigned char *s7Param = s7Data + sizeof(S7Header);
    int s7ParamLength = ntohs(s7Header->paramLength);
    const unsigned char *s7DataItem = s7Data + sizeof(S7Header) + s7ParamLength;
    int s7DataLen = ntohs(s7Header->dataLength);

    // 4. Parse S7 Parameter and Data (using lookup table)
    if (s7Header->messageType == 1) { // Job
        S7ParamParserReq parser = find_parser_req(s7Param[0]); // First byte of param is functionCode
        if (parser) {
             // 修正：传递正确的参数
             if (parser(s7Param, s7ParamLength, packet) != 0)
             {
               s7_free_packet(packet);
               return -1; // Parsing error
             }

        } else {
           // Unknown function code.  We could set an error, or just ignore it.
           return -1;
        }
    }
    else if (s7Header->messageType == 3) { // Ack-Data
        packet->errorClass = s7Param[2]; // In Ack-Data, error class is in param
        packet->errorCode = s7Param[3];

        int parserType;
        void *parser = find_parser_res(s7Param[0], &parserType);
        if(parser) {
            if (parserType == 0) { // S7ParamParserRes (has data)
                S7ParamParserRes resParser = (S7ParamParserRes)parser; // Cast to correct type
                if (resParser(s7Param, s7ParamLength, s7DataItem, s7DataLen, packet) != 0) {
                    s7_free_packet(packet);
                    return -1;
                }
            } else if (parserType == 1) { // S7ParamParserSimpleRes (NO data)
                S7ParamParserSimpleRes simpleParser = (S7ParamParserSimpleRes)parser; // Cast
                if (simpleParser(s7Param, s7ParamLength, packet) != 0) {
                    s7_free_packet(packet);
                    return -1;
                }
            } else {
                // Invalid parser type!  This should never happen if the table is correct.
                s7_free_packet(packet);
                return -1;
            }
        } else {
            // Unknown function code
            return -1;
        }
    }
    else {
      // Not a Job or Ack-Data message
      return -1;
    }
     //如果dataLen > 0, 且是Download Block请求, 保存block数据
    if (s7DataLen > 0 && packet->functionCode == S7_FUNCTION_DOWNLOAD_BLOCK)
    {
        packet->blockData = (uint8_t*)malloc(s7DataLen);
        if (!packet->blockData)
        {
          s7_free_packet(packet); // Free any previously allocated memory
          return -1;
        }
        memcpy(packet->blockData, s7DataItem, s7DataLen);
        packet->blockDataLen = s7DataLen;
    }

    return 0; // Success
}

void s7_protocol_cleanup() {
    // Cleanup logic, if any.
}
