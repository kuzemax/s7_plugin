#ifndef S7_PROTOCOL_H
#define S7_PROTOCOL_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>  // 添加

#ifdef __cplusplus
extern "C" {
#endif

// S7 Function Codes (更全面的列表)
#define S7_FUNCTION_READ_VAR        0x04
#define S7_FUNCTION_WRITE_VAR       0x05
#define S7_FUNCTION_REQ_DOWNLOAD    0x1A
#define S7_FUNCTION_DOWNLOAD_BLOCK  0x1B
#define S7_FUNCTION_DOWNLOAD_ENDED  0x1C
#define S7_FUNCTION_START_UPLOAD    0x1D
#define S7_FUNCTION_UPLOAD          0x1E
#define S7_FUNCTION_END_UPLOAD      0x1F
#define S7_FUNCTION_PLC_START       0x28
#define S7_FUNCTION_PLC_STOP        0x29
#define S7_FUNCTION_SETUP_COMM      0xF0 // Setup Communication (COT PDU的一部分)

// S7 Error Codes (部分)
#define S7_ERR_NO_ERROR             0x00
#define S7_ERR_INVALID_FUNCTION     0x01 // Function not implemented
#define S7_ERR_ADDRESS_OUT_OF_RANGE 0x05
#define S7_ERR_DATA_TYPE_NOT_SUPPORTED 0x06
#define S7_ERR_DATA_TYPE_INCONSISTENT 0x07
#define S7_ERR_OBJECT_DOES_NOT_EXIST 0x0A
#define S7_ERR_ACCESS_DENIED 0x8401 // Example

//Arkime flags
#define S7_FLAGS (1 << 0)

// S7 Item Structure (用于请求和响应)
typedef struct {
    uint8_t  syntaxId;        // 0x10 for ANY, 0x12 for item data in response
    uint8_t  transportSize;
    uint16_t length;          //  bits for BOOL, bytes for others
    uint8_t  area;
    uint16_t dbNumber;
    uint32_t startOffset;     // in bits
    uint8_t  returnCode;     // For response
    uint8_t *data;           // For response: Pointer to the data
    uint32_t dataLengthBytes; // For response: Length of 'data' in bytes
} S7Item;

// S7 Packet Structure
typedef struct {
    uint8_t   messageType;  // S7 Message Type (Job, Ack, Ack-Data, UserData)
    uint8_t   functionCode;
    uint8_t   itemCount;
    S7Item   *items;
    uint8_t   errorClass;
    uint8_t   errorCode;
    uint16_t  pduReference; // Added PDU Reference
    // Add more fields as needed (e.g., for block operations)
    uint8_t   blockType;     // For Download/Upload
    uint32_t  blockNumber;   // For Download/Upload
    uint8_t * blockData;    // Raw block data
    uint32_t  blockDataLen; //length of blockData
} S7Packet;

// Function prototypes
int s7_protocol_init();
int s7_protocol_parse(const unsigned char *data, int len, S7Packet *packet);
void s7_protocol_cleanup();
void s7_free_packet(S7Packet *packet); // Helper function to free packet resources
char* s7_decode_data(const S7Item *item, char * resultBuf, size_t bufSize); //helper function to decode S7 data

// 函数指针类型 (请求)：参数为 param, paramLen, packet
typedef int (*S7ParamParserReq)(const unsigned char *param, int paramLen, S7Packet *packet);

// 函数指针类型 (响应)：参数为 param, paramLen, data, dataLen, packet
typedef int (*S7ParamParserRes)(const unsigned char *param, int paramLen, const unsigned char *data, int dataLen, S7Packet *packet);

// NEW: Function pointer type (responses WITHOUT data): param, paramLen, packet
typedef int (*S7ParamParserSimpleRes)(const unsigned char *param, int paramLen, S7Packet *packet);

#ifdef __cplusplus
}
#endif

#endif // S7_PROTOCOL_H
