#include "arkime.h"
#include "s7-protocol.h"
#include <string.h>
#include <arpa/inet.h> // For htonl
#include <time.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h> // For va_list, etc.
#include <glib.h>

extern ArkimeConfig_t        config;

// Arkime 字段定义
static int s7FunctionCodeField;
static int s7DataBlockIdField; // Deprecated
static int s7ItemCountField;
static int s7TransportSizeField;
static int s7DataLengthField;
static int s7AreaField;
static int s7DBNumberField;
static int s7StartOffsetField;
static int s7ErrorClassField;
static int s7ErrorCodeField;
static int s7ReturnCodeField;
static int s7DataField;
static int s7PDUReferenceField;
static int s7MessageTypeField;
static int s7BlockTypeField;
static int s7BlockNumberField;
static int s7BlockDataField;

// 日志函数 (使用正确的格式化)
void s7_log(const char *format, ...) {
    va_list args;
    va_start(args, format);

    time_t timer;
    char buffer[26];
    struct tm tm_info;
    time(&timer);

    localtime_r(&timer, &tm_info); // 使用 localtime_r (线程安全)

    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", &tm_info);

    fprintf(stderr, "%s [s7_plugin] ", buffer);
    vfprintf(stderr, format, args);
    fprintf(stderr, "\n");
    va_end(args);
    fflush(stderr);  // 确保立即输出
}
/******************************************************************************/
// 插件初始化 (现在是 arkime_plugin_init, Arkime 会调用这个)
void arkime_plugin_init()
{
    s7_log("arkime_plugin_init() called");

    // 注册协议字段
        s7FunctionCodeField = arkime_field_define("s7", "integer",
        "s7.functionCode", "S7 Function Code", "s7.fc",
        "S7 function code",
        ARKIME_FIELD_TYPE_INT,  ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7ItemCountField = arkime_field_define("s7", "integer",
        "s7.itemCount", "S7 Item Count", "s7.items",
        "S7 item count",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7TransportSizeField = arkime_field_define("s7", "integer",
        "s7.transportSize", "S7 Transport Size", "s7.tsize",
        "S7 transport size",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
         "help", "BIT=1, BYTE/WORD/DWORD=2, COUNTER/TIMER=9, REAL=4",
        (char *)NULL);

    s7DataLengthField = arkime_field_define("s7", "integer",
        "s7.dataLength", "S7 Data Length", "s7.dlen",
        "S7 data length in bits",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7AreaField = arkime_field_define("s7", "lotext",
        "s7.area", "S7 Area", "s7.area",
        "S7 memory area",
        ARKIME_FIELD_TYPE_STR_HASH, ARKIME_FIELD_FLAG_CNT,
        "help", "PA=ProcessImageInput, PB=ProcessImageOutput, M=Merkers, DB=DataBlocks, CT=Counters, TM=Timers",
        (char *)NULL);

     s7DBNumberField = arkime_field_define("s7", "integer",
        "s7.dbNumber", "S7 DB Number", "s7.db",
        "S7 data block number",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7StartOffsetField = arkime_field_define("s7", "integer",
        "s7.startOffset", "S7 Start Offset", "s7.offset",
        "S7 start offset in bits",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7ErrorClassField = arkime_field_define("s7", "integer",
        "s7.errorClass", "S7 Error Class", "s7.eclass",
        "S7 error class",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

     s7ErrorCodeField = arkime_field_define("s7", "integer",
        "s7.errorCode", "S7 Error Code", "s7.ecode",
        "S7 error code",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

     s7ReturnCodeField = arkime_field_define("s7", "integer",
        "s7.returnCode", "S7 Return Code", "s7.rcode",
        "S7 return code for each item",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char*)NULL);

    s7DataField = arkime_field_define("s7", "string",
        "s7.data", "S7 Data", "s7.data",
        "S7 data value",
        ARKIME_FIELD_TYPE_STR_HASH,  0,
        (char *)NULL);

    // PDU Reference (for correlating requests and responses)
    s7PDUReferenceField = arkime_field_define("s7", "integer",
        "s7.pduReference", "S7 PDU Reference", "s7.pduref",
        "S7 PDU reference",
        ARKIME_FIELD_TYPE_INT,  ARKIME_FIELD_FLAG_CNT,
        (char *)NULL);

    s7MessageTypeField = arkime_field_define("s7", "integer",
        "s7.messageType", "S7 Message Type", "s7.mtype",
        "S7 message type",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        "help", "1=Job, 2=Ack, 3=Ack-Data, 7=UserData",
        (char *)NULL);

   s7BlockTypeField = arkime_field_define("s7", "lotext",
        "s7.blockType", "S7 Block Type", "s7.btype",
        "S7 Block Type",
        ARKIME_FIELD_TYPE_STR, ARKIME_FIELD_FLAG_CNT,
        "help", "B=Program, F=Data, O=Organization",
        (char*) NULL);

    s7BlockNumberField = arkime_field_define("s7", "integer",
        "s7.blockNumber", "S7 Block Number", "s7.bnum",
        "S7 Block Number",
        ARKIME_FIELD_TYPE_INT, ARKIME_FIELD_FLAG_CNT,
        (char*)NULL);

    s7BlockDataField = arkime_field_define("s7", "string",
        "s7.blockData", "S7 Block Data", "s7.bdata",
        "S7 Block Data",
        ARKIME_FIELD_TYPE_STR, 0,  // Don't cont, as block data can be large
        (char*)NULL);

    s7DataBlockIdField = arkime_field_define("s7", "integer",  // Deprecated, use s7.dbNumber
        "s7.dataBlockId", "S7 Data Block ID", "s7dbid",
        "S7 data block ID (Deprecated)",
        ARKIME_FIELD_TYPE_INT,  ARKIME_FIELD_FLAG_CNT | ARKIME_FIELD_FLAG_DISABLED,
        (char *)NULL);
    // 初始化 S7 解析库
    s7_protocol_init();

       // 注册统计信息
    //s7PacketsProcessed = 0; // 不需要手动初始化
    //arkime_plugins_add_stat("s7", "packetsProcessed", &s7PacketsProcessed);

    //  s7PluginStatusField = arkime_field_define("s7", "integer",
    //                                               "s7.pluginStatus", "S7 Plugin Status", "s7plugin.status",
    //                                              "S7 Plugin operational status",
    //                                               ARKIME_FIELD_TYPE_INT_HASH, 0, (char*)NULL);

    // 添加日志消息
    s7_log("S7 Plugin initialized successfully!");
}

/******************************************************************************/
// 预处理阶段
void s7_plugin_pre_process(ArkimeSession_t *session, const unsigned char *data, int len, int which, void *uw)
{
    (void) which;
    (void) uw;
    if(len < 7) return;
    if(data[0] != 0x03) return;
    if(data[5] != 0xf0 && data[5] !=0xe0) return;
    arkime_session_add_protocol(session, "s7");

    // 添加日志消息
    s7_log("S7 Plugin: pre_process called for session %p", session);
}
/******************************************************************************/
// 数据包解析函数
void s7_plugin_parser(ArkimeSession_t *session, const unsigned char *data, int len, int UNUSED(which))
{
    if (!arkime_session_has_protocol(session, "s7")) {
        return;
    }

     // 添加日志消息
    s7_log("S7 Plugin: parser called for session %p", session);

    //s7PacketsProcessed++; // 增加处理的数据包计数
    //arkime_field_int_add(s7PluginStatusField, session, 0); //假设开始是正常

    S7Packet s7packet;
    memset(&s7packet, 0, sizeof(s7packet));

    int result = s7_protocol_parse(data, len, &s7packet);

    if (result == 0) {
        // 解析成功，添加字段到 Arkime
        arkime_field_int_add(s7FunctionCodeField, session, s7packet.functionCode);
        arkime_field_int_add(s7ItemCountField,session, s7packet.itemCount);
        arkime_field_int_add(s7MessageTypeField, session, s7packet.messageType);
        arkime_field_int_add(s7PDUReferenceField, session, s7packet.pduReference);

        //处理块操作
        if (s7packet.functionCode == S7_FUNCTION_REQ_DOWNLOAD || s7packet.functionCode == S7_FUNCTION_DOWNLOAD_BLOCK ||
            s7packet.functionCode == S7_FUNCTION_START_UPLOAD || s7packet.functionCode == S7_FUNCTION_UPLOAD)
        {
          if (s7packet.blockType != 0)
          {
            char blockTypeStr[2] = {s7packet.blockType, 0}; // Convert to string
            arkime_field_string_add(s7BlockTypeField, session, blockTypeStr, strlen(blockTypeStr), TRUE);

          }
          arkime_field_int_add(s7BlockNumberField, session, s7packet.blockNumber);

          if (s7packet.blockData && s7packet.blockDataLen > 0)
          {
            //BASE64 encode
             arkime_field_string_add(s7BlockDataField, session, (char*)s7packet.blockData, s7packet.blockDataLen, TRUE);

          }
        }

        //处理items
        if (s7packet.items)
        {
             for (int i = 0; i < s7packet.itemCount; i++)
             {
                S7Item * item = &s7packet.items[i];
                if (item)
                {
                    // Add transport size, data length, return code
                    arkime_field_int_add(s7TransportSizeField, session, item->transportSize);
                    arkime_field_int_add(s7DataLengthField, session, item->length);
                    arkime_field_int_add(s7ReturnCodeField, session, item->returnCode);

                    // Add memory area
                    switch (item->area) {
                        case 0x81: arkime_field_string_add(s7AreaField, session, "PA", 2, TRUE); break; // Process Image Input
                        case 0x82: arkime_field_string_add(s7AreaField, session, "PB", 2, TRUE); break; // Process Image Output
                        case 0x83: arkime_field_string_add(s7AreaField, session, "M", 1, TRUE);  break; // Merkers
                        case 0x84: arkime_field_string_add(s7AreaField, session, "DB", 2, TRUE); break; // Data Blocks
                        case 0x1C:
                           arkime_field_string_add(s7AreaField, session, "CT", 2, TRUE);  break; //S7 Counters
                           break;
                        case 0x1D:
                            arkime_field_string_add(s7AreaField, session, "TM", 2, TRUE);  break; // S7 Timers
                        default: arkime_field_string_add(s7AreaField, session, "UNKNOWN", 7, TRUE); break;
                    }

                    arkime_field_int_add(s7DBNumberField,session, item->dbNumber);
                    arkime_field_int_add(s7StartOffsetField, session, item->startOffset);

                    // Add data (if available and successfully decoded)
                    if (item->data && item->dataLengthBytes > 0 ) {
                        char resultBuf[128]; // Buffer to store the decoded data, 足够大
                        if (s7_decode_data(item, resultBuf, sizeof(resultBuf))) // 确保 resultBuf 足够大
                        {
                           arkime_field_string_add(s7DataField, session, resultBuf, strlen(resultBuf), TRUE);
                        }

                    }

                }

             }
          }
       //add error code and class
       if (s7packet.errorClass != 0 || s7packet.errorCode !=0)
       {
          arkime_field_int_add(s7ErrorClassField, session, s7packet.errorClass);
          arkime_field_int_add(s7ErrorCodeField, session, s7packet.errorCode);
       }

        // 释放 items 数组, 使用帮助函数
      s7_free_packet(&s7packet);

    } else
    {
         //arkime_field_int_add(s7PluginStatusField, session, 1); //设置状态为错误
    }
}

/******************************************************************************/
// 插件退出函数
void s7_plugin_exit()
{
    // 目前没有特殊的清理工作
}

// Arkime 插件入口点 (只在一个文件中定义, 且调用 s7_plugin_init)
#ifndef UNIT_TEST
void arkime_plugin_load() {
    s7_log("arkime_plugin_load() called");
    arkime_plugin_init(); // 调用 Arkime 的初始化函数！
}
#endif
