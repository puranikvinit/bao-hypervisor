/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#ifndef __MBOX_K3_SEC_PROXY_H_
#define __MBOX_K3_SEC_PROXY_H_

#include <bao.h>
#include <plat/platform.h>
#include <stddef.h>
#include <stdint.h>
#include <types.h>

/**
 * @brief Defines the specific host function associated with a Secure Proxy
 * thread.
 */
typedef enum {
    HOST_FUNCTION_NOTIFY,
    HOST_FUNCTION_RESPONSE,
    HOST_FUNCTION_HIGH_PRIORITY,
    HOST_FUNCTION_LOW_PRIORITY,
    HOST_FUNCTION_NOTIFY_RESP,
} MBOX_K3_SEC_PROXY_HOST_FUNCTION;

/**
 * @brief Specifies the direction of data flow for a Secure Proxy thread.
 */
typedef enum {
    MSG_DRXN_WRITE = 0,
    MSG_DRXN_READ = 1,
} MBOX_K3_SEC_PROXY_MSG_DRXN;

/**
 * @brief Status codes returned by Secure Proxy APIs.
 */
typedef enum {
    STATUS_CODE_NO_ERROR = 0,
    STATUS_CODE_THREAD_CORRUPTED = -1,
    STATUS_CODE_INCORRECT_DRXN = -2,
    STATUS_CODE_NO_DATA = -4,
    STATUS_CODE_INVALID_MSG_LEN = -5,
    STATUS_CODE_THREAD_CLEAR_FAILED = -6,
} MBOX_K3_SEC_PROXY_STATUS_CODES;

/* bit indices */
#define MBOX_K3_SEC_PROXY_RT_THREAD_STATUS_OFFSET (0x0U)
#define MBOX_K3_SEC_PROXY_RT_THREAD_THRESHOLD_OFFSET (0x4U)

#define MBOX_K3_SEC_PROXY_RT_STATUS_ERROR_IDX (31)
#define MBOX_K3_SEC_PROXY_RT_STATUS_ERROR_MASK (1U << MBOX_K3_SEC_PROXY_RT_STATUS_ERROR_IDX)

#define MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_IDX (0)
#define MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_MASK (0xFFU << MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_IDX)

#define MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_OFFSET (0x1000U)

#define MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_DIR_IDX (31)
#define MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_DIR_MASK                                                \
    (1U << MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_DIR_IDX)

#define MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id) (0x1000U * (thread_id))

#define MBOX_K3_SEC_PROXY_DATA_START_OFFSET (0x4U)
#define MBOX_K3_SEC_PROXY_DATA_END_OFFSET (0x3CU) /* completion trigger offset */

/**
 * @brief Structure representing a message to be sent or received via Secure
 * Proxy.
 */
typedef struct {
    size_t len;       /**< Length of the message in bytes */
    uint32_t *buffer; /**< Pointer to the message data buffer */
} mbox_k3_sec_proxy_msg;

/**
 * @brief Hardware configuration for a Secure Proxy instance.
 */
typedef struct {
    /* note: declared as a 32-bit val because it is kept as such in u-boot
     * implementation. However, in J721E, there are only 2 supported sec_proxy
     * IDs:
     * 0 => NAVSS0_SEC_PROXY_0
     * 1 => MCU_NAVSS0_SEC_PROXY0
     * can modify type based on requirements...
     */
    uint32_t id; /**< Instance ID (e.g., NAVSS0_SEC_PROXY_0) */

    paddr_t rt_base; /**< Base address of Real-Time (RT) region */
    size_t rt_size;  /**< Size of RT region */

    paddr_t scfg_base; /**< Base address of Secure Configuration (SCFG) region */
    size_t scfg_size;  /**< Size of SCFG region */

    paddr_t data_base; /**< Base address of Data region */
    size_t data_size;  /**< Size of Data region */

    size_t max_msg_size;
} mbox_k3_sec_proxy_instance;

/**
 * @brief Configuration descriptor for a single Secure Proxy thread.
 */
typedef struct {
    uint8_t sec_proxy_thread_id;         /**< Secure Proxy thread ID */
    MBOX_K3_SEC_PROXY_MSG_DRXN msg_drxn; /**< Message direction (Read/Write) */
    uint8_t mbox_queue_depth;            /**< Depth of the mailbox queue */
    uint8_t host_id;                     /**< ID of the host associated with this thread */
    MBOX_K3_SEC_PROXY_HOST_FUNCTION
    host_function;               /**< Function/Role of the thread */
    uint16_t irq_line_threshold; /**< IRQ threshold configuration */
    uint16_t irq_line_error;     /**< IRQ error configuration */
} mbox_k3_sec_proxy_thread_desc;

/**
 * @brief Top-level descriptor aggregating the Secure Proxy instance and its
 * thread configurations.
 */
typedef struct {
    mbox_k3_sec_proxy_instance thread_inst; /**< Secure Proxy instance configuration */
    mbox_k3_sec_proxy_thread_desc sec_proxy_thread_desc[]; /**< Array of thread descriptors */
} mbox_k3_sec_proxy_desc;

// clang-format off
#define MBOX_K3_SEC_PROXY_THREAD_DESC_ENTRY(                                   \
    host, base_thread_id, notify_queue_depth, resp_queue_depth,                \
    high_priority_queue_depth, low_priority_queue_depth)                       \
  [base_thread_id] =                                                           \
      (mbox_k3_sec_proxy_thread_desc){                                         \
          .sec_proxy_thread_id = base_thread_id,                               \
          .msg_drxn = MSG_DRXN_READ,                                           \
          .mbox_queue_depth = notify_queue_depth,                              \
          .host_id = host,                                                     \
          .host_function = HOST_FUNCTION_NOTIFY},                              \
  [base_thread_id + 1] =                                                       \
      (mbox_k3_sec_proxy_thread_desc){                                         \
          .sec_proxy_thread_id = (base_thread_id + 1),                         \
          .msg_drxn = MSG_DRXN_READ,                                           \
          .mbox_queue_depth = resp_queue_depth,                                \
          .host_id = host,                                                     \
          .host_function = HOST_FUNCTION_RESPONSE},                            \
  [base_thread_id + 2] =                                                       \
      (mbox_k3_sec_proxy_thread_desc){                                         \
          .sec_proxy_thread_id = (base_thread_id + 2),                         \
          .msg_drxn = MSG_DRXN_WRITE,                                          \
          .mbox_queue_depth = high_priority_queue_depth,                       \
          .host_id = host,                                                     \
          .host_function = HOST_FUNCTION_HIGH_PRIORITY},                       \
  [base_thread_id + 3] =                                                       \
      (mbox_k3_sec_proxy_thread_desc){                                         \
          .sec_proxy_thread_id = (base_thread_id + 3),                         \
          .msg_drxn = MSG_DRXN_WRITE,                                          \
          .mbox_queue_depth = low_priority_queue_depth,                        \
          .host_id = host,                                                     \
          .host_function = HOST_FUNCTION_LOW_PRIORITY},                        \
  [base_thread_id + 4] =                                                       \
      (mbox_k3_sec_proxy_thread_desc) {                                        \
          .sec_proxy_thread_id = (base_thread_id + 4),                         \
          .msg_drxn = MSG_DRXN_WRITE,                                          \
          .mbox_queue_depth = 2, .host_id = host,                              \
          .host_function = HOST_FUNCTION_NOTIFY_RESP}
// clang-format on

extern mbox_k3_sec_proxy_desc sec_proxy_desc;

/**
 * @brief Verifies the status and configuration of a Secure Proxy thread.
 *
 * @param thread_id The ID of the thread to verify.
 * @param msg_drxn Expected message direction (MSG_DRXN_READ or MSG_DRXN_WRITE).
 *
 * @return int32_t STATUS_CODE_NO_ERROR on success, or respective error codes
 * on failure.
 */
int32_t mbox_k3_sec_proxy_verify_thread(uint8_t thread_id, uint8_t msg_drxn);

/**
 * @brief Reads a message from a specific Secure Proxy thread.
 *
 * @param thread_id The ID of the thread to read from.
 * @param msg Pointer to the structure where the read message will be stored.
 *
 * @return int32_t STATUS_CODE_NO_ERROR on success, or respective error codes
 * on failure.
 *
 * @notes
 * - does not support big-endian systems, current implementation only is
 * for little-endian.
 * - byte-ordering logic for trailing bytes assumes LSB-first memory layout.
 */
int32_t mbox_k3_sec_proxy_read(uint8_t thread_id, mbox_k3_sec_proxy_msg *msg);

/**
 * @brief Writes a message to a specific Secure Proxy thread.
 *
 * @param thread_id The ID of the thread to write to.
 * @param msg Pointer to the structure containing the message to send.
 *
 * @return int32_t STATUS_CODE_NO_ERROR on success, or an error code on
 * failure.
 *
 * @notes
 * - does not support big-endian systems, current implementation only is
 * for little-endian.
 * - byte-ordering logic for trailing bytes assumes LSB-first memory layout.
 */
int32_t mbox_k3_sec_proxy_write(uint8_t thread_id, mbox_k3_sec_proxy_msg *msg);

/**
 * @brief Clears all pending messages from a Secure Proxy thread.
 *
 * @param thread_id The ID of the thread to clear.
 *
 * @return int32_t STATUS_CODE_NO_ERROR on success, or an error code on failure.
 */
int32_t mbox_k3_sec_proxy_clear(uint8_t thread_id);

/**
 * @brief Performs a health check on a Secure Proxy thread and reports status.
 *
 * @param thread_id The ID of the thread to probe.
 *
 * @return int32_t STATUS_CODE_NO_ERROR on success, or respective error codes
 * on failure.
 */
int32_t mbox_k3_sec_proxy_probe(uint8_t thread_id);

#endif /* __MBOX_K3_SEC_PROXY_H_ */
