/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <drivers/k3_sec_proxy.h>

/**
 * @brief Reads a 32-bit value from a memory-mapped register.
 *
 * @param addr Base address of the peripheral or register block.
 * @param offset Offset from the base address to the specific register.
 *
 * @return The 32-bit value read from the register.
 */
static inline uint32_t read_reg(paddr_t addr, paddr_t offset)
{
    return *((volatile uint32_t*)((paddr_t)(addr + offset)));
}

/**
 * @brief Writes a 32-bit value to a memory-mapped register.
 *
 * @param addr Base address of the peripheral or register block.
 * @param offset Offset from the base address to the specific register.
 * @param value The 32-bit value to write.
 */
static inline void write_reg(paddr_t addr, paddr_t offset, uint32_t value)
{
    *((volatile uint32_t*)((paddr_t)(addr + offset))) = value;
}

/**
 * @brief Verifies the status and configuration of a Secure Proxy thread before
 * a transaction.
 *
 * @desc This function checks for thread corruption, validates the thread's
 * configured direction (read/write) against its intended usage, and ensures the
 * message queue is not empty if reading.
 *
 * @param thread_id The ID of the thread to verify.
 * @param msg_drxn Expected message direction (MSG_DRXN_READ or MSG_DRXN_WRITE).
 *
 * @return int32_t STATUS_CODE_NO_ERROR if the thread is valid and ready,
 * otherwise respective error codes.
 */
int32_t mbox_k3_sec_proxy_verify_thread(uint8_t thread_id, uint8_t msg_drxn)
{
    paddr_t thread_rt_base =
        sec_proxy_desc.thread_inst.rt_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);
    paddr_t thread_scfg_base =
        sec_proxy_desc.thread_inst.scfg_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);

    /* check for existing errors */
    if (read_reg(thread_rt_base, MBOX_K3_SEC_PROXY_RT_THREAD_STATUS_OFFSET) &
        MBOX_K3_SEC_PROXY_RT_STATUS_ERROR_MASK) {
        ERROR("secure_proxy_thread_%d corrupted", thread_id);
        return STATUS_CODE_THREAD_CORRUPTED;
    }

    /* validate thread drxn config */
    if ((read_reg(thread_scfg_base, MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_OFFSET) &
            MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_DIR_MASK) >>
            MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_DIR_IDX !=
        msg_drxn) {
        if (MSG_DRXN_WRITE == msg_drxn) {
            ERROR("secure_proxy_thread_%d cannot READ on WRITE thread", thread_id);
            return STATUS_CODE_INCORRECT_DRXN;
        } else {
            ERROR("secure_proxy_thread_%d cannot WRITE on READ thread", thread_id);
            return STATUS_CODE_INCORRECT_DRXN;
        }
    }

    /* check if msg queue has entries before txn attempt */
    if ((0 ==
            (read_reg(thread_rt_base, MBOX_K3_SEC_PROXY_RT_THREAD_STATUS_OFFSET) &
                MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_MASK)) &&
        (MSG_DRXN_READ == msg_drxn)) {
        ERROR("secure_proxy_thread_%d no entries in message queue", thread_id);
        return STATUS_CODE_NO_DATA;
    }

    return STATUS_CODE_NO_ERROR;
}

/*
 * read transaction:
 *
 * +-------------------------+
 * | 1. verify thread status |
 * +-----------+-------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 2. read whole words     | <---- | regs: base + DATA_START_OFFSET ... |
 * +-----------+-------------+       +------------------------------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 3. read & unpack trail  | <---- | reg: base + N                      |
 * |    bytes (little endian)|       | (extract from LSB)                 |
 * +-----------+-------------+       +------------------------------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 4. read trigger reg if  | <---- | trigger: base + DATA_END_OFFSET    |
 * |    not reached yet      |       +------------------------------------+
 * +-------------------------+
 */
int32_t mbox_k3_sec_proxy_read(uint8_t thread_id, mbox_k3_sec_proxy_msg* msg)
{
    /* verify thread status */
    int32_t read_status = mbox_k3_sec_proxy_verify_thread(thread_id, MSG_DRXN_READ);
    if (STATUS_CODE_NO_ERROR != read_status) {
        ERROR("secure_proxy_thread_%d thread verif failed", thread_id);
        return read_status;
    }

    /* perform read transaction */
    paddr_t data_reg = sec_proxy_desc.thread_inst.data_base +
        MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id) + MBOX_K3_SEC_PROXY_DATA_START_OFFSET;

    /* read whole words first */
    uint32_t word_iterator;
    size_t num_words = msg->len / sizeof(uint32_t);
    for (word_iterator = 0; word_iterator < num_words; word_iterator++) {
        ((uint32_t*)msg->buffer)[word_iterator] =
            read_reg(data_reg, word_iterator * sizeof(uint32_t));
    }

    /* read remaining bytes */
    uint32_t trail_bytes = msg->len % sizeof(uint32_t);
    if (0 != trail_bytes) {
        uint32_t data_trail = read_reg(data_reg, word_iterator++ * sizeof(uint32_t));

        size_t trail_iterator = msg->len - trail_bytes;
        while (trail_bytes--) {
            ((uint8_t*)msg->buffer)[trail_iterator++] = (uint8_t)(data_trail & 0xFFU);
            data_trail >>= 8;
        }
    }

    /* in case the completion trigger register is not accessed during the read,
     * the following access is performed, to mark the completion of the
     * transaction. */
    if ((MBOX_K3_SEC_PROXY_DATA_START_OFFSET + (word_iterator * sizeof(uint32_t))) <=
        MBOX_K3_SEC_PROXY_DATA_END_OFFSET) {
        read_reg(data_reg, MBOX_K3_SEC_PROXY_DATA_END_OFFSET - MBOX_K3_SEC_PROXY_DATA_START_OFFSET);
    }

    INFO("secure_proxy_thread_%d data READ success", thread_id);

    return read_status;
}

/*
 * write transaction:
 *
 * +-------------------------+
 * | 1. verify thread status |
 * +-----------+-------------+
 *             |
 *             v
 * +-----------+-------------+
 * | 2. check message length |
 * +-----------+-------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 3. write whole words    | ----> | regs: base + DATA_START_OFFSET ... |
 * +-----------+-------------+       +------------------------------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 4. pack & write trail   | ----> | reg: base + N                      |
 * |    bytes (little endian)|       | (right-aligned/LSB)                |
 * +-----------+-------------+       +------------------------------------+
 *             |
 *             v
 * +-----------+-------------+       +------------------------------------+
 * | 5. pad with zeros until | ----> | trigger: base + DATA_END_OFFSET    |
 * |    end offset (trigger) |       +------------------------------------+
 * +-------------------------+
 */
int32_t mbox_k3_sec_proxy_write(uint8_t thread_id, mbox_k3_sec_proxy_msg* msg)
{
    /* verify thread status */
    int32_t write_status = mbox_k3_sec_proxy_verify_thread(thread_id, MSG_DRXN_WRITE);
    if (STATUS_CODE_NO_ERROR != write_status) {
        ERROR("secure_proxy_thread_%d thread verif failed", thread_id);
        return write_status;
    }

    /* msg len check */
    if (msg->len > sec_proxy_desc.thread_inst.max_msg_size) {
        ERROR("secure_proxy_thread_%d msg len exceeds limit", thread_id);
        return STATUS_CODE_INVALID_MSG_LEN;
    }

    /* perform write transaction */
    paddr_t data_reg = sec_proxy_desc.thread_inst.data_base +
        MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id) + MBOX_K3_SEC_PROXY_DATA_START_OFFSET;

    /* write whole words first */
    uint32_t word_iterator;
    size_t num_words = msg->len / sizeof(uint32_t);
    for (word_iterator = 0; word_iterator < num_words; word_iterator++) {
        write_reg(data_reg, word_iterator * sizeof(uint32_t),
            ((uint32_t*)msg->buffer)[word_iterator]);
    }

    /* write remaining bytes */
    uint32_t trail_bytes = msg->len % sizeof(uint32_t);
    if (0 != trail_bytes) {
        uint32_t data_trail = 0;

        size_t trail_iterator = msg->len - trail_bytes;
        for (uint32_t i = 0; i < trail_bytes; i++) {
            data_trail |= (uint32_t)((uint8_t*)msg->buffer)[trail_iterator++] << (i * 8);
        }

        write_reg(data_reg, word_iterator++ * sizeof(uint32_t), data_trail);
    }

    /*
     * Pad the remaining registers with zeros up to the completion trigger offset.
     * The Secure Proxy hardware triggers the message transmission ONLY when
     * the last register at MBOX_K3_SEC_PROXY_DATA_END_OFFSET is written.
     */
    while ((MBOX_K3_SEC_PROXY_DATA_START_OFFSET + (word_iterator * sizeof(uint32_t))) <=
        MBOX_K3_SEC_PROXY_DATA_END_OFFSET) {
        write_reg(data_reg, word_iterator++ * sizeof(uint32_t), 0U);
    }

    INFO("secure_proxy_thread_%d data WRITE success", thread_id);

    return write_status;
}

int32_t mbox_k3_sec_proxy_clear(uint8_t thread_id)
{
    int32_t clear_status = mbox_k3_sec_proxy_verify_thread(thread_id, MSG_DRXN_READ);
    if (STATUS_CODE_NO_ERROR != clear_status) {
        ERROR("secure_proxy_thread_%d thread verif failed", thread_id);
        return clear_status;
    }

    paddr_t thread_rt_base =
        sec_proxy_desc.thread_inst.rt_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);
    paddr_t data_reg =
        sec_proxy_desc.thread_inst.data_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);

    uint32_t try_count = 10;
    while (0 !=
        (read_reg(thread_rt_base, MBOX_K3_SEC_PROXY_RT_THREAD_STATUS_OFFSET) &
            MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_MASK)) {
        if (0 == (try_count--)) {
            ERROR("secure_proxy_thread_%d mailbox clear failed", thread_id);
            return STATUS_CODE_THREAD_CLEAR_FAILED;
        }

        WARNING("secure_proxy_thread_%d mailbox clear in progress", thread_id);
        read_reg(data_reg, MBOX_K3_SEC_PROXY_DATA_END_OFFSET);
    }

    return STATUS_CODE_NO_ERROR;
}

int32_t mbox_k3_sec_proxy_probe(uint8_t thread_id)
{
    paddr_t thread_scfg_base =
        sec_proxy_desc.thread_inst.scfg_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);
    uint32_t config = read_reg(thread_scfg_base, MBOX_K3_SEC_PROXY_SCFG_THREAD_CTRL_OFFSET);

    paddr_t thread_rt_base =
        sec_proxy_desc.thread_inst.rt_base + MBOX_K3_SEC_PROXY_THREAD_OFFSET(thread_id);

    uint8_t hw_host = (config >> 8) & 0xFF;
    uint8_t expected_host = sec_proxy_desc.sec_proxy_thread_desc[thread_id].host_id;

    /* [step-1] verify thread access/host ownership */
    if (hw_host != expected_host) {
        ERROR("sec_proxy_thread_%d probe failed (hw_host=%d, expected=%d)", thread_id, hw_host,
            expected_host);
        return STATUS_CODE_THREAD_CORRUPTED;
    }

    /* [step-2] verify if thread is clean */
    int32_t probe_status = mbox_k3_sec_proxy_verify_thread(thread_id, MSG_DRXN_WRITE);
    if (STATUS_CODE_NO_ERROR != probe_status) {
        INFO("sec_proxy_thread_%d probe failed (error_id=%d)", thread_id, probe_status);
        return probe_status;
    }

    if (0 !=
        (read_reg(thread_rt_base, MBOX_K3_SEC_PROXY_RT_THREAD_STATUS_OFFSET) &
            MBOX_K3_SEC_PROXY_RT_STATUS_CUR_CNT_MASK)) {
        ERROR("secure_proxy_thread_%d probe failed (message queue not clean)", thread_id);
        return STATUS_CODE_DIRTY_HANDOFF;
    }

    /* [step-3] check pipeline health by pinging sysfw
     *
     * @notes
     * - the hook needs to be implemented by the platform, as the driver is protocol agnostic.
     */
    probe_status = mbox_k3_sec_proxy_ping_test(thread_id);
    if (STATUS_CODE_NO_ERROR != probe_status) {
        ERROR("sec_proxy_thread_%d probe failed (sysfw ping failure)", thread_id);
        return probe_status;
    }

    INFO("sec_proxy_thread_%d probe success", thread_id);
    return probe_status;
}

__attribute__((weak)) int32_t mbox_k3_sec_proxy_ping_test(uint8_t thread_id)
{
    UNUSED_ARG(thread_id);
    return STATUS_CODE_NO_ERROR;
}
