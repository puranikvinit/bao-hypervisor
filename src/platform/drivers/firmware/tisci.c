/**
 * SPDX-License-Identifier: Apache-2.0
 * Copyright (c) Bao Project and Contributors. All rights reserved.
 */

#include <drivers/tisci.h>

/**
 * @brief Prepares the TISCI message header.
 *
 * Assigns a new sequence ID to the message and sets the 'ACK On Processed' (AOP) flag
 * to ensure the DMSC sends a response.
 *
 * @param ctx The driver context containing the sequence ID counter.
 * @param tx_buf Pointer to the transmit buffer containing the message header.
 * @param tx_len Length of the transmit buffer.
 *
 * @return TISCI_STATUS_CODE_NO_ERROR on success, error code on failure.
 */
static int32_t _setup_hdr(tisci_ctx* ctx, void* tx_buf, size_t tx_len)
{
    tisci_msg_header* msg_hdr;

    if (tx_len > TISCI_MSG_MAX_SIZE || tx_len < sizeof(tisci_msg_header)) {
        return TISCI_STATUS_CODE_INVALID_MSG_LEN;
    }

    msg_hdr = (tisci_msg_header*)tx_buf;

    /* increment and assign sequence ID for tracking this specific transaction */
    msg_hdr->seq_id = ++ctx->seq_id;
    msg_hdr->msg_flags |= TISCI_MSG_REQ_FLAG_AOP;

    return TISCI_STATUS_CODE_NO_ERROR;
}

/**
 * @brief Receives a response from the TISCI channel.
 *
 * This function polls the receive channel for a response. It verifies:
 * 1. The message was received successfully.
 * 2. The received sequence ID matches the expected one (from the context).
 * 3. The response has the ACK flag set.
 *
 * It checks up to TISCI_MSG_NUM_RETRIES times to handle mismatched messages (e.g. stale responses).
 * The actual timeout is handled by the underlying recv operation.
 *
 * @param ctx The driver context.
 * @param chan_id The channel ID to receive from.
 * @param rx_buf Pointer to the receive buffer.
 * @param rx_len Length of the receive buffer.
 * @param expected_seq_id Expected Sequence ID for the received message.
 *
 * @return TISCI_STATUS_CODE_NO_ERROR on success, error code on failure.
 */
static int32_t _get_rsp(tisci_ctx* ctx, uint8_t chan_id, void* rx_buf, size_t rx_len,
    uint8_t expected_seq_id)
{
    tisci_msg_header* msg_hdr;

    /* Validate buffer size before receiving to prevent overflow */
    if (rx_len > TISCI_MSG_MAX_SIZE) {
        ERROR("channel_%d expected msg len too long", chan_id);
        return TISCI_STATUS_CODE_INVALID_MSG_LEN;
    }

    unsigned int retry_iterator = TISCI_MSG_NUM_RETRIES;
    for (; retry_iterator > 0; retry_iterator--) {
        int32_t recv_status = ctx->ops.recv(chan_id, rx_buf, rx_len);
        if (TISCI_STATUS_CODE_NO_ERROR != recv_status) {
            ERROR("channel_%d tisci msg rcv failed", chan_id);
            return TISCI_STATUS_CODE_MSG_RCV_FAILED;
        }

        msg_hdr = (tisci_msg_header*)rx_buf;
        /* Verify that the response corresponds to the request we just sent */
        if (msg_hdr->seq_id == expected_seq_id) {
            break;
        } else {
            WARNING("channel_%d unexpected seq_id (rcvd=%d, expected=%d)", chan_id, msg_hdr->seq_id,
                expected_seq_id);
        }
    }

    if (0 == retry_iterator) {
        ERROR("channel_%d timed out waiting for msg", chan_id);
        return TISCI_STATUS_CODE_MSG_RX_TIMEOUT;
    }

    /* Check if the DMSC acknowledged the request */
    if (0 == (msg_hdr->msg_flags & TISCI_MSG_RSP_FLAG_ACK)) {
        ERROR("channel_%d no ack rcvd", chan_id);
        return TISCI_STATUS_CODE_NO_ACK_RCVD;
    }

    return TISCI_STATUS_CODE_NO_ERROR;
}

/**
 * @brief Performs a full TISCI transaction (Send + Receive).
 *
 * Wraps the send and receive operations. It first sends the request,
 * then immediately waits for the corresponding response.
 *
 * @param ctx The driver context.
 * @param chan_id The channel ID for the transaction.
 * @param tx_buf Pointer to the transmit buffer.
 * @param tx_len Length of data to transmit.
 * @param rx_buf Pointer to the receive buffer.
 * @param rx_len Length of the receive buffer.
 * @param expected_seq_id Expected Sequence ID for the received message.
 *
 * @return TISCI_STATUS_CODE_NO_ERROR on success, error code on failure.
 */
static int32_t _perform_txn(tisci_ctx* ctx, uint8_t chan_id, void* tx_buf, size_t tx_len,
    void* rx_buf, size_t rx_len, uint8_t seq_id)
{
    int32_t txn_status = ctx->ops.send(chan_id, tx_buf, tx_len);
    if (TISCI_STATUS_CODE_NO_ERROR != txn_status) {
        ERROR("channel_%d txn - write failed", chan_id);
        return TISCI_STATUS_CODE_MSG_SEND_FAILED;
    }

    txn_status = _get_rsp(ctx, chan_id, rx_buf, rx_len, seq_id);
    if (TISCI_STATUS_CODE_NO_ERROR != txn_status) {
        ERROR("channel_%d txn - read failed", chan_id);
        return txn_status;
    }

    return TISCI_STATUS_CODE_NO_ERROR;
}

int32_t tisci_get_revision(tisci_ctx* ctx, uint8_t host_id, uint8_t chan_id,
    tisci_msg_version_rsp* ver_rsp)
{
    tisci_msg_header msg_header = {
        .host_id = host_id,
        .type = TISCI_MSG_VERSION,
    };

    /* critical section - aquire a spinlock on hdr setup to ensure atomic updates to seq_id and
     * store them for the current txn */
    spin_lock(&(ctx->seq_id_lock));

    int32_t rev_status = _setup_hdr(ctx, &msg_header, sizeof(msg_header));
    if (TISCI_STATUS_CODE_NO_ERROR != rev_status) {
        ERROR("channel_%d msg hdr setup failed", chan_id);
        spin_unlock(&(ctx->seq_id_lock));
        return rev_status;
    }

    uint8_t cur_seq_id = ctx->seq_id;
    spin_unlock(&(ctx->seq_id_lock));

    rev_status = _perform_txn(ctx, chan_id, &msg_header, sizeof(msg_header), ver_rsp,
        sizeof(*ver_rsp), cur_seq_id);
    if (TISCI_STATUS_CODE_NO_ERROR != rev_status) {
        ERROR("channel_%d tisci txn failed", chan_id);
        return rev_status;
    }

    return TISCI_STATUS_CODE_NO_ERROR;
}
