// Shared status plumbing for the atecc608 module: the curated-status
// mapping, the last-error record, and the status text. Compiled on both the
// Pico target and the host test build (it depends only on cryptoauthlib's
// atca_status.h, not on pico-sdk).

#include "atecc608/atecc608_types.h"
#include "atecc608_int.h"

// Raw ATCA_STATUS of the last failed call (module storage; the API is
// single-threaded and blocking).
static ATCA_STATUS s_last_error = ATCA_SUCCESS;

atecc608_status_t atecc608_map_status(ATCA_STATUS atca_status)
{
    if (ATCA_SUCCESS == atca_status) {
        s_last_error = ATCA_SUCCESS;
        return ATECC608_OK;
    }

    s_last_error = atca_status;

    switch (atca_status) {
    case ATCA_BAD_PARAM:
    case ATCA_INVALID_SIZE:
    case ATCA_SMALL_BUFFER:
        return ATECC608_ERR_BAD_PARAM;

    case ATCA_NOT_INITIALIZED:
        return ATECC608_ERR_NOT_INIT;

    case ATCA_WAKE_FAILED:
    case ATCA_NO_DEVICES:
    case ATCA_TOO_MANY_COMM_RETRIES:
        return ATECC608_ERR_WAKE;

    case ATCA_COMM_FAIL:
    case ATCA_TX_FAIL:
    case ATCA_TIMEOUT:
    case ATCA_TX_TIMEOUT:
    case ATCA_RX_TIMEOUT:
        return ATECC608_ERR_COMM;

    case ATCA_RX_FAIL:
    case ATCA_RX_NO_RESPONSE:
    case ATCA_RX_CRC_ERROR:
    case ATCA_STATUS_CRC:
    case ATCA_PARITY_ERROR:
        return ATECC608_ERR_RX;

    case ATCA_EXECUTION_ERROR:
    case ATCA_FUNC_FAIL:
    case ATCA_BAD_OPCODE:
    case ATCA_PARSE_ERROR:
    case ATCA_STATUS_ECC:
    case ATCA_STATUS_SELFTEST_ERROR:
    case ATCA_STATUS_UNKNOWN:
    case ATCA_CHECKMAC_VERIFY_FAILED:
        return ATECC608_ERR_EXEC;

    case ATCA_NOT_LOCKED:
    case ATCA_USE_FLAGS_CONSUMED:
        return ATECC608_ERR_CHIP_STATE;

    default:
        return ATECC608_ERR;
    }
}

ATCA_STATUS atecc608_last_error(void)
{
    return s_last_error;
}

const char *atecc608_status_str(atecc608_status_t st)
{
    switch (st) {
    case ATECC608_OK:              return "ok";
    case ATECC608_ERR:             return "error";
    case ATECC608_ERR_BAD_PARAM:   return "bad parameter";
    case ATECC608_ERR_NOT_INIT:    return "not initialized";
    case ATECC608_ERR_WAKE:        return "wake handshake failed (chip absent or asleep)";
    case ATECC608_ERR_COMM:        return "I2C transmit failed";
    case ATECC608_ERR_RX:          return "I2C receive failed";
    case ATECC608_ERR_EXEC:        return "chip execution error";
    case ATECC608_ERR_CHIP_STATE:  return "chip state prevents operation";
    default:                       return "unknown status";
    }
}
