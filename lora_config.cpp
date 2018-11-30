#ifndef __LORAMAC_CRYPTO_H__
#define __LORAMAC_CRYPTO_H__

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "LoRaMacTypes.h"
#include "LoRaMacMessageTypes.h"



/*!
 * Start value for unicast keys enumeration
 */
#define LORAMAC_CRYPTO_UNICAST_KEYS     0

/*!
 * Start value for multicast keys enumeration
 */
#define LORAMAC_CRYPTO_MULITCAST_KEYS   127

/*!
 * LoRaMac Crypto key identifier
 */
typedef enum eKeyIdentifier
{
    /*!
     * Application root key
     */
    APP_KEY = 0,
    /*!
     * Network root key
     */
    NWK_KEY,
    /*!
     * Join session integrity key
     */
    J_S_INT_KEY,
    /*!
     * Join session encryption key
     */
    J_S_ENC_KEY,
    /*!
     * Forwarding Network session integrity key
     */
    F_NWK_S_INT_KEY,
    /*!
     * Serving Network session integrity key
     */
    S_NWK_S_INT_KEY,
    /*!
     * Network session encryption key
     */
    NWK_S_ENC_KEY,
    /*!
     * Application session key
     */
    APP_S_KEY,
    /*!
     * Multicast key encryption key
     */
    MC_KE_KEY = LORAMAC_CRYPTO_MULITCAST_KEYS,
    /*!
     * Multicast root key index 0
     */
    MC_KEY_0,
    /*!
     * Multicast Application session key index 0
     */
    MC_APP_S_KEY_0,
    /*!
     * Multicast Network session key index 0
     */
    MC_NWK_S_KEY_0,
    /*!
     * Multicast root key index 1
     */
    MC_KEY_1,
    /*!
     * Multicast Application session key index 1
     */
    MC_APP_S_KEY_1,
    /*!
     * Multicast Network session key index 1
     */
    MC_NWK_S_KEY_1,
    /*!
     * Multicast root key index 2
     */
    MC_KEY_2,
    /*!
     * Multicast Application session key index 2
     */
    MC_APP_S_KEY_2,
    /*!
     * Multicast Network session key index 2
     */
    MC_NWK_S_KEY_2,
    /*!
     * Multicast root key index 3
     */
    MC_KEY_3,
    /*!
     * Multicast Application session key index 3
     */
    MC_APP_S_KEY_3,
    /*!
     * Multicast Network session key index 3
     */
    MC_NWK_S_KEY_3,
    /*!
     * No Key
     */
    NO_KEY,
}KeyIdentifier_t;

/*!
 * LoRaMac Crypto join-request / rejoin type identifier
 */
typedef enum eJoinReqIdentifier
{
    /*!
     * Rejoin type 0
     */
    RE_JOIN_REQ_0 = 0x00,
    /*!
     * Rejoin type 1
     */
    RE_JOIN_REQ_1 = 0x01,
    /*!
     * Rejoin type 2
     */
    RE_JOIN_REQ_2 = 0x02,
    /*!
     * Join-request
     */
    JOIN_REQ = 0xFF,
}JoinReqIdentifier_t;

/*!
 * LoRaWAN specification version
 */
typedef enum eLoRaWANSpecVersion
{
    /*!
     * Version 1.0.2
     */
    V1_0_2 = 0,
    /*!
     * Version 1.1.0
     */
    V1_1_0 = 1,
}LoRaWANSpecVersion_t;

/*!
 * LoRaMac Cryto Status
 */
typedef enum eLoRaMacCryptoStatus
{
    /*!
     * No error occurred
     */
    LORAMAC_CRYPTO_SUCCESS = 0,
    /*!
     * MIC does not match
     */
    LORAMAC_CRYPTO_FAIL_MIC,
    /*!
     * Address does not match
     */
    LORAMAC_CRYPTO_FAIL_ADDRESS,
    /*!
     * JoinNonce was not greater than previous one.
     */
    LORAMAC_CRYPTO_FAIL_JOIN_NONCE,
    /*!
     * RJcount0 reached 2^16-1
     */
    LORAMAC_CRYPTO_FAIL_RJCOUNT0_OVERFLOW,
    /*!
     * FCntUp/Down check failed
     */
    LORAMAC_CRYPTO_FAIL_FCNT,
    /*!
     * Not allowed parameter value
     */
    LORAMAC_CRYPTO_FAIL_PARAM,
    /*!
     * Null pointer exception
     */
    LORAMAC_CRYPTO_ERROR_NPE,
    /*!
     * Invalid key identifier exception
     */
    LORAMAC_CRYPTO_ERROR_INVALID_KEY_ID,
    /*!
     * Invalid address identifier exception
     */
    LORAMAC_CRYPTO_ERROR_INVALID_ADDR_ID,
    /*!
     * Invalid LoRaWAN specification version
     */
    LORAMAC_CRYPTO_ERROR_INVALID_VERSION,
    /*!
     * Incompatible buffer size
     */
    LORAMAC_CRYPTO_ERROR_BUF_SIZE,
    /*!
     * The secure element reports an error
     */
    LORAMAC_CRYPTO_ERROR_SECURE_ELEMENT_FUNC,
    /*!
     * Error from parser reported
     */
    LORAMAC_CRYPTO_ERROR_PARSER,
    /*!
     * Error from serializer reported
     */
    LORAMAC_CRYPTO_ERROR_SERIALIZER,
    /*!
     * RJcount1 reached 2^16-1 which should never happen
     */
    LORAMAC_CRYPTO_ERROR_RJCOUNT1_OVERFLOW,
    /*!
     * Undefined Error occurred
     */
    LORAMAC_CRYPTO_ERROR,
}LoRaMacCryptoStatus_t;

/*!
 * Signature of callback function to be called by the LoRaMac Crypto module when the
 * non-volatile context have to be stored. It is also possible to save the entire
 * crypto module context.
 *
 */
typedef void ( *EventNvmCtxChanged )( void );

/*!
 * Initialization of LoRaMac Crypto module
 * It sets initial values of volatile variables and assigns the non-volatile context.
 *
 * \param[IN]     version             - LoRaWAN specification Version
 * \param[IN]     cryptoNvmCtxChanged - Callback function which will be called  when the
 *                                      non-volatile context have to be stored.
 * \retval                            - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoInit( LoRaWANSpecVersion_t version, EventNvmCtxChanged cryptoNvmCtxChanged );

/*!
 * Restores the internal nvm context from passed pointer.
 *
 * \param[IN]     version          - LoRaWAN specification Version
 * \param[IN]     cryptoNmvCtx     - Pointer to non-volatile crypto module context to be restored.
 * \retval                         - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoRestoreNvmCtx( LoRaWANSpecVersion_t version, void* cryptoNvmCtx );

/*!
 * Returns a pointer to the internal non-volatile context.
 *
 * \param[IN]     version          - LoRaWAN specification Version
 * \param[IN]     cryptoNvmCtxSize - Size of the module non-volatile context
 * \retval                         - Points to a structure where the module store its non-volatile context
 */
void* LoRaMacCryptoGetNvmCtx( LoRaWANSpecVersion_t version, size_t* cryptoNvmCtxSize );

/*!
 * Sets a key
 *
 * \param[IN]     version        - LoRaWAN specification Version
 * \param[IN]     keyID          - Key identifier
 * \param[IN]     key            - Key value (16 byte), if its a multicast key it must be encrypted with McKEKey
 * \retval                       - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoSetKey( LoRaWANSpecVersion_t version, KeyIdentifier_t keyID, uint8_t* key );

/*!
 * Prepares the join-request message.
 * It computes the mic and add it to the message.
 *
 * \param[IN]     version        - LoRaWAN specification Version
 * \param[IN/OUT] macMsg         - Join-request message object
 * \retval                       - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoPrepareJoinRequest( LoRaWANSpecVersion_t version, LoRaMacMessageJoinRequest_t* macMsg );

/*!
 * Prepares a rejoin-request type 1 message.
 * It computes the mic and add it to the message.
 *
 * \param[IN]     version        - LoRaWAN specification Version
 * \param[IN/OUT] macMsg         - Rejoin message object
 * \retval                       - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoPrepareReJoinType1( LoRaWANSpecVersion_t version, LoRaMacMessageReJoinType1_t* macMsg );

/*!
 * Prepares a rejoin-request type 0 or 2 message.
 * It computes the mic and add it to the message.
 *
 * \param[IN]     version        - LoRaWAN specification Version
 * \param[IN/OUT] macMsg         - Rejoin message object
 * \retval                       - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoPrepareReJoinType0or2( LoRaWANSpecVersion_t version, LoRaMacMessageReJoinType0or2_t* macMsg );

/*!
 * Handles the join-accept message.
 * It decrypts the message, verifies the MIC and if successful derives the session keys.
 *
 * \param[IN]     version        - LoRaWAN specification Version
 * \param[IN]     joinReqType    - Type of last join-request or rejoin which triggered the join-accept response
 * \param[IN]     joinEUI        - Join server EUI (8 byte)
 * \param[IN/OUT] macMsg         - Join-accept message object
 * \retval                       - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoHandleJoinAccept( LoRaWANSpecVersion_t version, JoinReqIdentifier_t joinReqType, uint8_t* joinEUI, LoRaMacMessageJoinAccept_t* macMsg );

/*!
 * Secures a message (encryption + integrity).
 *
 * \param[IN]     version         - LoRaWAN specification Version
 * \param[IN]     fCntUp          - Uplink sequence counter
 * \param[IN]     txDr            - Data rate used for the transmission
 * \param[IN]     txCh            - Index of the channel used for the transmission
 * \param[IN/OUT] macMsg          - Data message object
 * \retval                        - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoSecureMessage( LoRaWANSpecVersion_t version, uint32_t fCntUp, uint8_t txDr, uint8_t txCh, LoRaMacMessageData_t* macMsg );

/*!
 * Unsecures a message (decryption + integrity verification).
 *
 * \param[IN]     version         - LoRaWAN specification Version
 * \param[IN]     addrID          - Address identifier
 * \param[IN]     address         - Address
 * \param[IN]     fCntID          - Frame counter identifier
 * \param[IN]     fCntDown        - Downlink sequence counter
 * \param[IN/OUT] macMsg          - Data message object
 * \retval                        - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoUnsecureMessage( LoRaWANSpecVersion_t version, AddressIdentifier_t addrID, uint32_t address, FCntIdentifier_t fCntID, uint32_t fCntDown, LoRaMacMessageData_t* macMsg );

/*!
 * Derives the McKEKey from the AppKey or NwkKey.
 *
 * McKEKey = aes128_encrypt(NwkKey or AppKey , nonce | DevEUI  | pad16)
 *
 * \param[IN]     version         - LoRaWAN specification Version
 * \param[IN]     keyID           - Key identifier of the root key to use to perform the derivation ( NwkKey or AppKey )
 * \param[IN]     nonce           - Nonce value ( nonce <= 15)
 * \param[IN]     devEUI          - DevEUI Value
 * \retval                        - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoDeriveMcKEKey( LoRaWANSpecVersion_t version, KeyIdentifier_t keyID, uint16_t nonce, uint8_t* devEUI );

/*!
 * Derives a Multicast group key pair ( McAppSKey, McNwkSKey ) from McKey
 *
 * McAppSKey = aes128_encrypt(McKey, 0x01 | McAddr | pad16)
 * McNwkSKey = aes128_encrypt(McKey, 0x02 | McAddr | pad16)
 *
 * \param[IN]     version         - LoRaWAN specification Version
 * \param[IN]     addrID          - Address identifier to select the multicast group
 * \param[IN]     mcAddr          - Multicast group address (4 bytes)
 * \retval                        - Status of the operation
 */
LoRaMacCryptoStatus_t LoRaMacCryptoDeriveMcSessionKeyPair( LoRaWANSpecVersion_t version, AddressIdentifier_t addrID, uint32_t mcAddr );

/*! \} addtogroup LORAMAC */

#endif // __LORAMAC_CRYPTO_H__
secure-element header
/*!
 * \file      secure-element.h
 *
 * \brief     Secure Element driver API
 *
 * \copyright Revised BSD License, see section \ref LICENSE.
 *
 * \code
 *                ______                              _
 *               / _____)             _              | |
 *              ( (____  _____ ____ _| |_ _____  ____| |__
 *               \____ \| ___ |    (_   _) ___ |/ ___)  _ \
 *               _____) ) ____| | | || |_| ____( (___| | | |
 *              (______/|_____)_|_|_| \__)_____)\____)_| |_|
 *              (C)2013-2017 Semtech
 *
 *               ___ _____ _   ___ _  _____ ___  ___  ___ ___
 *              / __|_   _/_\ / __| |/ / __/ _ \| _ \/ __| __|
 *              \__ \ | |/ _ \ (__| ' <| _| (_) |   / (__| _|
 *              |___/ |_/_/ \_\___|_|\_\_| \___/|_|_\\___|___|
 *              embedded.connectivity.solutions===============
 *
 * \endcode
 *
 * \author    Miguel Luis ( Semtech )
 *
 * \author    Gregory Cristian ( Semtech )
 *
 * \author    Daniel Jaeckle ( STACKFORCE )
 *
 * \author    Johannes Bruder ( STACKFORCE )
 *
 */
#ifndef __SECURE_ELEMENT_H__
#define __SECURE_ELEMENT_H__

#include <stdint.h>
#include "LoRaMacCrypto.h"

/*!
 * Return values.
 */
typedef enum eSecureElementStatus
{
    /*!
     * No error occurred
     */
    SECURE_ELEMENT_SUCCESS = 0,
    /*!
     * CMAC does not match
     */
    SECURE_ELEMENT_FAIL_CMAC,
    /*!
     * Null pointer exception
     */
    SECURE_ELEMENT_ERROR_NPE,
    /*!
     * Invalid key identifier exception
     */
    SECURE_ELEMENT_ERROR_INVALID_KEY_ID,
    /*!
     * Invalid LoRaWAN specification version
     */
    SECURE_ELEMENT_ERROR_INVALID_LORAWAM_SPEC_VERSION,
    /*!
     * Incompatible buffer size
     */
    SECURE_ELEMENT_ERROR_BUF_SIZE,
    /*!
     * Undefined Error occurred
     */
    SECURE_ELEMENT_ERROR,
}SecureElementStatus_t;

/*!
 * Signature of callback function to be called by the Secure Element driver when the
 * non volatile context have to be stored.
 *
 */
typedef void ( *EventNvmCtxChanged )( void );

/*!
 * Initialization of Secure Element driver
 *
 * \param[IN]     version                   - LoRaWAN specification Version
 * \param[IN]     seNvmCtxChanged           - Callback function which will be called  when the
 *                                            non-volatile context have to be stored.
 * \retval                                  - Status of the operation
 */
SecureElementStatus_t SecureElementInit( LoRaWANSpecVersion_t version, EventNvmCtxChanged seNvmCtxChanged );

/*!
 * Restores the internal nvm context from passed pointer.
 *
 * \param[IN]     version          - LoRaWAN specification Version
 * \param[IN]     seNvmCtx         - Pointer to non-volatile module context to be restored.
 * \retval                         - Status of the operation
 */
SecureElementStatus_t SecureElementRestoreNvmCtx( LoRaWANSpecVersion_t version, void* seNvmCtx );

/*!
 * Returns a pointer to the internal non-volatile context.
 *
 * \param[IN]     version         - LoRaWAN specification Version
 * \param[IN]     seNvmCtxSize    - Size of the module non volatile context
 * \retval                        - Points to a structure where the module store its non volatile context
 */
void* SecureElementGetNvmCtx( LoRaWANSpecVersion_t version, size_t* seNvmCtxSize );

/*!
 * Sets a key
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[IN]  keyID          - Key identifier
 * \param[IN]  key            - Key value
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementSetKey( LoRaWANSpecVersion_t version, KeyIdentifier_t keyID, uint8_t* key );

/*!
 * Computes a CMAC
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[IN]  buffer         - Data buffer
 * \param[IN]  size           - Data buffer size
 * \param[IN]  keyID          - Key identifier to determine the AES key to be used
 * \param[OUT] cmac           - Computed cmac
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementComputeAesCmac( LoRaWANSpecVersion_t version, uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint32_t* cmac );

/*!
 * Verifies a CMAC (computes and compare with expected cmac)
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[IN]  buffer         - Data buffer
 * \param[IN]  size           - Data buffer size
 * \param[in]  expectedCmac   - Expected cmac
 * \param[IN]  keyID          - Key identifier to determine the AES key to be used
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementVerifyAesCmac( LoRaWANSpecVersion_t version, uint8_t* buffer, uint16_t size, uint32_t expectedCmac, KeyIdentifier_t keyID );

/*!
 * Encrypt a buffer
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[IN]  buffer         - Data buffer
 * \param[IN]  size           - Data buffer size
 * \param[IN]  keyID          - Key identifier to determine the AES key to be used
 * \param[OUT] encBuffer      - Encrypted buffer
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementAesEncrypt( LoRaWANSpecVersion_t version, uint8_t* buffer, uint16_t size, KeyIdentifier_t keyID, uint8_t* encBuffer );

/*!
 * Derives and store a key
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[IN]  input          - Input data from which the key is derived ( 16 byte )
 * \param[IN]  rootKeyID      - Key identifier of the root key to use to perform the derivation
 * \param[IN]  targetKeyID    - Key identifier of the key which will be derived
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementDeriveAndStoreKey( LoRaWANSpecVersion_t version, uint8_t* input, KeyIdentifier_t rootKeyID, KeyIdentifier_t targetKeyID );

/*!
 * Generates a random number
 *
 * \param[IN]  version        - LoRaWAN specification Version
 * \param[OUT] randomNum      - 32 bit random number
 * \retval                    - Status of the operation
 */
SecureElementStatus_t SecureElementRandomNumber( LoRaWANSpecVersion_t version, uint32_t* randomNum );

#endif //  __SECURE_ELEMENT_H__
