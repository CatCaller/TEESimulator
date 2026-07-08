package org.matrix.TEESimulator.interception.keystore.shim

import android.hardware.security.keymint.Algorithm
import android.hardware.security.keymint.BlockMode
import android.hardware.security.keymint.Digest
import android.hardware.security.keymint.KeyPurpose
import android.hardware.security.keymint.PaddingMode
import android.os.RemoteException
import android.system.keystore2.IKeystoreOperation
import java.security.KeyPair
import java.security.SecureRandom
import java.security.Signature
import java.security.SignatureException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import org.matrix.TEESimulator.attestation.KeyMintAttestation
import org.matrix.TEESimulator.logging.KeyMintParameterLogger
import org.matrix.TEESimulator.logging.SystemLogger

// A sealed interface to represent the different cryptographic operations we can perform.
private sealed interface CryptoPrimitive {
    fun update(data: ByteArray?): ByteArray?

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray?

    fun abort()
}

// Helper object to map KeyMint constants to JCA algorithm strings.
private object JcaAlgorithmMapper {
    fun mapSignatureAlgorithm(params: KeyMintAttestation): String {
        val digest =
            when (params.digest.firstOrNull()) {
                Digest.SHA_2_256 -> "SHA256"
                Digest.SHA_2_384 -> "SHA384"
                Digest.SHA_2_512 -> "SHA512"
                else -> "NONE"
            }
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.EC -> "ECDSA"
                Algorithm.RSA -> "RSA"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported signature algorithm: ${params.algorithm}"
                    )
            }
        return "${digest}with${keyAlgo}"
    }

    fun mapCipherAlgorithm(params: KeyMintAttestation): String {
        val keyAlgo =
            when (params.algorithm) {
                Algorithm.RSA -> "RSA"
                Algorithm.AES -> "AES"
                else ->
                    throw IllegalArgumentException(
                        "Unsupported cipher algorithm: ${params.algorithm}"
                    )
            }
        val blockMode =
            when (params.blockMode.firstOrNull()) {
                BlockMode.ECB -> "ECB"
                BlockMode.CBC -> "CBC"
                BlockMode.GCM -> "GCM"
                else -> "ECB" // Default for RSA
            }
        val padding =
            when (params.padding.firstOrNull()) {
                PaddingMode.NONE -> "NoPadding"
                PaddingMode.PKCS7 -> "PKCS7Padding"
                PaddingMode.RSA_PKCS1_1_5_ENCRYPT -> "PKCS1Padding"
                PaddingMode.RSA_OAEP -> "OAEPPadding"
                else -> "NoPadding" // Default for GCM
            }
        return "$keyAlgo/$blockMode/$padding"
    }
}

// Concrete implementation for Signing.
private class Signer(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initSign(keyPair.private)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray {
        if (data != null) update(data)
        return this.signature.sign()
    }

    override fun abort() {}
}

// Concrete implementation for Verification.
private class Verifier(keyPair: KeyPair, params: KeyMintAttestation) : CryptoPrimitive {
    private val signature: Signature =
        Signature.getInstance(JcaAlgorithmMapper.mapSignatureAlgorithm(params)).apply {
            initVerify(keyPair.public)
        }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) signature.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) update(data)
        if (signature == null) throw SignatureException("Signature to verify is null")
        if (!this.signature.verify(signature)) {
            // Throwing an exception is how Keystore signals verification failure.
            throw SignatureException("Signature verification failed")
        }
        // A successful verification returns no data.
        return null
    }

    override fun abort() {}
}

// Concrete implementation for Encryption/Decryption.
private class CipherPrimitive(
    keyPair: KeyPair,
    params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val cipher: Cipher =
        Cipher.getInstance(JcaAlgorithmMapper.mapCipherAlgorithm(params)).apply {
            val key = if (opMode == Cipher.ENCRYPT_MODE) keyPair.public else keyPair.private
            init(opMode, key)
        }

    override fun update(data: ByteArray?): ByteArray? =
        if (data != null) cipher.update(data) else null

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        if (data != null) cipher.doFinal(data) else cipher.doFinal()

    override fun abort() {}
}

// Concrete implementation for symmetric Encryption/Decryption (AES / 3DES).
// Handles the IV/nonce for CBC and GCM block modes. On ENCRYPT the caller does not supply an IV,
// so one is generated and prepended to the first output chunk (matching KeyMint's behaviour of
// returning the IV to the client). On DECRYPT the IV/nonce is taken from the operation params.
private class SecretCipherPrimitive(
    private val secretKey: SecretKey,
    private val params: KeyMintAttestation,
    private val opMode: Int,
) : CryptoPrimitive {
    private val blockMode = params.blockMode.firstOrNull()
    private val transformation = JcaAlgorithmMapper.mapCipherAlgorithm(params)
    private val cipher: Cipher = Cipher.getInstance(transformation)
    private var ivEmitted = false
    private var generatedIv: ByteArray? = null

    init {
        val needsIv = blockMode == BlockMode.CBC || blockMode == BlockMode.GCM
        if (opMode == Cipher.ENCRYPT_MODE) {
            if (needsIv) {
                val ivLen = if (blockMode == BlockMode.GCM) 12 else 16
                val iv = ByteArray(ivLen).also { SecureRandom().nextBytes(it) }
                generatedIv = iv
                cipher.init(opMode, secretKey, buildSpec(iv))
            } else {
                cipher.init(opMode, secretKey)
            }
        } else {
            if (needsIv) {
                val iv =
                    params.nonce
                        ?: throw IllegalArgumentException("Missing IV/nonce for decrypt operation")
                cipher.init(opMode, secretKey, buildSpec(iv))
            } else {
                cipher.init(opMode, secretKey)
            }
        }
    }

    private fun buildSpec(iv: ByteArray) =
        if (blockMode == BlockMode.GCM) {
            val macBits = if (params.macLength > 0) params.macLength else 128
            GCMParameterSpec(macBits, iv)
        } else {
            IvParameterSpec(iv)
        }

    // Prepend the generated IV to the first output produced during an encrypt operation.
    private fun maybePrependIv(out: ByteArray?): ByteArray? {
        if (opMode != Cipher.ENCRYPT_MODE || ivEmitted) return out
        val iv = generatedIv ?: return out
        ivEmitted = true
        return iv + (out ?: ByteArray(0))
    }

    override fun update(data: ByteArray?): ByteArray? =
        maybePrependIv(if (data != null) cipher.update(data) else null)

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? =
        maybePrependIv(if (data != null) cipher.doFinal(data) else cipher.doFinal())

    override fun abort() {}
}

// Concrete implementation for HMAC signing/verification with a symmetric key.
private class MacPrimitive(secretKey: SecretKey, params: KeyMintAttestation) : CryptoPrimitive {
    private val mac: Mac =
        Mac.getInstance(secretKey.algorithm).apply { init(secretKey) }

    override fun update(data: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        return null
    }

    override fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        if (data != null) mac.update(data)
        val computed = mac.doFinal()
        // VERIFY passes the expected MAC as `signature`; SIGN returns the computed MAC.
        if (signature != null) {
            if (!computed.contentEquals(signature))
                throw SignatureException("HMAC verification failed")
            return null
        }
        return computed
    }

    override fun abort() {}
}

/**
 * A software-only implementation of a cryptographic operation. This class acts as a controller,
 * delegating to a specific cryptographic primitive based on the operation's purpose.
 */
class SoftwareOperation
private constructor(private val txId: Long, private val primitive: CryptoPrimitive) {

    // Asymmetric (KeyPair-backed) operations: SIGN / VERIFY / ENCRYPT / DECRYPT.
    constructor(
        txId: Long,
        keyPair: KeyPair,
        params: KeyMintAttestation,
    ) : this(txId, selectAsymmetricPrimitive(txId, keyPair, params))

    // Symmetric (SecretKey-backed) operations: AES/3DES cipher + HMAC.
    constructor(
        txId: Long,
        secretKey: SecretKey,
        params: KeyMintAttestation,
    ) : this(txId, selectSymmetricPrimitive(txId, secretKey, params))

    fun update(data: ByteArray?): ByteArray? {
        try {
            return primitive.update(data)
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to update operation.", e)
            throw e
        }
    }

    fun finish(data: ByteArray?, signature: ByteArray?): ByteArray? {
        try {
            val result = primitive.finish(data, signature)
            SystemLogger.info("[SoftwareOp TX_ID: $txId] Finished operation successfully.")
            return result
        } catch (e: Exception) {
            SystemLogger.error("[SoftwareOp TX_ID: $txId] Failed to finish operation.", e)
            // Re-throw the exception so the binder can report it to the client.
            throw e
        }
    }

    fun abort() {
        primitive.abort()
        SystemLogger.debug("[SoftwareOp TX_ID: $txId] Operation aborted.")
    }

    companion object {
        private fun logPurpose(txId: Long, params: KeyMintAttestation) {
            val purpose = params.purpose.firstOrNull()
            val purposeName = KeyMintParameterLogger.purposeNames[purpose] ?: "UNKNOWN"
            SystemLogger.debug("[SoftwareOp TX_ID: $txId] Initializing for purpose: $purposeName.")
        }

        private fun selectAsymmetricPrimitive(
            txId: Long,
            keyPair: KeyPair,
            params: KeyMintAttestation,
        ): CryptoPrimitive {
            logPurpose(txId, params)
            return when (params.purpose.firstOrNull()) {
                KeyPurpose.SIGN -> Signer(keyPair, params)
                KeyPurpose.VERIFY -> Verifier(keyPair, params)
                KeyPurpose.ENCRYPT -> CipherPrimitive(keyPair, params, Cipher.ENCRYPT_MODE)
                KeyPurpose.DECRYPT -> CipherPrimitive(keyPair, params, Cipher.DECRYPT_MODE)
                else ->
                    throw UnsupportedOperationException(
                        "Unsupported operation purpose: ${params.purpose.firstOrNull()}"
                    )
            }
        }

        private fun selectSymmetricPrimitive(
            txId: Long,
            secretKey: SecretKey,
            params: KeyMintAttestation,
        ): CryptoPrimitive {
            logPurpose(txId, params)
            return when (params.purpose.firstOrNull()) {
                KeyPurpose.ENCRYPT -> SecretCipherPrimitive(secretKey, params, Cipher.ENCRYPT_MODE)
                KeyPurpose.DECRYPT -> SecretCipherPrimitive(secretKey, params, Cipher.DECRYPT_MODE)
                KeyPurpose.SIGN,
                KeyPurpose.VERIFY -> MacPrimitive(secretKey, params)
                else ->
                    throw UnsupportedOperationException(
                        "Unsupported symmetric operation purpose: ${params.purpose.firstOrNull()}"
                    )
            }
        }
    }
}

/** The Binder interface for our [SoftwareOperation]. */
class SoftwareOperationBinder(private val operation: SoftwareOperation) :
    IKeystoreOperation.Stub() {

    @Throws(RemoteException::class)
    override fun update(input: ByteArray?): ByteArray? {
        return operation.update(input)
    }

    @Throws(RemoteException::class)
    override fun finish(input: ByteArray?, signature: ByteArray?): ByteArray? {
        return operation.finish(input, signature)
    }

    @Throws(RemoteException::class)
    override fun abort() {
        operation.abort()
    }
}
