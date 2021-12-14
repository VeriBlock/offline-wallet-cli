// VeriBlock NodeCore
// Copyright 2017-2021 Xenios SEZC
// All rights reserved.
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

package veriblock;

import com.google.protobuf.ByteString;
import nodecore.api.grpc.*;
import nodecore.api.grpc.utilities.ByteStringAddressUtility;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.veriblock.core.DefaultOutput;
import org.veriblock.core.SharedConstants;
import org.veriblock.core.bitcoinj.Base58;
import org.veriblock.core.bitcoinj.Base59;
import org.veriblock.core.contracts.*;
import org.veriblock.core.types.Pair;
import org.veriblock.core.utilities.AddressUtility;
import org.veriblock.core.utilities.TransactionUtility;
import org.veriblock.core.utilities.Utility;
import org.veriblock.core.wallet.AddressManager;
import org.veriblock.core.wallet.AddressPubKey;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class OfflineTransactionUtilities {
    private static final Logger logger = LoggerFactory.getLogger(OfflineTransactionUtilities.class);

    public static byte[] generateSignedRegularTransaction(String sourceAddress, long sourceAmount, List<Output> outputs, long signatureIndex, AddressManager addressManager) {
        if (addressManager.get(sourceAddress) == null) {
            throw new IllegalArgumentException("The address " + sourceAddress + " is not contained in the specified wallet file!");
        }

        try {
            byte[] txid = calculateRegularTransactionTxID(sourceAddress, sourceAmount, outputs, signatureIndex);
            byte[] signature = addressManager.signMessage(txid, sourceAddress);

            RpcTransaction.Builder builder = RpcTransaction.newBuilder();

            builder.setTxId(ByteString.copyFrom(txid));
            builder.setSourceAddress(ByteString.copyFrom(Base58.decode(sourceAddress)));
            builder.setSourceAmount(sourceAmount);
            builder.setType(RpcTransaction.Type.STANDARD);
            builder.setTimestamp(Utility.getCurrentTimeSeconds());
            builder.setData(ByteString.copyFrom(new byte[]{}));

            for (Output output : outputs) {
                RpcOutput.Builder outputBuilder = builder.addOutputsBuilder();

                outputBuilder.setAddress(ByteString.copyFrom(output.getAddress().toByteArray()));
                outputBuilder.setAmount(output.getAmount().value());
            }

            RpcSignedTransaction.Builder signedTransactionBuilder = RpcSignedTransaction.newBuilder();
            signedTransactionBuilder.setPublicKey(ByteString.copyFrom(addressManager.getPublicKeyForAddress(sourceAddress).getEncoded()));
            signedTransactionBuilder.setSignatureIndex(signatureIndex);
            signedTransactionBuilder.setSignature(ByteString.copyFrom(signature));
            signedTransactionBuilder.setTransaction(builder);

            RpcTransactionUnion.Builder unionBuilder = RpcTransactionUnion.newBuilder();

            unionBuilder.setSigned(signedTransactionBuilder);

            return unionBuilder.build().toByteArray();
        } catch (Exception e) {
            logger.error("Unable to generate signed transaction", e);
            return null;
        }
    }


    public static byte[] calculateRegularTransactionTxID(String sourceAddress, long sourceAmount, List<Output> outputs, long signatureIndex) {
        byte[] txid = TransactionUtility.calculateTxIDByteArray(
                SharedConstants.STANDARD_TRANSACTION_ID,
                new Pair<>(sourceAddress, sourceAmount),
                outputs,
                signatureIndex);

        return txid;
    }

    public static byte[] compileSignedMultisigTransaction(RpcUnsignedMultisigTransactionWithIndex unsignedMultisigTransaction, String[] publicKeysOrAddresses, byte[][] signatures) {
        byte[] txid = OfflineTransactionUtilities.calculateMultisigTxID(unsignedMultisigTransaction.getUnsignedMultisigTansaction(), unsignedMultisigTransaction.getSignatureIndex());

        int validSignatures = 0;

        RpcMultisigBundle.Builder multisigBundleBuilder = RpcMultisigBundle.newBuilder();

        List<String> signingAddresses = new ArrayList<>();

        for (int i = 0; i < publicKeysOrAddresses.length; i++) {
            RpcMultisigSlot.Builder multisigSlotBuilder = RpcMultisigSlot.newBuilder();
            if (AddressUtility.isValidStandardAddress(publicKeysOrAddresses[i])) {
                multisigSlotBuilder.setOwnerAddress(ByteString.copyFrom(Base58.decode(publicKeysOrAddresses[i])));
                multisigSlotBuilder.setPopulated(false);
            } else {
                if (signatures[i] == null || signatures[i].length == 0) {
                    throw new IllegalArgumentException("Invalid signatures provided!\n" +
                            "Slot " + i + " was indicated as populated (public key provided) but there is no corresponding signature!");
                }

                byte[] publicKey = Utility.hexToBytes(publicKeysOrAddresses[i]);
                byte[] signature = signatures[i];
                String signingAddress = AddressUtility.addressFromPublicKey(publicKey);

                if (!AddressUtility.isSignatureValid(txid, signature, publicKey, signingAddress)) {
                    throw new IllegalArgumentException("The signature for address " + signingAddress + " does not sign the TxID " + Utility.bytesToHex(txid) + "!");
                } else {
                    validSignatures++;
                    multisigSlotBuilder.setPublicKey(ByteString.copyFrom(publicKey));
                    multisigSlotBuilder.setSignature(ByteString.copyFrom(signature));
                    multisigSlotBuilder.setPopulated(true);
                    signingAddresses.add(signingAddress);
                }
            }

            multisigBundleBuilder.addSlots(i, multisigSlotBuilder.build());
        }

        int m = AddressUtility.multisigAddressGetMandN(Base59.encode(unsignedMultisigTransaction.getUnsignedMultisigTansaction().getSourceAddress().toByteArray())).getFirst();

        if (m > validSignatures) {
            String signingAddressesStr = "";
            for (int i = 0; i < signingAddresses.size(); i++) {
                signingAddressesStr += signingAddresses.get(i) + " ";
            }
            throw new IllegalArgumentException("Only " + validSignatures + " valid signatures were provided (from addresses: " + signingAddressesStr.trim() + "), but " + m + " were required!");
        }

        RpcSignedMultisigTransaction.Builder signedMultisigTransactionBuilder = RpcSignedMultisigTransaction.newBuilder();

        signedMultisigTransactionBuilder.setSignatureBundle(multisigBundleBuilder.build());
        signedMultisigTransactionBuilder.setTransaction(unsignedMultisigTransaction.getUnsignedMultisigTansaction());
        signedMultisigTransactionBuilder.setSignatureIndex(unsignedMultisigTransaction.getSignatureIndex());

        RpcTransactionUnion.Builder txUnionBuilder = RpcTransactionUnion.newBuilder();
        txUnionBuilder.setSignedMultisig(signedMultisigTransactionBuilder);

        return txUnionBuilder.build().toByteArray();
    }

    public static byte[] calculateMultisigTxID(RpcTransaction transaction, long signatureIndex) {
        List<Output> outputs = new ArrayList<>();

        for (int i = 0; i < transaction.getOutputsCount(); i++) {
            RpcOutput output = transaction.getOutputs(i);
            outputs.add(new DefaultOutput(ByteStringAddressUtility.parseProperAddressTypeAutomatically(output.getAddress()), output.getAmount()));
        }

        return calculateMultisigTxID(
                ByteStringAddressUtility.parseProperAddressTypeAutomatically(transaction.getSourceAddress()),
                transaction.getSourceAmount(),
                outputs,
                signatureIndex);
    }

    public static byte[] calculateMultisigTxID(String sourceAddress, long sourceAmount, List<Output> outputs, long signatureIndex) {
        return TransactionUtility.calculateTxIDByteArray(
                SharedConstants.MULTISIG_TRANSACTION_ID,
                new Pair<>(sourceAddress, sourceAmount),
                outputs,
                signatureIndex);
    }

    public static byte[] generateUnsignedMultisigTransaction(String sourceAddress, long sourceAmount, List<Output> outputs, long signatureIndex) {
        try {
            RpcTransaction.Builder txBuilder = RpcTransaction.newBuilder();

            txBuilder.setTxId(ByteString.copyFrom(calculateMultisigTxID(sourceAddress, sourceAmount, outputs, signatureIndex)));
            txBuilder.setSourceAddress(ByteString.copyFrom(Base59.decode(sourceAddress)));
            txBuilder.setSourceAmount(sourceAmount);
            txBuilder.setType(RpcTransaction.Type.MULTISIG);
            txBuilder.setTimestamp(Utility.getCurrentTimeSeconds());
            txBuilder.setData(ByteString.copyFrom(new byte[]{}));

            for (Output output : outputs) {
                RpcOutput.Builder outputBuilder = txBuilder.addOutputsBuilder();
                outputBuilder.setAddress(ByteString.copyFrom(output.getAddress().toByteArray()));
                outputBuilder.setAmount(output.getAmount().value());
            }

            RpcUnsignedMultisigTransactionWithIndex.Builder unsignedMultisigTransactionBuilder = RpcUnsignedMultisigTransactionWithIndex.newBuilder();
            unsignedMultisigTransactionBuilder.setUnsignedMultisigTansaction(txBuilder);
            unsignedMultisigTransactionBuilder.setSignatureIndex(signatureIndex);

            return unsignedMultisigTransactionBuilder.build().toByteArray();
        } catch (Exception e) {
            logger.error("Unable to generate unsigned multisig transaction", e);
            return null;
        }
    }

    private byte[] signHexMessage(byte[] message, String address, AddressManager addressManager) {
        return addressManager.signMessage(message, address);
    }

    private AddressPubKey getNewAddress(AddressManager addressManager) {
        try {
            return addressManager.getNewAddress();
        } catch (IOException e) {
            logger.error("Unable to generate new address", e);
            return null;
        }
    }

}
