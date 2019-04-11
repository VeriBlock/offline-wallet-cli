// VeriBlock NodeCore
// Copyright 2017-2019 Xenios SEZC
// All rights reserved.
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

package veriblock;

import nodecore.api.grpc.VeriBlockMessages;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.veriblock.core.DefaultOutput;
import org.veriblock.core.contracts.AddressManager;
import org.veriblock.core.contracts.Output;
import org.veriblock.core.utilities.AddressUtility;
import org.veriblock.core.utilities.Utility;
import org.veriblock.core.wallet.Address;

import java.util.ArrayList;
import java.util.List;

public class CommandProcessor {
    private static final Logger logger = LoggerFactory.getLogger(CommandProcessor.class);

    public AddressManager addressManager;

    enum ArgumentType {
        standard_address {
            @Override
            public boolean validate(String toValidate) {
                return AddressUtility.isValidStandardAddress(toValidate);
            }
        },
        multisig_address {
            @Override
            public boolean validate(String toValidate) {
                return AddressUtility.isValidMultisigAddress(toValidate);
            }
        },
        standard_or_multisig_address {
            @Override
            public boolean validate(String toValidate) {
                return AddressUtility.isValidStandardOrMultisigAddress(toValidate);
            }
        },
        vbk_amount_string {
            @Override
            public boolean validate(String toValidate) {
                try {
                    long value = Utility.convertDecimalCoinToAtomicLong(toValidate);
                    if (value > 0) {
                        return true;
                    }
                } catch (Exception e) {}
                return false;
            }
        },
        positive_or_zero_long_value {
            @Override
            public boolean validate(String toValidate) {
                try {
                    long result = Long.parseLong(toValidate);
                    return result >= 0;
                } catch (Exception e) {}
                return false;
            }
        },
        positive_long_value {
            @Override
            public boolean validate(String toValidate) {
                try {
                    long result = Long.parseLong(toValidate);
                    return result > 0;
                } catch (Exception e) {}
                return false;
            }
        },
        multisig_m_value {
            @Override
            public boolean validate(String toValidate) {
                try {
                    int result = Integer.parseInt(toValidate);
                    return result > 0 && result <= 58;
                } catch (Exception e) {}
                return false;
            }
        },
        unsigned_multisig_transaction {
            @Override
            public boolean validate(String toValidate) {
                try {
                    byte[] transactionBytes = Utility.hexToBytes(toValidate);
                    VeriBlockMessages.UnsignedMultisigTransactionWithIndex.parseFrom(transactionBytes);

                    return true;
                } catch (Exception e) { }
                return false;
            }
        },
        comma_separated_standard_addresses {
            @Override
            public boolean validate(String toValidate) {
                try {
                    String[] addresses = toValidate.split(",");
                    for (int i = 0; i < addresses.length; i++) {
                        if (!AddressUtility.isValidStandardAddress(addresses[i])) {
                            return false;
                        }
                    }
                    return true;
                } catch (Exception e) {}
                return false;
            }
        },
        comma_separated_public_keys_or_addresses {
            @Override
            public boolean validate(String toValidate) {
                String[] publicKeysOrAddresses = toValidate.split(",");

                if (publicKeysOrAddresses.length < 2 || publicKeysOrAddresses.length > 58) {
                    return false;
                }

                for (int i = 0; i < publicKeysOrAddresses.length; i++) {
                    String addressOrPublicKey = publicKeysOrAddresses[i];
                    if (!AddressUtility.isValidStandardAddress(addressOrPublicKey)) {
                        if (!Utility.isHex(addressOrPublicKey)) {
                            return false;
                        }
                        if (addressOrPublicKey.length() != 0 && (addressOrPublicKey.length() != 176)) {
                            return false;
                        }
                    }
                }

                return true;
            }
        },
        comma_separated_signatures {
            @Override
            public boolean validate(String toValidate) {
                String[] signatures = toValidate.split(",");

                if (signatures.length < 2 || signatures.length > 58) {
                    return false;
                }

                for (String signature : signatures) {
                    if (!Utility.isHex(signature)) {
                        return false;
                    }

                    if (signature.length() != 0 && (signature.length() < 120 || signature.length() > 144)) {
                        return false;
                    }
                }

                return true;
            }
        },
        hex_string {
            @Override
            public boolean validate(String toValidate) {
                return Utility.isHex(toValidate);
            }
        },
        string {
            @Override
            public boolean validate(String toValidate) {
                return toValidate != null && toValidate.length() > 0;
            }
        };

        public abstract boolean validate(String toValidate);
    }

    static class Argument {
        private final ArgumentType argumentType;
        private final String name;
        private final boolean required;
        Argument(ArgumentType argumentType, String name, boolean required) {
            this.argumentType = argumentType;
            this.name = name;
            this.required = required;
        }

        ArgumentType getArgumentType() {
            return argumentType;
        }

        String getName() {
            return name;
        }

        boolean isRequired() {
            return required;
        }
    }

    enum Command {
        help {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);
                try {
                    String message = "";

                    message += "Available commands:\n";

                    for (Command commandEnum : Command.values()) {
                        message += commandEnum.getSyntaxMessage() + "\n" + commandEnum.getPurposeMessage() + "\n\n";
                    }

                    return message;
                } catch (Exception e) {
                    return e.getMessage();
                }
            }
        },
        getnewaddress {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                if (addressManager.isLocked()) {
                    throw new CommandExecutionException("Wallet must be unlocked to generate a new address");
                }

                try {
                    return addressManager.getNewAddress().getHash();
                } catch (Exception e) {
                    throw new CommandExecutionException(e.getMessage(), e);
                }
            }
        },
        signhexmessage {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                if (addressManager.isLocked()) {
                    throw new CommandExecutionException("Wallet must be unlocked to sign a message");
                }

                String address = args[0];
                byte[] message = Utility.hexToBytes(args[1]);
                byte[] signedMessage = addressManager.signMessage(message, address);
                byte[] publicKey = addressManager.getPublicKeyForAddress(address).getEncoded();

                if (!AddressUtility.isSignatureValid(message, signedMessage, publicKey, address)) {
                   return "Unable to generate a valid signature";
                }

                String msg =
                        "Address: " + address + "\n" +
                        "Message: " + Utility.bytesToHex(message) + "\n" +
                        "Public Key: " + Utility.bytesToHex(publicKey) + "\n" +
                        "Signature: " + Utility.bytesToHex(signedMessage);

                return msg;
            }
        },
        makesignedstandardtx {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                if (addressManager.isLocked()) {
                    throw new CommandExecutionException("Wallet must be unlocked to create a signed transaction");
                }

                String sourceAddress = args[0];
                long outputAmount = Utility.convertDecimalCoinToAtomicLong(args[1]);
                long fee = Utility.convertDecimalCoinToAtomicLong(args[3]);
                long sourceAmount = outputAmount + fee;
                String destinationAddress = args[2];
                List<Output> outputs = new ArrayList<>();
                outputs.add(new DefaultOutput(destinationAddress, outputAmount));
                long signatureIndex = Long.parseLong(args[4]);

                byte[] signedTransaction = OfflineTransactionUtilities.generateSignedRegularTransaction(sourceAddress, sourceAmount, outputs, signatureIndex, addressManager);
                byte[] txid = OfflineTransactionUtilities.calculateRegularTransactionTxID(sourceAddress, sourceAmount, outputs, signatureIndex);

                String msg = "Raw signed transaction: " + Utility.bytesToHex(signedTransaction) + "\n" +
                        "TxID: " + Utility.bytesToHex(txid);

                return msg;
            }
        },
        generatemultisigaddress {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                String[] addresses = args[0].split(",");
                int mValue = Integer.parseInt(args[1]);

                if (mValue > addresses.length) {
                    return "A multisig address cannot be generated with an m value (" + mValue + ") greater than " +
                            "the number of addresses comprising the multisig group (" + addresses.length + ")!";
                }

                try {
                    String address =  AddressUtility.multisigAddressFromAddressesAndMOfN(addresses, mValue);
                    if (address == null) {
                        return "Unable to generate a multisig address!";
                    }
                    return address;
                } catch (Exception e) {
                    return e.getMessage();
                }
            }
        },
        makeunsignedmultisigtx {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                String sourceAddress = args[0];
                long outputAmount = Utility.convertDecimalCoinToAtomicLong(args[1]);
                long fee = Utility.convertDecimalCoinToAtomicLong(args[3]);
                long sourceAmount = outputAmount + fee;
                String destinationAddress = args[2];
                List<Output> outputs = new ArrayList<>();
                outputs.add(new DefaultOutput(destinationAddress, outputAmount));
                long signatureIndex = Long.parseLong(args[4]);

                byte[] transaction = OfflineTransactionUtilities.generateUnsignedMultisigTransaction(sourceAddress, sourceAmount, outputs, signatureIndex);
                byte[] txid = OfflineTransactionUtilities.calculateMultisigTxID(sourceAddress, sourceAmount, outputs, signatureIndex);

                String msg = "";
                if (transaction != null) {
                    msg += "Raw transaction: " + Utility.bytesToHex(transaction) + "\n";
                    msg += "TxID: " + Utility.bytesToHex(txid) + "\n";
                } else {
                    msg = "Unable to create the unsigned multisig transaction!";
                }

                return msg;
            }
        },
        compilesignedmultisigtx {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                byte[] rawUnsignedMultisigTransaction = Utility.hexToBytes(args[0]);
                String[] publicKeysOrAddresses = args[1].split(",");
                String[] signaturesHex = args[2].split(",");
                byte[][] signatures = new byte[signaturesHex.length][];
                for (int i = 0; i < signaturesHex.length; i++) {
                    if (signaturesHex[i].equals("")) {
                        signatures[i] = null;
                    } else {
                        signatures[i] = Utility.hexToBytes(signaturesHex[i]);
                    }
                }

                VeriBlockMessages.UnsignedMultisigTransactionWithIndex unsignedTransaction;
                try {
                     unsignedTransaction = VeriBlockMessages.UnsignedMultisigTransactionWithIndex.parseFrom(rawUnsignedMultisigTransaction);

                     byte[] transaction = OfflineTransactionUtilities.compileSignedMultisigTransaction(unsignedTransaction, publicKeysOrAddresses, signatures);

                     return "Signed multisig transaction: " + Utility.bytesToHex(transaction);
                } catch (Exception e) {
                    return "The provided multisig transaction could not be compiled with the provided addresses/public_keys and signatures!\n" +
                            e.getMessage();
                }
            }
        },
        getalladdresses {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                List<Address> addresses = addressManager.getAll();

                String msg = "";

                for (int i = 0; i < addresses.size(); i++) {
                    msg += addresses.get(i).getHash() + "\n";
                }

                return msg.trim();
            }
        },
        encryptwallet {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                char[] passphrase = args[0].toCharArray();

                try {
                    boolean result = addressManager.encryptWallet(passphrase);
                    if (result) {
                        return "Wallet successfully encrypted with passphrase";
                    } else {
                        return "Wallet could not be encrypted";
                    }
                } catch (Exception e) {
                    throw new CommandExecutionException(e.getMessage(), e);
                }
            }
        },
        decryptwallet {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                char[] passphrase = args[0].toCharArray();

                try {
                    boolean result = addressManager.decryptWallet(passphrase);
                    if (result) {
                        return "Wallet successfully decrypted with passphrase";
                    } else {
                        return "Wallet could not be decrypted";
                    }
                } catch (Exception e) {
                    throw new CommandExecutionException(e.getMessage(), e);
                }
            }
        },
        unlockwallet {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                validateArguments(args);

                char[] passphrase = args[0].toCharArray();

                try {
                    boolean result = addressManager.unlock(passphrase);
                    if (result) {
                        return "Wallet successfully unlocked with passphrase";
                    } else {
                        return "Wallet could not be unlocked";
                    }
                } catch (Exception e) {
                    throw new CommandExecutionException(e.getMessage(), e);
                }
            }
        },
        lockwallet {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                addressManager.lock();
                return "Wallet successfully locked";
            }
        },
        switchwallet {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                // This is pre-empted by the main loop
                return "";
            }
        },
        quit {
            @Override
            public String execute(String[] args, AddressManager addressManager) {
                // This is pre-empted by the main loop
                return "";
            }
        };

        private String purposeMessage;

        private Argument[] arguments;

        public abstract String execute(String[] args, AddressManager addressManager);

        static {
            help.purposeMessage =
                    "\tShows a list of available commands.";
            help.arguments = new Argument[]{};

            getnewaddress.purposeMessage =
                    "\tGenerates a new public-private keypair in the current wallet file, and returns the\n" +
                    "\tcorresponding address.";
            getnewaddress.arguments = new Argument[]{};

            signhexmessage.purposeMessage =
                    "\tSigns the bytes corresponding to the provided hex-encoded <message> with the private key\n" +
                    "\tof the provided <address>.";
            signhexmessage.arguments = new Argument[]{
                    new Argument(ArgumentType.standard_address, "address", true),
                    new Argument(ArgumentType.hex_string, "message", true),
            };

            makesignedstandardtx.purposeMessage =
                    "\tGenerates and signs a standard tx sending <amount> VBK to <destinationAddress> with the\n" +
                    "\tspecified <transactionFee> and <signatureIndex>.";
            makesignedstandardtx.arguments = new Argument[]{
                    new Argument(ArgumentType.standard_address, "sourceAddress", true),
                    new Argument(ArgumentType.vbk_amount_string, "amount", true),
                    new Argument(ArgumentType.standard_or_multisig_address, "destinationAddress", true),
                    new Argument(ArgumentType.vbk_amount_string, "transactionFee", true),
                    new Argument(ArgumentType.positive_or_zero_long_value, "signatureIndex", true)
            };

            generatemultisigaddress.purposeMessage =
                    "\tGenerates a multisig address from the provided comma-separated addresses with an 'M'\n" +
                    "\t(number of required signatures) value of <signatureThreshold>";
            generatemultisigaddress.arguments = new Argument[]{
                    new Argument(ArgumentType.comma_separated_standard_addresses, "csvAddresses", true),
                    new Argument(ArgumentType.multisig_m_value, "signatureThreshold", true)
            };

            makeunsignedmultisigtx.purposeMessage =
                    "\tGenerates an unsigned multisig transaction sending <amount> VBK to <destinationAddress>\n" +
                    "\twith the specified <transactionFee> and <signatureIndex>.";
            makeunsignedmultisigtx.arguments = new Argument[]{
                    new Argument(ArgumentType.multisig_address, "sourceAddress", true),
                    new Argument(ArgumentType.vbk_amount_string, "amount", true),
                    new Argument(ArgumentType.standard_or_multisig_address, "destinationAddress", true),
                    new Argument(ArgumentType.vbk_amount_string, "transactionFee", true),
                    new Argument(ArgumentType.positive_or_zero_long_value, "signatureIndex", true)};

            compilesignedmultisigtx.purposeMessage =
                    "\tCompiles the provided <unsignedTransactionHex> unsigned multisig transaction with the\n" +
                    "\tcomma-separated <csvPublicKeysOrAddresses> public keys (for addresses signing the\n" +
                    "\ttransaction) and addresses (for addresses not signing the transaction), and comma-separated\n" +
                    "\t<csvSignaturesHex> signatures (for the addresses which signed the transaction,\n" +
                    "\tleaving blanks for the non-signing addresses) to create a signed multisig transaction.\n";
            compilesignedmultisigtx.arguments = new Argument[]{
                    new Argument(ArgumentType.unsigned_multisig_transaction, "unsignedTransactionHex", true),
                    new Argument(ArgumentType.comma_separated_public_keys_or_addresses, "csvPublicKeysOrAddresses", true),
                    new Argument(ArgumentType.comma_separated_signatures, "csvSignaturesHex", true)};

            getalladdresses.purposeMessage =
                    "\tDisplays all of the (standard) addresses contained in the current wallet file.";
            getalladdresses.arguments = new Argument[]{};

            encryptwallet.purposeMessage =
                    "\tEncrypts the wallet on disk using the passphrase supplied";
            encryptwallet.arguments = new Argument[] {
                    new Argument(ArgumentType.string, "passphrase", true)
            };

            decryptwallet.purposeMessage =
                    "\tDecrypts the wallet on disk using the passphrase supplied";
            decryptwallet.arguments = new Argument[] {
                    new Argument(ArgumentType.string, "passphrase", true)
            };

            unlockwallet.purposeMessage =
                    "\tUnlocks the in-memory wallet using the passphrase supplied thereby enabling the use of\n" +
                    "\tcommands that rely on protected private keys.";
            ;
            unlockwallet.arguments = new Argument[] {
                    new Argument(ArgumentType.string, "passphrase", true)
            };

            lockwallet.purposeMessage =
                    "\tLocks the in-memory wallet thereby disabling the use of commands that rely on\n" +
                    "\tprotected private keys.";
            lockwallet.arguments = new Argument[] {};

            switchwallet.purposeMessage =
                    "\tSwitches context to an alternate wallet";
            switchwallet.arguments = new Argument[]{
                    new Argument(null, "walletName", true)
            };

            quit.purposeMessage =
                    "\tExits the application";
            quit.arguments = new Argument[]{};
        }

        public String getSyntaxMessage() {
            String syntaxMessage =  name() + "";
            for (Argument argument : getArguments()) {
                boolean required = argument.isRequired();
                String argumentString = (required ? "<" : "[") + argument.name + (required ? ">" : "]");
                syntaxMessage += " " + argumentString;
            }

            return syntaxMessage;
        }

        public String getPurposeMessage() {
            return purposeMessage;
        }

        public Argument[] getArguments() {
            return arguments;
        }

        public void validateArguments(String[] argumentStrings) {
            if (argumentStrings == null) {
                throw new IllegalArgumentException("validateArguments cannot be called with a null argument array!");
            }

            Argument[] argumentDefintions = getArguments();

            int totalRequiredArguments = 0;
            for (Argument argumentDefinition : argumentDefintions) {
                if (argumentDefinition.isRequired()) {
                    totalRequiredArguments++;
                }
            }

            int fulfilledArguments = 0;
            for (int i = 0; i < argumentStrings.length; i++) {
                if (i >= argumentDefintions.length) {
                    String providedArguments = "";
                    for (int j = 0; j < argumentStrings.length; j++) {
                        providedArguments += argumentStrings[j] + " ";
                    }

                    providedArguments = providedArguments.trim();

                    throw new IllegalArgumentException(argumentStrings.length +
                            " arguments were provided (" + providedArguments + ") but the command "
                            + name() + " only supports " +
                            argumentDefintions.length + " arguments!\n" +
                            "Syntax: " + getSyntaxMessage());
                }

                Argument argumentDefintion = argumentDefintions[i];
                if (!argumentDefintion.getArgumentType().validate(argumentStrings[i])) {
                    throw new IllegalArgumentException("The command " + name() + " expects a " +
                            argumentDefintion.getArgumentType().name() + " as the argument at index " + i +
                            " but the argument '" + argumentStrings[i] + "' does not fit!\n" +
                            "Syntax: " + getSyntaxMessage());
                } else {
                    fulfilledArguments++;
                }
            }

            if (fulfilledArguments < totalRequiredArguments) {
                throw new IllegalArgumentException("The command "  + name() + " expects " + argumentDefintions.length +
                        " arguments, but only " + argumentStrings.length + " were provided!\n" +
                        "Syntax: " + getSyntaxMessage());
            }
        }

    }

    public CommandProcessor(AddressManager addressManager) {
        this.addressManager = addressManager;
    }

    public static Command getCommandFromString(String command) {
        for (Command commandEnum : Command.values()) {
            if (commandEnum.name().equalsIgnoreCase(command)) {
                return commandEnum;
            }
        }

        return null;
    }

    public String processCommand(String commandString, String[] arguments) {
        Command command = getCommandFromString(commandString);

        if (command == null) {
            return "The command " + commandString + " is not recognized! Run 'help' for a list of available commands!";
        }

        return command.execute(arguments, addressManager);
    }
}
