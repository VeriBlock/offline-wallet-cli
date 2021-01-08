// VeriBlock NodeCore
// Copyright 2017-2021 Xenios SEZC
// All rights reserved.
// https://www.veriblock.org
// Distributed under the MIT software license, see the accompanying
// file LICENSE or http://www.opensource.org/licenses/mit-license.php.

package veriblock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.veriblock.core.contracts.*;
import org.veriblock.core.wallet.DefaultAddressManager;

import java.io.File;
import java.io.IOException;
import java.util.Scanner;

public class Main {
    private static final Logger logger = LoggerFactory.getLogger(Main.class);

    private static String walletPath = null;

    private static CommandProcessor commandProcessor;

    public static void main(String[] args) {
        String command = null;
        if (args.length >= 1) {
            walletPath = args[0];
        } if (args.length >= 2) {
            command = args[1];
        }

        Scanner scan = new Scanner(System.in);
        if (walletPath == null) {
            System.out.println("Please enter the name of the wallet you want to interact with.");
            walletPath = scan.nextLine();
        }

        switchWallet(walletPath);

        if (commandProcessor == null) {
            logger.error("Unable to load command processor! Exiting...");
            return;
        }

        if (command == null) {
            while (true) {
                System.out.print("[" + walletPath + "]> ");
                String[] line = scan.nextLine().split(" ");
                command = line[0];
                String[] arguments = new String[line.length - 1];
                System.arraycopy(line, 1, arguments, 0, arguments.length);

                if (command.equalsIgnoreCase("switchwallet")) {
                    if (arguments.length == 0) {
                        System.out.println("The switchwallet command requires the name of the wallet file to switch to!");
                        continue;
                    }
                    switchWallet(arguments[0]);
                } else if (command.equalsIgnoreCase("q") ||
                        command.equalsIgnoreCase("quit") ||
                        command.equalsIgnoreCase("exit")) {
                    break;
                }
                else {
                    try {
                        String result = commandProcessor.processCommand(command, arguments);
                        System.out.println(result);
                    } catch (Exception e) {
                        displayException(e);
                    }
                }
            }
        } else {
            String[] arguments = new String[args.length - 2];
            System.arraycopy(args, 2, arguments, 0, arguments.length);
            try {
                String result = commandProcessor.processCommand(command, arguments);
                System.out.println(result);
            } catch (Exception e) {
                displayException(e);
            }
        }
    }

    private static void displayException(Exception e) {
        logger.error("An error occurred while processing the command", e);
        try { Thread.sleep(15); } catch (Exception ignored) {}
    }



    private static void switchWallet(String newWalletFile) {
        try {
            if (!newWalletFile.endsWith(".dat")) {
                newWalletFile = newWalletFile + ".dat";
            }

            walletPath = newWalletFile;
            File wallet = new File(walletPath);

            AddressManager addressManager = new DefaultAddressManager();
            addressManager.load(wallet);

            String result = String.format("Switched to wallet file %s with default address %s", walletPath, addressManager.getDefaultAddress().getHash());
            System.out.println(result);
            logger.info(result);

            commandProcessor = new CommandProcessor(addressManager);
        } catch (IOException e) {
            logger.error("Unable to load wallet: {}", newWalletFile);
        }
    }
}
