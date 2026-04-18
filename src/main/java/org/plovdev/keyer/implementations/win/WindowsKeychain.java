package org.plovdev.keyer.implementations.win;

import org.plovdev.keyer.Keychain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.concurrent.atomic.AtomicBoolean;

public class WindowsKeychain implements Keychain {
    private static final Logger log = LoggerFactory.getLogger(WindowsKeychain.class);

    /**
     * Native bridge for Project Panama calls.
     */
    private static final WinOsKeychainNative WIN_OS_KEYCHAIN_NATIVE = new WinOsKeychainNative();

    // state variables
    private final AtomicBoolean isInited = new AtomicBoolean(false);
    private String appId;

    @Override
    public synchronized void init(String appId) {
        if (isInited.get()) return;
        this.appId = appId;
        isInited.set(true);
    }

    @Override
    public synchronized char[] getPassword(String alias) {
        checkIfInited();
        return WIN_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
    }

    @Override
    public synchronized boolean setPassword(String alias, char[] newPassword) {
        checkIfInited();
        try {
            WIN_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public synchronized boolean deletePassword(String alias) {
        checkIfInited();
        try {
            WIN_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Ensures that the keychain instance has been properly initialized with an appId.
     *
     * @throws IllegalStateException if {@code isInited} is false.
     */
    private void checkIfInited() {
        if (!isInited.get()) {
            throw new IllegalStateException("Keyer not inited!");
        }
    }
}