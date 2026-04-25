package org.plovdev.keyer.implementations.unix;

import org.plovdev.keyer.Keychain;

public class UnixKeychain implements Keychain {
    /**
     * Native bridge for Project Panama calls.
     */
    private static final UnixOsKeychainNative UNIX_OS_KEYCHAIN_NATIVE = new UnixOsKeychainNative();

    // state variables
    private final String appId;

    public UnixKeychain(String appId) {
        this.appId = appId;
    }

    @Override
    public synchronized char[] getPassword(String alias) {
        try {
            return UNIX_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public synchronized boolean setPassword(String alias, char[] newPassword) {
        try {
            UNIX_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public synchronized boolean deletePassword(String alias) {
        try {
            UNIX_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}