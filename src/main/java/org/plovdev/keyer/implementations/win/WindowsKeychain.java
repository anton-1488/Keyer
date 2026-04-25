package org.plovdev.keyer.implementations.win;

import org.plovdev.keyer.Keychain;

public class WindowsKeychain implements Keychain {
    /**
     * Native bridge for Project Panama calls.
     */
    private static final WinOsKeychainNative WIN_OS_KEYCHAIN_NATIVE = new WinOsKeychainNative();

    // state variables
    private final String appId;

    public WindowsKeychain(String appId) {
        this.appId = appId;
    }

    @Override
    public synchronized char[] getPassword(String alias) {
        try {
            return WIN_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
        } catch (Exception e) {
            return null;
        }
    }

    @Override
    public synchronized boolean setPassword(String alias, char[] newPassword) {
        try {
            WIN_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public synchronized boolean deletePassword(String alias) {
        try {
            WIN_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}