package org.plovdev.keyer.implementations.win;

import org.plovdev.keyer.Keychain;

/**
 * Windows implementation of the {@link Keychain} interface.
 * <p>
 * Provides access to Windows Credential Manager via native calls to Advapi32.dll.
 * Stores generic credentials using the Windows Vault.
 *
 * @author Anton
 * @since 1.0
 * @version 1.6
 */
public class WindowsKeychain implements Keychain {
    /**
     * Native bridge for Project Panama calls.
     */
    private static final WinOsKeychainNative WIN_OS_KEYCHAIN_NATIVE = new WinOsKeychainNative();

    private final String appId;

    /**
     * Constructs a WindowsKeychain instance.
     *
     * @param appId application identifier used as credential target prefix
     */
    public WindowsKeychain(String appId) {
        this.appId = appId;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public char[] getPassword(String alias) {
        return WIN_OS_KEYCHAIN_NATIVE.getPassword(appId, alias);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void setPassword(String alias, char[] newPassword) {
        WIN_OS_KEYCHAIN_NATIVE.setPassword(appId, alias, newPassword);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public void deletePassword(String alias) {
        WIN_OS_KEYCHAIN_NATIVE.deletePassword(appId, alias);
    }
}