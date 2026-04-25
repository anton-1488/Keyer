package org.plovdev.keyer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Objects;

/**
 * A basic example demonstrating how to use the Keyer library.
 * <p>
 * This example shows the standard lifecycle of password management:
 * <ol>
 *     <li>Obtaining a platform-specific {@link Keychain} instance</li>
 *     <li>Storing a secret password using an alias</li>
 *     <li>Retrieving the stored password back from the native store</li>
 * </ol>
 *
 * <p>Note: This example uses the simplified {@code void main()} entry point
 * available in Java 25 versions.</p>
 *
 * @author Anton
 * @version 1.0
 */
public class KeyerExample {
    private static final Logger log = LoggerFactory.getLogger(KeyerExample.class);

    /**
     * Executes the keychain demonstration.
     * <p>
     * <b>Warning:</b> In a real production environment, you should clear the
     * password character array using {@code Arrays.fill(password, '\0')}
     * after use to ensure maximum security.
     */
    void main() {
        // 1. Get the keychain instance for your application
        Keychain keychain = Keychain.getKeychain("MyApp");
        String alias = "wallet1";

        // 2. Set a new password
        boolean setted = keychain.setPassword(alias, "123".toCharArray());
        log.info("Password setted: {}", setted);

        // 3. Retrieve the password
        char[] password = keychain.getPassword(alias);

        // 4. Log the result (using Objects.requireNonNull to handle null safety)
        log.info("Getted password: {}", new String(Objects.requireNonNull(password)));
    }
}