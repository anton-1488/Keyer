package org.plovdev.keyer.implementations.unix;

import org.plovdev.keyer.utils.NativeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.util.Arrays;

import static org.plovdev.keyer.utils.NativeUtils.find;

public final class UnixOsKeychainNative {
    private static final Logger log = LoggerFactory.getLogger(UnixOsKeychainNative.class);
    private static final String SCHEMA_NAME = "org.plovdev.keyer";

    private static final Arena SHARED = Arena.ofAuto();
    private static final Linker LINKER = Linker.nativeLinker();

    /**
     * Path to libsecret shared library.
     * Common paths for different distributions:
     * - /usr/lib/libsecret-1.so
     * - /usr/lib/x86_64-linux-gnu/libsecret-1.so
     * - /usr/lib64/libsecret-1.so
     */
    private static final SymbolLookup SECRET;

    static {
        String[] possiblePaths = {"libsecret-1.so", "libsecret-1.so.0", "/usr/lib/libsecret-1.so", "/usr/lib/x86_64-linux-gnu/libsecret-1.so", "/usr/lib64/libsecret-1.so"};

        SymbolLookup lookup = null;
        for (String path : possiblePaths) {
            try {
                lookup = SymbolLookup.libraryLookup(path, SHARED);
                break;
            } catch (Exception e) {
                log.debug("Failed to load libsecret from {}: {}", path, e.getMessage());
            }
        }
        if (lookup == null) {
            throw new UnsatisfiedLinkError("Unable to load libsecret");
        }
        SECRET = lookup;
    }

    // Function descriptors for libsecret API
    private static final MethodHandle SECRET_PASSWORD_LOOKUP_SYNC = find(SECRET, LINKER, "secret_password_lookup_sync", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SECRET_PASSWORD_STORE_SYNC = find(SECRET, LINKER, "secret_password_store_sync", FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SECRET_PASSWORD_CLEAR_SYNC = find(SECRET, LINKER, "secret_password_clear_sync", FunctionDescriptor.of(ValueLayout.JAVA_BOOLEAN, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.ADDRESS));
    private static final MethodHandle SECRET_SCHEMA_NEW = find(SECRET, LINKER, "secret_schema_new", FunctionDescriptor.of(ValueLayout.ADDRESS, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle SECRET_SCHEMA_UNREF = find(SECRET, LINKER, "secret_schema_unref", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));
    private static final MethodHandle G_FREE = find(SymbolLookup.libraryLookup("libglib-2.0.so", SHARED), LINKER, "g_free", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    private static final MemorySegment schemaRef;

    static {
        MemorySegment nameSegment = SHARED.allocateFrom(SCHEMA_NAME);
        try {
            schemaRef = (MemorySegment) SECRET_SCHEMA_NEW.invokeExact(nameSegment, 0);
            log.info("Secret schema created successfully");
        } catch (Throwable t) {
            throw new RuntimeException("Failed to create secret schema", t);
        }
    }

    public char [] getPassword(String app, String alias) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            MemorySegment passwordSegment = (MemorySegment) SECRET_PASSWORD_LOOKUP_SYNC.invokeExact(
                    schemaRef,
                    MemorySegment.NULL,
                    errorPtr,
                    arena.allocateFrom("service"),
                    arena.allocateFrom(app),
                    arena.allocateFrom("account"),
                    arena.allocateFrom(alias),
                    MemorySegment.NULL
            );

            MemorySegment errorSegment = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (errorSegment.address() != 0 || passwordSegment.address() == 0) {
                return null;
            }

            long size = 0;
            while (passwordSegment.get(ValueLayout.JAVA_BYTE, size) != 0) {
                size++;
            }
            MemorySegment readable = passwordSegment.reinterpret(size);
            byte[] rawBytes = new byte[(int) size];
            MemorySegment.copy(readable, ValueLayout.JAVA_BYTE, 0, rawBytes, 0, (int) size);

            char[] password = NativeUtils.bytesToCharsUTF_8(rawBytes);
            Arrays.fill(rawBytes, (byte) 0);
            G_FREE.invokeExact(passwordSegment);

            return password;
        } catch (Throwable t) {
            throw new RuntimeException("Error getting password: ", t);
        }
    }

    public void setPassword(String app, String alias, char[] newPassword) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);

            byte[] passBytes = NativeUtils.charsUTF_8ToBytes(newPassword);
            MemorySegment passwordSegment = arena.allocateFrom(ValueLayout.JAVA_BYTE, passBytes);
            Arrays.fill(passBytes, (byte) 0);

            String label = app + " - " + alias;
            boolean success = (boolean) SECRET_PASSWORD_STORE_SYNC.invokeExact(
                    schemaRef,
                    MemorySegment.NULL,
                    arena.allocateFrom(label),
                    passwordSegment,
                    MemorySegment.NULL,
                    errorPtr,
                    arena.allocateFrom("service"),
                    arena.allocateFrom(app),
                    arena.allocateFrom("account"),
                    arena.allocateFrom(alias),
                    MemorySegment.NULL
            );

            MemorySegment errorSegment = errorPtr.get(ValueLayout.ADDRESS, 0);
            if (errorSegment.address() != 0 || !success) {
                throw new RuntimeException("Failed to store password");
            }

            log.debug("Password stored successfully");
        } catch (Throwable t) {
            throw new RuntimeException("Cannot set password: ", t);
        }
    }


    public void deletePassword(String app, String alias) {
        try (var arena = Arena.ofConfined()) {
            MemorySegment errorPtr = arena.allocate(ValueLayout.ADDRESS);
            boolean success = (boolean) SECRET_PASSWORD_CLEAR_SYNC.invokeExact(
                    schemaRef,
                    MemorySegment.NULL,
                    errorPtr,
                    arena.allocateFrom("service"),
                    arena.allocateFrom(app),
                    arena.allocateFrom("account"),
                    arena.allocateFrom(alias),
                    MemorySegment.NULL
            );

            MemorySegment errorSegment = errorPtr.get(ValueLayout.ADDRESS, 0);
            log.debug("Deleting success: {}", success);
            if (!errorSegment.equals(MemorySegment.NULL)) {
                throw new RuntimeException("Failed to delete password");
            }
        } catch (Throwable t) {
            throw new RuntimeException("Error deleting password: ", t);
        }
    }
}