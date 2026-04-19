package org.plovdev.keyer.implementations.win;

import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;
import org.plovdev.keyer.utils.NativeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.foreign.*;
import java.lang.invoke.MethodHandle;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.plovdev.keyer.utils.NativeUtils.find;

public final class WinOsKeychainNative {
    private static final Logger log = LoggerFactory.getLogger(WinOsKeychainNative.class);

    private static final Arena SHARED = Arena.ofAuto();
    private static final Linker LINKER = Linker.nativeLinker();
    private static final SymbolLookup ADVAPI32 = SymbolLookup.libraryLookup("Advapi32", SHARED);
    private static final SymbolLookup KERNEL32 = SymbolLookup.libraryLookup("Kernel32", SHARED);

    private static final int CRED_TYPE_GENERIC = 1;
    private static final int CRED_PERSIST_LOCAL_MACHINE = 2;

    private static final MethodHandle GET_PASSWORD = find(ADVAPI32, LINKER, "CredReadW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT, ValueLayout.ADDRESS));
    private static final MethodHandle SET_PASSWORD = find(ADVAPI32, LINKER, "CredWriteW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT));
    private static final MethodHandle DELETE_PASSWORD = find(ADVAPI32, LINKER, "CredDeleteW", FunctionDescriptor.of(ValueLayout.JAVA_INT, ValueLayout.ADDRESS, ValueLayout.JAVA_INT, ValueLayout.JAVA_INT));
    private static final MethodHandle CLEAN_PASSWORD = find(ADVAPI32, LINKER, "CredFree", FunctionDescriptor.ofVoid(ValueLayout.ADDRESS));

    private static final StructLayout CREDENTIAL_LAYOUT = MemoryLayout.structLayout(
            ValueLayout.JAVA_INT.withName("Flags"),
            ValueLayout.JAVA_INT.withName("Type"),
            ValueLayout.ADDRESS.withName("TargetName"),
            ValueLayout.ADDRESS.withName("Comment"),
            MemoryLayout.structLayout(ValueLayout.JAVA_INT.withName("dwLowDateTime"), ValueLayout.JAVA_INT.withName("dwHighDateTime")).withName("LastWritten"),
            ValueLayout.JAVA_INT.withName("CredentialBlobSize"),
            MemoryLayout.paddingLayout(4),
            ValueLayout.ADDRESS.withName("CredentialBlob"),
            ValueLayout.JAVA_INT.withName("Persist"),
            ValueLayout.JAVA_INT.withName("AttributeCount"),
            ValueLayout.ADDRESS.withName("Attributes"),
            ValueLayout.ADDRESS.withName("TargetAlias"),
            ValueLayout.ADDRESS.withName("UserName")
    );

    @Contract(value = "_, _ -> new", pure = true)
    public char @Nullable [] getPassword(String appId, String alias) {
        try (var arena = Arena.ofConfined()) {
            String targetName = formTargetName(appId, alias);
            MemorySegment targetSegment = arena.allocateFrom(targetName, StandardCharsets.UTF_16LE);
            MemorySegment credPtrSegment = arena.allocate(ValueLayout.ADDRESS);

            int getStatus = (int) GET_PASSWORD.invokeExact(targetSegment, CRED_TYPE_GENERIC, 0, credPtrSegment);
            log.trace("Password getting status: {}", getStatus);
            if (getStatus <= 0) return null; // == FALSE

            MemorySegment itemRef = credPtrSegment.get(ValueLayout.ADDRESS, 0);
            MemorySegment credential = itemRef.reinterpret(CREDENTIAL_LAYOUT.byteSize());

            int blobSize = credential.get(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("CredentialBlobSize")));
            MemorySegment blob = credential.get(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("CredentialBlob"))).reinterpret(blobSize);

            byte[] rawPassword = blob.toArray(ValueLayout.JAVA_BYTE);
            char[] password = NativeUtils.bytesToCharsUTF_16LE(rawPassword);

            CLEAN_PASSWORD.invokeExact(itemRef);
            Arrays.fill(rawPassword, (byte) 0);
            return password;
        } catch (Throwable t) {
            throw new RuntimeException("Cann't get password.");
        }
    }

    public void setPassword(String appId, String alias, char[] newPassword) {
        try (var arena = Arena.ofConfined()) {
            String targetName = formTargetName(appId, alias);
            MemorySegment targetSegment = arena.allocateFrom(targetName, StandardCharsets.UTF_16LE);

            byte[] passwordBytes = NativeUtils.charsUTF_16LEToBytes(newPassword);
            MemorySegment passwordSegment = arena.allocateFrom(ValueLayout.JAVA_BYTE, passwordBytes);

            MemorySegment credential = arena.allocate(CREDENTIAL_LAYOUT);
            credential.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Type")), CRED_TYPE_GENERIC);
            credential.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("TargetName")), targetSegment);
            credential.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("UserName")), targetSegment);
            credential.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("CredentialBlobSize")), (int) passwordSegment.byteSize());
            credential.set(ValueLayout.ADDRESS, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("CredentialBlob")), passwordSegment);
            credential.set(ValueLayout.JAVA_INT, CREDENTIAL_LAYOUT.byteOffset(MemoryLayout.PathElement.groupElement("Persist")), CRED_PERSIST_LOCAL_MACHINE);

            int setStatus = (int) SET_PASSWORD.invokeExact(credential, 0);
            log.trace("Password setting status: {}", setStatus);

            Arrays.fill(passwordBytes, (byte) 0);
            if (setStatus <= 0) throw new RuntimeException("Windows CredWrite failed");
        } catch (Throwable t) {
            throw new RuntimeException("Cann't set password.");
        }
    }

    public void deletePassword(String appId, String alias) {
        try (var arena = Arena.ofConfined()) {
            String targetName = formTargetName(appId, alias);
            MemorySegment targetSegment = arena.allocateFrom(targetName, StandardCharsets.UTF_16LE);

            int delStatus = (int) DELETE_PASSWORD.invokeExact(targetSegment, CRED_TYPE_GENERIC, 0);
            log.trace("Password deleting status: {}", delStatus);

            if (delStatus <= 0) throw new RuntimeException("Unable to delete password");
        } catch (Throwable t) {
            throw new RuntimeException("Cann't delete password.");
        }
    }

    @Contract(pure = true)
    @NotNull
    private static String formTargetName(String app, String alias) {
        return app + ":" + alias;
    }
}