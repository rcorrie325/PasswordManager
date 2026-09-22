package edu.cwru.passwordmanager.model;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordModelTest {

    private static final String MASTER_PASSWORD = "testMasterPassword";
    private static final String OTHER_MASTER_PASSWORD = "differentTestMasterPassword";
    private static final String LABEL = "Canvas";
    private static final String DUMMY_PASSWORD = "dummyPassword123";
    private static final String UPDATED_DUMMY_PASSWORD = "updatedDummyPassword456";
    private static final String VERIFY_STRING = "Peanuts";
    private static final String SEPARATOR = "\t";

    @TempDir
    Path tempDir;

    private File originalPasswordFile;

    @BeforeEach
    void setUp() throws Exception {
        originalPasswordFile = getStaticField("passwordFile", File.class);
        setStaticField("passwordFile", tempDir.resolve("passwords.txt").toFile());
        resetPasswordState();
    }

    @AfterEach
    void tearDown() throws Exception {
        setStaticField("passwordFile", originalPasswordFile);
        resetPasswordState();
    }

    @Test
    void initializePasswordFileCreatesValidEncryptedPasswordFile() throws Exception {
        PasswordModel.initializePasswordFile(MASTER_PASSWORD);

        Path passwordFile = currentPasswordFile();
        assertTrue(Files.exists(passwordFile));

        String content = Files.readString(passwordFile, StandardCharsets.UTF_8);
        List<String> lines = Files.readAllLines(passwordFile, StandardCharsets.UTF_8);
        assertEquals(1, lines.size());

        String[] parts = lines.get(0).split(SEPARATOR, 2);
        assertEquals(2, parts.length);
        assertEquals(16, Base64.getDecoder().decode(parts[0]).length);
        assertTrue(Base64.getDecoder().decode(parts[1]).length > 0);
        assertFalse(content.contains(VERIFY_STRING));
    }

    @Test
    void verifyPasswordReturnsTrueForCorrectMasterPassword() throws Exception {
        PasswordModel.initializePasswordFile(MASTER_PASSWORD);

        assertTrue(PasswordModel.verifyPassword(MASTER_PASSWORD));
    }

    @Test
    void verifyPasswordReturnsFalseForIncorrectMasterPassword() throws Exception {
        PasswordModel.initializePasswordFile(MASTER_PASSWORD);

        assertFalse(PasswordModel.verifyPassword(OTHER_MASTER_PASSWORD));
    }

    @Test
    void addPasswordPersistsWithoutWritingPlaintextPassword() throws Exception {
        PasswordModel model = initializedModel();

        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));

        String content = Files.readString(currentPasswordFile(), StandardCharsets.UTF_8);
        assertTrue(content.contains(LABEL));
        assertFalse(content.contains(DUMMY_PASSWORD));
    }

    @Test
    void constructorLoadsSavedPasswordEntries() throws Exception {
        PasswordModel model = initializedModel();
        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));

        PasswordModel reloadedModel = new PasswordModel();

        assertEquals(1, reloadedModel.getPasswords().size());
        Password password = reloadedModel.getPasswords().get(0);
        assertEquals(LABEL, password.getLabel());
        assertEquals(DUMMY_PASSWORD, password.getPassword());
    }

    @Test
    void updatePasswordPersistsUpdatedEntry() throws Exception {
        PasswordModel model = initializedModel();
        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));

        model.updatePassword(new Password(LABEL, UPDATED_DUMMY_PASSWORD), 0);
        PasswordModel reloadedModel = new PasswordModel();

        assertEquals(1, reloadedModel.getPasswords().size());
        Password password = reloadedModel.getPasswords().get(0);
        assertEquals(LABEL, password.getLabel());
        assertEquals(UPDATED_DUMMY_PASSWORD, password.getPassword());
    }

    @Test
    void deletePasswordPersistsRemovedEntry() throws Exception {
        PasswordModel model = initializedModel();
        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));

        model.deletePassword(0);
        PasswordModel reloadedModel = new PasswordModel();

        assertTrue(reloadedModel.getPasswords().isEmpty());
    }

    @Test
    void multiplePasswordEntriesArePersistedAndLoaded() throws Exception {
        PasswordModel model = initializedModel();
        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));
        model.addPassword(new Password("GitHub", "anotherDummyPassword456"));

        PasswordModel reloadedModel = new PasswordModel();

        assertEquals(2, reloadedModel.getPasswords().size());
        assertEquals(LABEL, reloadedModel.getPasswords().get(0).getLabel());
        assertEquals(DUMMY_PASSWORD, reloadedModel.getPasswords().get(0).getPassword());
        assertEquals("GitHub", reloadedModel.getPasswords().get(1).getLabel());
        assertEquals("anotherDummyPassword456", reloadedModel.getPasswords().get(1).getPassword());
    }

    @Test
    void verifyPasswordReturnsFalseForEmptyPasswordFile() throws Exception {
        Files.createFile(currentPasswordFile());

        assertFalse(PasswordModel.verifyPassword(MASTER_PASSWORD));
    }

    @Test
    void verifyPasswordReturnsFalseForMalformedPasswordFile() throws Exception {
        Files.writeString(currentPasswordFile(), "not-a-valid-password-file", StandardCharsets.UTF_8);

        assertFalse(PasswordModel.verifyPassword(MASTER_PASSWORD));
    }

    @Test
    void loadingWithWrongMasterPasswordFailsToDecryptSavedPasswords() throws Exception {
        PasswordModel model = initializedModel();
        model.addPassword(new Password(LABEL, DUMMY_PASSWORD));

        assertFalse(PasswordModel.verifyPassword(OTHER_MASTER_PASSWORD));

        assertThrows(RuntimeException.class, PasswordModel::new);
    }

    private PasswordModel initializedModel() throws Exception {
        PasswordModel.initializePasswordFile(MASTER_PASSWORD);
        assertTrue(PasswordModel.verifyPassword(MASTER_PASSWORD));
        return new PasswordModel();
    }

    private Path currentPasswordFile() throws Exception {
        return getStaticField("passwordFile", File.class).toPath();
    }

    private void resetPasswordState() throws Exception {
        setStaticField("passwordFilePassword", "");
        setStaticField("passwordFileKey", null);
        setStaticField("passwordFileSalt", null);
    }

    private static void setStaticField(String fieldName, Object value) throws Exception {
        Field field = PasswordModel.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(null, value);
    }

    private static <T> T getStaticField(String fieldName, Class<T> fieldType) throws Exception {
        Field field = PasswordModel.class.getDeclaredField(fieldName);
        field.setAccessible(true);
        return fieldType.cast(field.get(null));
    }
}
