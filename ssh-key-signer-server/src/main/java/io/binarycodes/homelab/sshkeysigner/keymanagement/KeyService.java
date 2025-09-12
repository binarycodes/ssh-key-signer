package io.binarycodes.homelab.sshkeysigner.keymanagement;

import com.sshtools.common.publickey.*;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.ssh.components.SshCertificate;
import com.sshtools.common.ssh.components.SshKeyPair;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import io.binarycodes.homelab.sshkeysigner.config.ApplicationProperties;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;

@Log4j2
@Service
public class KeyService {
    /* https://jadaptive.com/app/manpage/en/article/2895616 */

    private static final String CERTIFICATE_FILE_NAME_SUFFIX = "cert";
    private final ApplicationProperties applicationProperties;

    private enum SIGN_TYPE {
        USER, HOST
    }

    public KeyService(ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    /**
     * Generates new ED25519 keys
     */
    public Optional<KeyInfo> generateKey(String comment, String passphrase) {
        try {
            var pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.ED25519);
            return Optional.of(createKeyInfo(pair, comment, passphrase));
        } catch (IOException | SshException e) {
            log.error(e.getMessage(), e);
        }
        return Optional.empty();
    }

    /**
     * Generates new keys and signs it
     */
    public Optional<SignedKeyInfo> generateHostSignedKey(String comment, String passphrase, String hostname, int validityDays, KeyInfo caKey, String caPassphrase) {
        var generatedKey = generateKey(comment, passphrase);

        return generatedKey.map(keyInfo -> {
            try {
                var sshKeyPair = keyInfoToKeyPair(keyInfo, passphrase);
                var caSshKeyPair = keyInfoToKeyPair(caKey, caPassphrase);
                var certificate = SshCertificateAuthority.generateHostCertificate(sshKeyPair, 0L, hostname, validityDays, caSshKeyPair);

                return createSignedKeyInfo(certificate, comment, passphrase);
            } catch (IOException | InvalidPassphraseException | SshException e) {
                log.error(e.getMessage(), e);
            }
            return null;
        });
    }

    /**
     * Generates new keys and signs it
     */
    public Optional<SignedKeyInfo> generateUserSignedKey(String comment, String passphrase, String principalName, int validityDays, KeyInfo caKey, String caPassphrase) {
        var generatedKey = generateKey(comment, passphrase);

        return generatedKey.map(keyInfo -> {
            try {
                var sshKeyPair = keyInfoToKeyPair(keyInfo, passphrase);
                var caSshKeyPair = keyInfoToKeyPair(caKey, caPassphrase);
                var certificate = SshCertificateAuthority.generateUserCertificate(sshKeyPair, 0L, principalName, validityDays, caSshKeyPair);

                return createSignedKeyInfo(certificate, comment, passphrase);
            } catch (IOException | InvalidPassphraseException | SshException e) {
                log.error(e.getMessage(), e);
            }
            return null;
        });
    }

    private SignedKeyInfo createSignedKeyInfo(SshCertificate certificate, String comment, String passphrase) throws IOException {
        var certKeyInfo = createKeyInfo(certificate, comment, passphrase);

        var certificateKeyFile = SshPublicKeyFileFactory.create(certificate.getCertificate(), comment, SshPublicKeyFileFactory.OPENSSH_FORMAT);
        var certificateKey = new String(certificateKeyFile.getFormattedKey(), StandardCharsets.UTF_8);

        return new SignedKeyInfo(certKeyInfo, certificateKey);
    }

    private KeyInfo createKeyInfo(SshKeyPair pair, String comment, String passphrase) throws IOException {
        var privateKeyFile = SshPrivateKeyFileFactory.create(pair, passphrase, comment, SshPrivateKeyFileFactory.OPENSSH_FORMAT);
        var publicKeyFile = SshPublicKeyFileFactory.create(pair.getPublicKey(), comment, SshPublicKeyFileFactory.OPENSSH_FORMAT);

        var privateKey = new String(privateKeyFile.getFormattedKey(), StandardCharsets.UTF_8);
        var publicKey = new String(publicKeyFile.getFormattedKey(), StandardCharsets.UTF_8);

        return new KeyInfo(privateKey, publicKey);
    }

    private SshKeyPair keyInfoToKeyPair(KeyInfo keyInfo, String passphrase) throws IOException, InvalidPassphraseException {
        return SshPrivateKeyFileFactory.parse(keyInfo.privateKey()
                        .getBytes(StandardCharsets.UTF_8))
                .toKeyPair(passphrase);
    }

    /**
     * Signs the given key for user
     */
    public Optional<SignedPublicKeyDownload> signUserKey(String filename, byte[] bytes, String principalName) {
        return signKey(SIGN_TYPE.USER, filename, bytes, principalName);
    }

    /**
     * Signs the given key for host
     */
    public Optional<SignedPublicKeyDownload> signHostKey(String filename, byte[] bytes, String hostName) {
        return signKey(SIGN_TYPE.HOST, filename, bytes, hostName);
    }

    private Optional<SignedPublicKeyDownload> signKey(SIGN_TYPE signType, String filename, byte[] bytes, String typeData) {
        try {
            var publicKeyFileToSign = SshPublicKeyFileFactory.parse(bytes);
            var keyPairToSign = SshKeyPair.getKeyPair(null, publicKeyFileToSign.toPublicKey());

            var signed = switch (signType) {
                case USER ->
                        SshCertificateAuthority.generateUserCertificate(keyPairToSign, 0L, typeData, applicationProperties.caUserValidity(), readUserCAKeys());
                case HOST ->
                        SshCertificateAuthority.generateHostCertificate(keyPairToSign, 0L, typeData, applicationProperties.caHostValidity(), readHostCAKeys());
            };

            var signedKey = SshPublicKeyFileFactory.create(signed.getCertificate(), publicKeyFileToSign.getComment(), SshPublicKeyFileFactory.OPENSSH_FORMAT);
            var signedKeyString = new String(signedKey.getFormattedKey(), StandardCharsets.UTF_8);
            var downloadFilename = "%s-%s.%s".formatted(FilenameUtils.getBaseName(filename), CERTIFICATE_FILE_NAME_SUFFIX, FilenameUtils.getExtension(filename));

            return Optional.of(new SignedPublicKeyDownload(downloadFilename, signedKeyString));
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        } catch (InvalidPassphraseException | SshException e) {
            throw new RuntimeException(e);
        }
        return Optional.empty();
    }

    private SshKeyPair readUserCAKeys() throws IOException, InvalidPassphraseException {
        return SshPrivateKeyFileFactory.parse(Path.of(applicationProperties.caUserPath()))
                .toKeyPair("");
    }

    private SshKeyPair readHostCAKeys() throws IOException, InvalidPassphraseException {
        return SshPrivateKeyFileFactory.parse(Path.of(applicationProperties.caHostPath()))
                .toKeyPair("");
    }
}
