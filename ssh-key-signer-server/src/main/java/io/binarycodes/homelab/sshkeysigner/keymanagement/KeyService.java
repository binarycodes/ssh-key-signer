package io.binarycodes.homelab.sshkeysigner.keymanagement;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.Optional;

import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.SshCertificateAuthority;
import com.sshtools.common.publickey.SshKeyPairGenerator;
import com.sshtools.common.publickey.SshPrivateKeyFileFactory;
import com.sshtools.common.publickey.SshPublicKeyFileFactory;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.ssh.components.SshCertificate;
import com.sshtools.common.ssh.components.SshKeyPair;
import io.binarycodes.homelab.lib.SignedPublicKeyDownload;
import io.binarycodes.homelab.sshkeysigner.config.ApplicationProperties;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;

@Log4j2
@Service
public class KeyService {
    /* https://jadaptive.com/app/manpage/en/article/2895616 */

    private static final String CERTIFICATE_FILE_NAME_SUFFIX = "cert";
    private final ApplicationProperties applicationProperties;

    private enum SIGN_TYPE {
        USER, HOST
    }

    public KeyService(final ApplicationProperties applicationProperties) {
        this.applicationProperties = applicationProperties;
    }

    /**
     * Generates new ED25519 keys
     */
    public Optional<KeyInfo> generateKey(final String comment, final String passphrase) {
        try {
            final var pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.ED25519);
            return Optional.of(createKeyInfo(pair, comment, passphrase));
        } catch (final IOException | SshException e) {
            log.error(e.getMessage(), e);
        }
        return Optional.empty();
    }

    /**
     * Generates new keys and signs it
     */
    public Optional<SignedKeyInfo> generateHostSignedKey(final String comment, final String passphrase, final String hostname, final int validityDays, final KeyInfo caKey, final String caPassphrase) {
        final var generatedKey = generateKey(comment, passphrase);

        return generatedKey.map(keyInfo -> {
            try {
                final var sshKeyPair = keyInfoToKeyPair(keyInfo, passphrase);
                final var caSshKeyPair = keyInfoToKeyPair(caKey, caPassphrase);
                final var certificate = SshCertificateAuthority.generateHostCertificate(sshKeyPair, 0L, hostname, validityDays, caSshKeyPair);

                return createSignedKeyInfo(certificate, comment, passphrase);
            } catch (final IOException | InvalidPassphraseException | SshException e) {
                log.error(e.getMessage(), e);
            }
            return null;
        });
    }

    /**
     * Generates new keys and signs it
     */
    public Optional<SignedKeyInfo> generateUserSignedKey(final String comment, final String passphrase, final String principalName, final int validityDays, final KeyInfo caKey, final String caPassphrase) {
        final var generatedKey = generateKey(comment, passphrase);

        return generatedKey.map(keyInfo -> {
            try {
                final var sshKeyPair = keyInfoToKeyPair(keyInfo, passphrase);
                final var caSshKeyPair = keyInfoToKeyPair(caKey, caPassphrase);
                final var certificate = SshCertificateAuthority.generateUserCertificate(sshKeyPair, 0L, principalName, validityDays, caSshKeyPair);

                return createSignedKeyInfo(certificate, comment, passphrase);
            } catch (final IOException | InvalidPassphraseException | SshException e) {
                log.error(e.getMessage(), e);
            }
            return null;
        });
    }

    private SignedKeyInfo createSignedKeyInfo(final SshCertificate certificate, final String comment, final String passphrase) throws IOException {
        final var certKeyInfo = createKeyInfo(certificate, comment, passphrase);

        final var certificateKeyFile = SshPublicKeyFileFactory.create(certificate.getCertificate(), comment, SshPublicKeyFileFactory.OPENSSH_FORMAT);
        final var certificateKey = new String(certificateKeyFile.getFormattedKey(), StandardCharsets.UTF_8);

        return new SignedKeyInfo(certKeyInfo, certificateKey);
    }

    private KeyInfo createKeyInfo(final SshKeyPair pair, final String comment, final String passphrase) throws IOException {
        final var privateKeyFile = SshPrivateKeyFileFactory.create(pair, passphrase, comment, SshPrivateKeyFileFactory.OPENSSH_FORMAT);
        final var publicKeyFile = SshPublicKeyFileFactory.create(pair.getPublicKey(), comment, SshPublicKeyFileFactory.OPENSSH_FORMAT);

        final var privateKey = new String(privateKeyFile.getFormattedKey(), StandardCharsets.UTF_8);
        final var publicKey = new String(publicKeyFile.getFormattedKey(), StandardCharsets.UTF_8);

        return new KeyInfo(privateKey, publicKey);
    }

    private SshKeyPair keyInfoToKeyPair(final KeyInfo keyInfo, final String passphrase) throws IOException, InvalidPassphraseException {
        return SshPrivateKeyFileFactory.parse(keyInfo.privateKey()
                        .getBytes(StandardCharsets.UTF_8))
                .toKeyPair(passphrase);
    }

    /**
     * Signs the given key for user
     */
    public Optional<SignedPublicKeyDownload> signUserKey(final String filename, final byte[] bytes, final String principalName) {
        return signKey(SIGN_TYPE.USER, filename, bytes, principalName);
    }

    /**
     * Signs the given key for host
     */
    public Optional<SignedPublicKeyDownload> signHostKey(final String filename, final byte[] bytes, final String hostName) {
        return signKey(SIGN_TYPE.HOST, filename, bytes, hostName);
    }

    private Optional<SignedPublicKeyDownload> signKey(final SIGN_TYPE signType, final String filename, final byte[] bytes, final String typeData) {
        try {
            final var publicKeyFileToSign = SshPublicKeyFileFactory.parse(bytes);
            final var keyPairToSign = SshKeyPair.getKeyPair(null, publicKeyFileToSign.toPublicKey());

            final var signed = switch (signType) {
                case USER -> SshCertificateAuthority.generateUserCertificate(keyPairToSign, 0L, typeData, applicationProperties.caUserValidity(), readUserCAKeys());
                case HOST -> SshCertificateAuthority.generateHostCertificate(keyPairToSign, 0L, typeData, applicationProperties.caHostValidity(), readHostCAKeys());
            };

            final var signedKey = SshPublicKeyFileFactory.create(signed.getCertificate(), publicKeyFileToSign.getComment(), SshPublicKeyFileFactory.OPENSSH_FORMAT);
            final var signedKeyString = new String(signedKey.getFormattedKey(), StandardCharsets.UTF_8);
            final var downloadFilename = "%s-%s.%s".formatted(FilenameUtils.getBaseName(filename), CERTIFICATE_FILE_NAME_SUFFIX, FilenameUtils.getExtension(filename));

            return Optional.of(new SignedPublicKeyDownload(downloadFilename, signedKeyString));
        } catch (final IOException e) {
            log.error(e.getMessage(), e);
        } catch (final InvalidPassphraseException | SshException e) {
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
