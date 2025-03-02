package io.binarycodes.homelab.sshkeysigner.keymanagement;

import com.sshtools.common.publickey.*;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.ssh.components.SshCertificate;
import com.sshtools.common.ssh.components.SshKeyPair;
import lombok.extern.log4j.Log4j2;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Optional;

@Log4j2
@Service
public class KeyService {
    /* https://jadaptive.com/app/manpage/en/article/2895616 */

    public Optional<KeyInfo> generateKey(String comment, String passphrase) {
        try {
            var pair = SshKeyPairGenerator.generateKeyPair(SshKeyPairGenerator.ED25519);
            return Optional.of(createKeyInfo(pair, comment, passphrase));
        } catch (IOException | SshException e) {
            log.error(e.getMessage(), e);
        }
        return Optional.empty();
    }

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
        return SshPrivateKeyFileFactory.parse(keyInfo.privateKey().getBytes(StandardCharsets.UTF_8)).toKeyPair(passphrase);
    }

}
