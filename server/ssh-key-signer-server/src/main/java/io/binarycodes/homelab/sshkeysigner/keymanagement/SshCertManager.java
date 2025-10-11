package io.binarycodes.homelab.sshkeysigner.keymanagement;

import com.sshtools.common.publickey.CertificateExtension;
import com.sshtools.common.publickey.CriticalOption;
import com.sshtools.common.publickey.InvalidPassphraseException;
import com.sshtools.common.publickey.NamedCertificateExtension;
import com.sshtools.common.publickey.OpenSshCertificate;
import com.sshtools.common.ssh.SshException;
import com.sshtools.common.ssh.components.SshCertificate;
import com.sshtools.common.ssh.components.SshKeyPair;
import com.sshtools.common.ssh.components.jce.OpenSshEcdsaSha2Nist256Certificate;
import com.sshtools.common.ssh.components.jce.OpenSshEcdsaSha2Nist384Certificate;
import com.sshtools.common.ssh.components.jce.OpenSshEcdsaSha2Nist521Certificate;
import com.sshtools.common.ssh.components.jce.OpenSshEd25519Certificate;
import com.sshtools.common.ssh.components.jce.OpenSshRsaCertificate;
import com.sshtools.common.util.UnsignedInteger64;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

public class SshCertManager {

    public static SshCertificate generateCertificate(final SshCertificateType signType,
                                                     final SshKeyPair key,
                                                     final String keyId,
                                                     final List<String> validPrincipals,
                                                     final Duration validityDuration,
                                                     final List<String> sourceAddresses,
                                                     final List<String> knownExtensions,
                                                     final SshKeyPair signedBy) throws SshException, IOException, InvalidPassphraseException {

        final var type = switch (signType) {
            case HOST -> SshCertificate.SSH_CERT_TYPE_HOST;
            case USER -> SshCertificate.SSH_CERT_TYPE_USER;
        };

        final var criticalOptions = new CriticalOption.Builder()
                .sourceAddress(sourceAddresses.toArray(String[]::new))
                .build();

        final var extensionsBuilder = new CertificateExtension.Builder();
        knownExtensions.forEach(extension -> extensionsBuilder.knownExtension(new NamedCertificateExtension(extension, true)));

        final var extensions = extensionsBuilder.build();

        final var now = Instant.now().atZone(ZoneOffset.UTC);
        final UnsignedInteger64 validAfter = new UnsignedInteger64(now.toEpochSecond());
        final UnsignedInteger64 validBefore = new UnsignedInteger64(now.plus(validityDuration).toEpochSecond());

        return generateCertificate(key, 0L, type, keyId, validPrincipals, validAfter, validBefore, criticalOptions, extensions, signedBy);
    }

    public static SshCertificate generateCertificate(final SshKeyPair key,
                                                     final long serial,
                                                     final int type,
                                                     final String keyId,
                                                     final List<String> validPrincipals,
                                                     final UnsignedInteger64 validAfter,
                                                     final UnsignedInteger64 validBefore,
                                                     final List<CriticalOption> criticalOptions,
                                                     final List<CertificateExtension> extensions,
                                                     final SshKeyPair signedBy) throws SshException, IOException {
        @SuppressWarnings("unused")
        String reserved = "";

        OpenSshCertificate cert;
        switch (key.getPublicKey().getAlgorithm()) {
            case "ssh-rsa":
            case "rsa-sha2-256":
            case "rsa-sha2-512":
                cert = new OpenSshRsaCertificate();
                break;
            case "ssh-ed25519":
                cert = new OpenSshEd25519Certificate();
                break;
            case "ecdsa-sha2-nistp256":
                cert = new OpenSshEcdsaSha2Nist256Certificate();
                break;
            case "ecdsa-sha2-nistp384":
                cert = new OpenSshEcdsaSha2Nist384Certificate();
                break;
            case "ecdsa-sha2-nistp521":
                cert = new OpenSshEcdsaSha2Nist521Certificate();
                break;
            default:
                throw new SshException(SshException.BAD_API_USAGE,
                        String.format("Unsupported certificate type %s", key.getPublicKey().getAlgorithm()));
        }

        cert.sign(key.getPublicKey(), new UnsignedInteger64(serial), type, keyId, validPrincipals,
                validAfter, validBefore, criticalOptions, extensions, signedBy);

        return new SshCertificate(key, cert);
    }
}
