// Copyright 2024, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package info.usmans.besu.plugin.softhsm;

import static info.usmans.besu.plugin.softhsm.SignatureUtil.extractRAndSFromDERSignature;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.interfaces.ECPublicKey;
import java.util.Arrays;
import javax.crypto.KeyAgreement;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModule;
import org.hyperledger.besu.plugin.services.securitymodule.SecurityModuleException;
import org.hyperledger.besu.plugin.services.securitymodule.data.PublicKey;
import org.hyperledger.besu.plugin.services.securitymodule.data.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** A PKCS11 based implementation of Besu SecurityModule interface. */
public class Pkcs11SecurityModuleService implements SecurityModule {
  private static final Logger LOG = LoggerFactory.getLogger(Pkcs11SecurityModuleService.class);
  private static final String SIGNATURE_ALGORITHM = "NONEWithECDSA";
  private static final String KEY_AGREEMENT_ALGORITHM = "ECDH";

  private final Pkcs11PluginCliOptions cliParams;
  private Provider provider;
  private KeyStore keyStore;
  private PrivateKey privateKey;
  private ECPublicKey ecPublicKey;

  public Pkcs11SecurityModuleService(final Pkcs11PluginCliOptions cliParams) {
    LOG.debug("Creating Pkcs11SecurityModuleService ...");
    this.cliParams = cliParams;
    validateCliOptions();
    loadPkcs11Provider();
    loadPkcs11Keystore();
    loadPkcs11PrivateKey();
    loadPkcs11PublicKey();
  }

  private void validateCliOptions() {
    if (cliParams.getPkcs11ConfigPath() == null) {
      throw new SecurityModuleException("PKCS11 configuration file path is not provided");
    }
    if (cliParams.getPrivateKeyAlias() == null) {
      throw new SecurityModuleException("PKCS11 private key alias is not provided");
    }
  }

  private char[] obtainPin() {
    if (cliParams.isAskPassword()) {
      java.io.Console console = System.console();
      if (console != null) {
        char[] entered = console.readPassword("Enter PKCS#11 PIN: ");
        if (entered == null || entered.length == 0) {
          throw new SecurityModuleException("Empty PIN entered.");
        }
        return entered;
      } else {
        // fallback to stdin when no TTY (input will echo)
        try {
          LOG.warn("No TTY console detected; reading PIN from stdin (input will be echoed).");
          BufferedReader br =
              new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));
          String line = br.readLine();
          if (line == null || line.isEmpty()) {
            throw new SecurityModuleException("Empty PIN read from stdin.");
          }
          return line.trim().toCharArray();
        } catch (IOException e) {
          throw new SecurityModuleException("Unable to read PIN from stdin.", e);
        }
      }
    }
    throw new SecurityModuleException("Missing PIN. Provide: --plugin-pkcs11-hsm-ask-password");
  }

  private void loadPkcs11Provider() {
    // initialize PKCS11 provider
    LOG.info("Initializing PKCS11 provider ...");

    try {
      final Provider sunPKCS11Provider = Security.getProvider("SunPKCS11");
      if (sunPKCS11Provider == null) {
        throw new SecurityModuleException("SunPKCS11 provider not found");
      }
      // configure the provider with the PKCS11 configuration file
      provider = sunPKCS11Provider.configure(cliParams.getPkcs11ConfigPath().toString());
      if (provider == null) {
        throw new SecurityModuleException("Unable to configure SunPKCS11 provider");
      }
      // finally add configured provider.
      Security.addProvider(provider);
    } catch (final Exception e) {
      if (e instanceof SecurityModuleException) {
        throw (SecurityModuleException) e;
      }

      throw new SecurityModuleException(
          "Error encountered while loading SunPKCS11 provider with configuration: "
              + cliParams.getPkcs11ConfigPath().toString(),
          e);
    }
  }

  private void loadPkcs11Keystore() {
    LOG.info("Loading PKCS11 keystore ...");
    final char[] pin = obtainPin();
    try {
      keyStore = KeyStore.getInstance("PKCS11", provider);
      keyStore.load(null, pin);
    } catch (final Exception e) {
      throw new SecurityModuleException("Error loading PKCS11 keystore", e);
    } finally {
      // Best-effort zeroization of PIN in memory
      Arrays.fill(pin, '\0');
    }
  }

  private void loadPkcs11PrivateKey() {
    LOG.info("Loading private key ...");
    final Key key;
    try {
      key = keyStore.getKey(cliParams.getPrivateKeyAlias(), new char[0]);
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error loading private key for alias: " + cliParams.getPrivateKeyAlias(), e);
    }

    if (!(key instanceof PrivateKey)) {
      throw new SecurityModuleException(
          "Loaded key is not a PrivateKey for alias: " + cliParams.getPrivateKeyAlias());
    }

    privateKey = (PrivateKey) key;
  }

  private void loadPkcs11PublicKey() {
    LOG.info("Loading public key ...");
    final Certificate certificate;
    try {
      certificate = keyStore.getCertificate(cliParams.getPrivateKeyAlias());
      if (certificate == null) {
        throw new SecurityModuleException(
            "Certificate not found for private key alias: " + cliParams.getPrivateKeyAlias());
      }
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error while loading certificate for private key alias: "
              + cliParams.getPrivateKeyAlias(),
          e);
    }

    final java.security.PublicKey publicKey;
    try {
      publicKey = certificate.getPublicKey();
    } catch (final Exception e) {
      throw new SecurityModuleException(
          "Error while loading public key for alias: " + cliParams.getPrivateKeyAlias(), e);
    }

    if (!(publicKey instanceof ECPublicKey)) {
      throw new SecurityModuleException(
          "Public Key is not a valid ECPublicKey for alias: " + cliParams.getPrivateKeyAlias());
    }
    ecPublicKey = (ECPublicKey) publicKey;
  }

  @Override
  public Signature sign(Bytes32 dataHash) throws SecurityModuleException {
    try {
      // Java classes generate ASN1 encoded signature,
      // Besu needs P1363 i.e. R and S of the signature
      final java.security.Signature signature =
          java.security.Signature.getInstance(SIGNATURE_ALGORITHM, provider);
      signature.initSign(privateKey);
      signature.update(dataHash.toArray());
      final byte[] sigBytes = signature.sign();
      return extractRAndSFromDERSignature(sigBytes);
    } catch (final Exception e) {
      if (e instanceof SecurityModuleException) {
        throw (SecurityModuleException) e;
      }
      throw new SecurityModuleException("Error initializing signature", e);
    }
  }

  @Override
  public PublicKey getPublicKey() throws SecurityModuleException {
    return ecPublicKey::getW;
  }

  @Override
  public Bytes32 calculateECDHKeyAgreement(PublicKey theirKey) throws SecurityModuleException {
    LOG.debug("Calculating ECDH key agreement ...");
    // convert Besu PublicKey (which wraps ECPoint) to java.security.PublicKey
    java.security.PublicKey theirPublicKey =
        SignatureUtil.eCPointToPublicKey(theirKey.getW(), provider);

    // generate ECDH Key Agreement
    try {
      final KeyAgreement keyAgreement = KeyAgreement.getInstance(KEY_AGREEMENT_ALGORITHM, provider);
      keyAgreement.init(privateKey);
      keyAgreement.doPhase(theirPublicKey, true);
      return Bytes32.wrap(keyAgreement.generateSecret());
    } catch (final Exception e) {
      throw new SecurityModuleException("Error calculating ECDH key agreement", e);
    }
  }
}
