// Copyright 2024, Usman Saleem.
// SPDX-License-Identifier: (Apache-2.0 OR MIT)
package info.usmans.besu.plugin.softhsm;

import static info.usmans.besu.plugin.softhsm.Pkcs11HsmPlugin.SECURITY_MODULE_NAME;

import java.nio.file.Path;
import picocli.CommandLine.Option;

/** Represents cli options that are required by the Besu PKCS11-SoftHSM plugin. */
public class Pkcs11PluginCliOptions {
  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-config-path",
      description = "Path to the PKCS11 configuration file",
      required = false,
      paramLabel = "<path>")
  private Path pkcs11ConfigPath;

  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-ask-password",
      description = "Prompt for PIN/password on startup (interactive stdin/tty)",
      required = true)
  private boolean askPassword;

  @Option(
      names = "--plugin-" + SECURITY_MODULE_NAME + "-key-alias",
      description = "Alias or label of the private key that is stored in the HSM",
      required = true,
      paramLabel = "<label>")
  private String privateKeyAlias;

  public boolean isAskPassword() {
    return askPassword;
  }

  /** Default constructor. Performs no initialization. */
  public Pkcs11PluginCliOptions() {}

  /**
   * Constructor that initializes the PKCS11 configuration file path.
   *
   * @param pkcs11ConfigPath the path to the PKCS11 configuration file
   */
  public Pkcs11PluginCliOptions(final Path pkcs11ConfigPath) {
    this.pkcs11ConfigPath = pkcs11ConfigPath;
  }

  /**
   * Returns the path to the PKCS11 configuration file.
   *
   * @return the path to the PKCS11 configuration file
   */
  public Path getPkcs11ConfigPath() {
    return pkcs11ConfigPath;
  }

  /**
   * Returns the alias or label of the private key that is stored in the HSM.
   *
   * @return the alias or label of the private key that is stored in the HSM
   */
  public String getPrivateKeyAlias() {
    return privateKeyAlias;
  }
}
