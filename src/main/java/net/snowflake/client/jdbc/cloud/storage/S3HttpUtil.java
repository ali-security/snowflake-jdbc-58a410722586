/*
 * Copyright (c) 2024 Snowflake Computing Inc. All rights reserved.
 */

package net.snowflake.client.jdbc.cloud.storage;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.Protocol;
import com.google.common.base.Strings;
import java.util.Arrays;
import java.util.Properties;
import java.util.stream.Collectors;
import net.snowflake.client.core.HttpClientSettingsKey;
import net.snowflake.client.core.HttpProtocol;
import net.snowflake.client.core.SFSessionProperty;
import net.snowflake.client.core.SnowflakeJdbcInternalApi;
import net.snowflake.client.jdbc.ErrorCode;
import net.snowflake.client.jdbc.SnowflakeSQLException;

@SnowflakeJdbcInternalApi
public class S3HttpUtil {
  /**
   * A static function to set S3 proxy params when there is a valid session
   *
   * @param key key to HttpClient map containing OCSP and proxy info
   * @param clientConfig the configuration needed by S3 to set the proxy
   */
  public static void setProxyForS3(HttpClientSettingsKey key, ClientConfiguration clientConfig) {
    if (key != null && key.usesProxy()) {
      clientConfig.setProxyProtocol(
          key.getProxyHttpProtocol() == HttpProtocol.HTTPS ? Protocol.HTTPS : Protocol.HTTP);
      clientConfig.setProxyHost(key.getProxyHost());
      clientConfig.setProxyPort(key.getProxyPort());
      clientConfig.setNonProxyHosts(prepareNonProxyHosts(key.getNonProxyHosts()));
      if (!Strings.isNullOrEmpty(key.getProxyUser())
          && !Strings.isNullOrEmpty(key.getProxyPassword())) {
        clientConfig.setProxyUsername(key.getProxyUser());
        clientConfig.setProxyPassword(key.getProxyPassword());
      }
    }
  }

  /**
   * A static function to set S3 proxy params for sessionless connections using the proxy params
   * from the StageInfo
   *
   * @param proxyProperties proxy properties
   * @param clientConfig the configuration needed by S3 to set the proxy
   * @throws SnowflakeSQLException
   */
  public static void setSessionlessProxyForS3(
      Properties proxyProperties, ClientConfiguration clientConfig) throws SnowflakeSQLException {
    // do nothing yet
    if (proxyProperties != null
        && proxyProperties.size() > 0
        && proxyProperties.getProperty(SFSessionProperty.USE_PROXY.getPropertyKey()) != null) {
      Boolean useProxy =
          Boolean.valueOf(
              proxyProperties.getProperty(SFSessionProperty.USE_PROXY.getPropertyKey()));
      if (useProxy) {
        // set up other proxy related values.
        String proxyHost =
            proxyProperties.getProperty(SFSessionProperty.PROXY_HOST.getPropertyKey());
        int proxyPort;
        try {
          proxyPort =
              Integer.parseInt(
                  proxyProperties.getProperty(SFSessionProperty.PROXY_PORT.getPropertyKey()));
        } catch (NumberFormatException | NullPointerException e) {
          throw new SnowflakeSQLException(
              ErrorCode.INVALID_PROXY_PROPERTIES, "Could not parse port number");
        }
        String proxyUser =
            proxyProperties.getProperty(SFSessionProperty.PROXY_USER.getPropertyKey());
        String proxyPassword =
            proxyProperties.getProperty(SFSessionProperty.PROXY_PASSWORD.getPropertyKey());
        String nonProxyHosts =
            proxyProperties.getProperty(SFSessionProperty.NON_PROXY_HOSTS.getPropertyKey());
        String proxyProtocol =
            proxyProperties.getProperty(SFSessionProperty.PROXY_PROTOCOL.getPropertyKey());
        Protocol protocolEnum =
            (!Strings.isNullOrEmpty(proxyProtocol) && proxyProtocol.equalsIgnoreCase("https"))
                ? Protocol.HTTPS
                : Protocol.HTTP;
        clientConfig.setProxyHost(proxyHost);
        clientConfig.setProxyPort(proxyPort);
        clientConfig.setNonProxyHosts(prepareNonProxyHosts(nonProxyHosts));
        clientConfig.setProxyProtocol(protocolEnum);
        if (!Strings.isNullOrEmpty(proxyUser) && !Strings.isNullOrEmpty(proxyPassword)) {
          clientConfig.setProxyUsername(proxyUser);
          clientConfig.setProxyPassword(proxyPassword);
        }
      }
    }
  }

  /**
   * The AWS SDK turns every nonProxyHosts entry into a regular expression (lower-cased, with each
   * '*' replaced by '.*?') and matches the target host against it with String.matches(). Rewrite
   * each '|'-separated wildcard entry so that it is safe to be used that way: all regex
   * metacharacters are escaped, so only '*' keeps its wildcard meaning, and every literal part
   * between two wildcards is wrapped in an atomic group, so wildcards can not backtrack against
   * each other. This prevents ReDoS through crafted nonProxyHosts entries.
   *
   * @param nonProxyHosts '|'-separated list of wildcard host patterns
   * @return the list in the form expected by the AWS SDK, or the input if it is null or empty
   */
  static String prepareNonProxyHosts(String nonProxyHosts) {
    if (Strings.isNullOrEmpty(nonProxyHosts)) {
      return nonProxyHosts;
    }
    return Arrays.stream(nonProxyHosts.split("\\|"))
        .map(String::trim)
        .map(S3HttpUtil::globToAwsSafePattern)
        .collect(Collectors.joining("|"));
  }

  private static String globToAwsSafePattern(String glob) {
    String[] parts = glob.split("\\*", -1);
    StringBuilder safePattern = new StringBuilder(escapeRegexMetacharacters(parts[0]));
    for (int i = 1; i < parts.length - 1; i++) {
      safePattern.append("(?>*").append(escapeRegexMetacharacters(parts[i])).append(')');
    }
    if (parts.length > 1) {
      safePattern.append('*').append(escapeRegexMetacharacters(parts[parts.length - 1]));
    }
    return safePattern.toString();
  }

  /**
   * Escapes with a backslash every ASCII character that is not a letter or a digit. Backslash
   * escaping (instead of Pattern.quote()) is required because the AWS SDK lower-cases the pattern.
   */
  private static String escapeRegexMetacharacters(String literal) {
    StringBuilder escaped = new StringBuilder(literal.length());
    for (char c : literal.toCharArray()) {
      if (c < 128 && !Character.isLetterOrDigit(c)) {
        escaped.append('\\');
      }
      escaped.append(c);
    }
    return escaped.toString();
  }
}
