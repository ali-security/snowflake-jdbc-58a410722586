/*
 * Copyright (c) 2026 Snowflake Computing Inc. All rights reserved.
 */

package net.snowflake.client.core;

import com.google.common.base.Strings;
import java.util.Arrays;
import net.snowflake.client.jdbc.SnowflakeUtil;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.impl.conn.DefaultRoutePlanner;
import org.apache.http.impl.conn.DefaultSchemePortResolver;
import org.apache.http.protocol.HttpContext;

/**
 * SdkProxyRoutePlanner delegates a Proxy Route Planner from the settings instead of the system
 * properties. It will use the proxy created from proxyHost, proxyPort, and proxyProtocol and filter
 * the hosts who matches nonProxyHosts pattern.
 *
 * <p>The nonProxyHosts entries are simple wildcard patterns ('*' is the only special character);
 * they are never interpreted as regular expressions.
 */
@SnowflakeJdbcInternalApi
public class SdkProxyRoutePlanner extends DefaultRoutePlanner {
  private final HttpHost proxy;
  private final String[] hostPatterns;

  public SdkProxyRoutePlanner(
      String proxyHost, int proxyPort, HttpProtocol proxyProtocol, String nonProxyHosts) {
    super(DefaultSchemePortResolver.INSTANCE);
    proxy = new HttpHost(proxyHost, proxyPort, proxyProtocol.getScheme());
    if (!Strings.isNullOrEmpty(nonProxyHosts)) {
      hostPatterns = nonProxyHosts.split("\\|");
    } else {
      hostPatterns = null;
    }
  }

  private boolean doesTargetMatchNonProxyHosts(HttpHost target) {
    if (hostPatterns == null) {
      return false;
    }
    String targetHost = target.getHostName().toLowerCase();
    return Arrays.stream(hostPatterns)
        .anyMatch(pattern -> SnowflakeUtil.hostnameMatchesGlob(targetHost, pattern));
  }

  @Override
  protected HttpHost determineProxy(
      final HttpHost target, final HttpRequest request, final HttpContext context)
      throws HttpException {
    return doesTargetMatchNonProxyHosts(target) ? null : proxy;
  }
}
