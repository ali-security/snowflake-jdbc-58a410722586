/*
 * Copyright (c) 2026 Snowflake Computing Inc. All rights reserved.
 */
package net.snowflake.client.jdbc.cloud.storage;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import com.amazonaws.ClientConfiguration;
import com.amazonaws.http.apache.SdkProxyRoutePlanner;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Properties;
import net.snowflake.client.core.HttpClientSettingsKey;
import net.snowflake.client.core.OCSPMode;
import org.apache.http.HttpException;
import org.apache.http.HttpHost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.message.BasicHttpRequest;
import org.junit.Test;

public class S3HttpUtilTest {
  private static final String MALICIOUS_HOST =
      "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaac";

  @Test
  public void testPrepareNonProxyHosts() {
    Map<String, String> testCases = new LinkedHashMap<>();
    testCases.put("example.com", "example\\.com");
    testCases.put("example.com|test.org | localhost", "example\\.com|test\\.org|localhost");
    testCases.put("*.example.com", "*\\.example\\.com");
    testCases.put(
        "example.com|*.test.org|localhost|*.internal.*",
        "example\\.com|*\\.test\\.org|localhost|(?>*\\.internal\\.)*");
    testCases.put("(a+)+", "\\(a\\+\\)\\+");
    testCases.put("[a-z]+$|^a?{2}\\d", "\\[a\\-z\\]\\+\\$|\\^a\\?\\{2\\}\\\\d");
    for (Map.Entry<String, String> testCase : testCases.entrySet()) {
      assertEquals(
          "nonProxyHosts: " + testCase.getKey(),
          testCase.getValue(),
          S3HttpUtil.prepareNonProxyHosts(testCase.getKey()));
    }
    assertNull(S3HttpUtil.prepareNonProxyHosts(null));
    assertEquals("", S3HttpUtil.prepareNonProxyHosts(""));
  }

  @Test
  public void testNonProxyHostsAreMatchedAsWildcardsByAwsSdk() throws Exception {
    ClientConfiguration clientConfig = new ClientConfiguration();
    S3HttpUtil.setProxyForS3(
        createProxyKey("*.amazonaws.com | LOCALHOST|s3.example.com|foo*bar*baz"), clientConfig);
    SdkProxyRoutePlanner planner = createAwsSdkRoutePlanner(clientConfig);

    assertNull(determineRouteProxy(planner, "bucket.s3.us-west-2.amazonaws.com"));
    assertNull(determineRouteProxy(planner, "localhost"));
    assertNull(determineRouteProxy(planner, "S3.Example.com"));
    assertNull(determineRouteProxy(planner, "fooXbarYbaz"));
    assertNotNull(determineRouteProxy(planner, "amazonaws.com"));
    assertNotNull(determineRouteProxy(planner, "s3XexampleXcom"));
    assertNotNull(determineRouteProxy(planner, "fooXbaz"));
    assertNotNull(determineRouteProxy(planner, "snowflakecomputing.com"));
  }

  @Test
  public void testSetProxyForS3ReDoSPatternsDoNotHangInAwsSdk() throws Exception {
    // The exact ReDoS payload from the vulnerability report, chained payloads and wildcard-only
    // payloads, matched by the route planner the AWS SDK creates for the S3 client
    String[] maliciousNonProxyHosts = {
      "(a+)+",
      "(a+)+|(a|aa)+|(a|a?)+|([a-z]+)*",
      "*************************b",
      "*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b"
    };
    for (String nonProxyHosts : maliciousNonProxyHosts) {
      ClientConfiguration clientConfig = new ClientConfiguration();
      S3HttpUtil.setProxyForS3(createProxyKey(nonProxyHosts), clientConfig);
      assertProxiedQuickly(createAwsSdkRoutePlanner(clientConfig), nonProxyHosts);
    }
  }

  @Test
  public void testSetSessionlessProxyForS3ReDoSPatternDoesNotHangInAwsSdk() throws Exception {
    Properties props = new Properties();
    props.put("useProxy", "true");
    props.put("proxyHost", "localhost");
    props.put("proxyPort", "8084");
    props.put("nonProxyHosts", "(a+)+ | *a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b");
    props.put("proxyProtocol", "http");
    ClientConfiguration clientConfig = new ClientConfiguration();
    S3HttpUtil.setSessionlessProxyForS3(props, clientConfig);
    assertProxiedQuickly(
        createAwsSdkRoutePlanner(clientConfig), props.getProperty("nonProxyHosts"));
  }

  private static void assertProxiedQuickly(SdkProxyRoutePlanner planner, String nonProxyHosts)
      throws HttpException {
    long start = System.currentTimeMillis();
    assertNotNull(nonProxyHosts, determineRouteProxy(planner, MALICIOUS_HOST));
    long elapsed = System.currentTimeMillis() - start;
    assertTrue(
        "Non-proxy host matching of "
            + nonProxyHosts
            + " should complete nearly instantly, took "
            + elapsed
            + "ms",
        elapsed < 1000);
  }

  private static HttpClientSettingsKey createProxyKey(String nonProxyHosts) {
    return new HttpClientSettingsKey(
        OCSPMode.FAIL_OPEN,
        "proxy.example.com",
        8080,
        nonProxyHosts,
        "testuser",
        "pw",
        "http",
        "jdbc",
        false);
  }

  /** Creates the route planner exactly as the AWS SDK does for a client with this configuration. */
  private static SdkProxyRoutePlanner createAwsSdkRoutePlanner(ClientConfiguration clientConfig) {
    return new SdkProxyRoutePlanner(
        clientConfig.getProxyHost(),
        clientConfig.getProxyPort(),
        clientConfig.getProxyProtocol(),
        clientConfig.getNonProxyHosts());
  }

  private static HttpHost determineRouteProxy(SdkProxyRoutePlanner planner, String host)
      throws HttpException {
    return planner
        .determineRoute(
            new HttpHost(host), new BasicHttpRequest("GET", "/"), HttpClientContext.create())
        .getProxyHost();
  }
}
