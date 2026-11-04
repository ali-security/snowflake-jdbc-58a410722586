/*
 * Copyright (c) 2012-2022 Snowflake Computing Inc. All rights reserved.
 */

package net.snowflake.client.core;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertThrows;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;
import net.snowflake.client.jdbc.SnowflakeSQLException;
import net.snowflake.common.core.ClientAuthnDTO;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.junit.Test;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

class MockAuthExternalBrowserHandlers
    implements SessionUtilExternalBrowser.AuthExternalBrowserHandlers {
  @Override
  public HttpPost build(URI uri) {
    HttpPost httpPost = mock(HttpPost.class);
    when(httpPost.getMethod()).thenReturn("POST");
    return httpPost;
  }

  @Override
  public void openBrowser(String ssoUrl) throws SFException {
    // nop. Don't open browser
  }

  @Override
  public void output(String msg) {
    // nop. No output
  }
}

/** Simulates SessionUtilExternalBrower without popping up a browser window */
class FakeSessionUtilExternalBrowser extends SessionUtilExternalBrowser {
  static final String MOCK_SAML_TOKEN = "MOCK_SAML_TOKEN";
  private final ServerSocket mockServerSocket;

  public static SessionUtilExternalBrowser createInstance(SFLoginInput loginInput, boolean isPost) {
    return new FakeSessionUtilExternalBrowser(loginInput, isPost);
  }

  private FakeSessionUtilExternalBrowser(SFLoginInput loginInput, boolean isPost) {
    super(loginInput, new MockAuthExternalBrowserHandlers());
    try {
      this.mockServerSocket = initMockServerSocket(isPost);
    } catch (IOException ex) {
      throw new RuntimeException("Failed to initialize ServerSocket mock");
    }
  }

  /** Uses the given (real) server socket instead of a mock, e.g. a real localhost listener. */
  FakeSessionUtilExternalBrowser(SFLoginInput loginInput, ServerSocket serverSocket) {
    super(loginInput, new MockAuthExternalBrowserHandlers());
    this.mockServerSocket = serverSocket;
  }

  /**
   * Mock ServerSocket and Socket.
   *
   * <p>Socket mock will be included in ServerSocket mock.
   *
   * @param isPost true if the response is POST request otherwise GET request
   * @return Server socket
   * @throws IOException if any IO error occurs
   */
  private static ServerSocket initMockServerSocket(boolean isPost) throws IOException {
    // mock client socket
    final Socket mockSocket = mock(Socket.class);
    String str;
    if (isPost) {
      str =
          String.format(
              "POST / HTTP/1.1\r\n"
                  + "USER-AGENT: snowflake client\r\n"
                  + "Origin: https://testaccount.snowflakecomputing.com\r\n"
                  + "\r\n"
                  + "token=%s&confirm=1",
              MOCK_SAML_TOKEN);
    } else {
      str =
          String.format(
              "GET /?token=%s&confirm=1 HTTP/1.1\r\n" + "USER-AGENT: snowflake client",
              MOCK_SAML_TOKEN);
    }
    InputStream stream = new ByteArrayInputStream(str.getBytes(StandardCharsets.UTF_8));
    when(mockSocket.getInputStream()).thenReturn(stream);
    when(mockSocket.getOutputStream()).thenReturn(new NullOutputStream());

    // mock server socket
    final ServerSocket mockServerSocket = mock(ServerSocket.class);
    when(mockServerSocket.getLocalPort()).thenReturn(12345);
    when(mockServerSocket.accept()).thenReturn(mockSocket);
    return mockServerSocket;
  }

  static class NullOutputStream extends OutputStream {
    @Override
    public void write(int b) throws IOException {}
  }

  @Override
  protected ServerSocket getServerSocket() throws SFException {
    return mockServerSocket;
  }

  @Override
  protected int getLocalPort(ServerSocket ssocket) {
    return super.getLocalPort(ssocket);
  }
}

public class SessionUtilExternalBrowserTest {
  private static final String MOCK_PROOF_KEY = "specialkey";
  private static final String MOCK_SSO_URL = "https://sso.someidp.net/";

  /**
   * Unit test for SessionUtilExternalBrowser
   *
   * @throws Throwable if any error occurs
   */
  @Test
  public void testSessionUtilExternalBrowser() throws Throwable {
    final SFLoginInput loginInput = initMockLoginInput();

    try (MockedStatic<HttpUtil> mockedHttpUtil = mockStatic(HttpUtil.class)) {
      mockedHttpUtil
          .when(
              () ->
                  HttpUtil.executeGeneralRequest(
                      Mockito.any(HttpRequestBase.class),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.nullable(HttpClientSettingsKey.class)))
          .thenReturn(
              "{\"success\":\"true\",\"data\":{\"proofKey\":\""
                  + MOCK_PROOF_KEY
                  + "\","
                  + " \"ssoUrl\":\""
                  + MOCK_SSO_URL
                  + "\"}}");

      SessionUtilExternalBrowser sub =
          FakeSessionUtilExternalBrowser.createInstance(loginInput, false);
      sub.authenticate();
      assertThat("", sub.getToken(), equalTo(FakeSessionUtilExternalBrowser.MOCK_SAML_TOKEN));

      sub = FakeSessionUtilExternalBrowser.createInstance(loginInput, true);
      sub.authenticate();
      assertThat("", sub.getToken(), equalTo(FakeSessionUtilExternalBrowser.MOCK_SAML_TOKEN));
    }
  }

  /**
   * Unit test for SessionUtilExternalBrowser (fail)
   *
   * @throws Throwable if any error occurs
   */
  @Test
  public void testSessionUtilExternalBrowserFail() throws Throwable {
    final SFLoginInput loginInput = initMockLoginInput();

    try (MockedStatic<HttpUtil> mockedHttpUtil = mockStatic(HttpUtil.class)) {
      mockedHttpUtil
          .when(
              () ->
                  HttpUtil.executeGeneralRequest(
                      Mockito.any(HttpRequestBase.class),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.anyInt(),
                      Mockito.nullable(HttpClientSettingsKey.class)))
          .thenReturn("{\"success\":\"false\",\"code\":\"123456\",\"message\":\"errormes\"}");

      SessionUtilExternalBrowser sub =
          FakeSessionUtilExternalBrowser.createInstance(loginInput, false);
      try {
        sub.authenticate();
        fail("should have failed with an exception.");
      } catch (SnowflakeSQLException ex) {
        assertThat("Error is expected", ex.getErrorCode(), equalTo(123456));
      }
    }
  }

  @Test
  public void testBuildDefaultHandler() throws URISyntaxException {
    SessionUtilExternalBrowser.DefaultAuthExternalBrowserHandlers handler =
        new SessionUtilExternalBrowser.DefaultAuthExternalBrowserHandlers();
    URI uri =
        new URI("https://testaccount.snowflakecomputing.com:443/session/authenticator-request");
    HttpPost postReq = handler.build(uri);
    assertEquals(
        "POST https://testaccount.snowflakecomputing.com:443/session/authenticator-request HTTP/1.1",
        postReq.toString());
  }

  @Test
  public void testInvalidSSOUrl() {
    SessionUtilExternalBrowser.DefaultAuthExternalBrowserHandlers handler =
        new SessionUtilExternalBrowser.DefaultAuthExternalBrowserHandlers();
    try {
      handler.openBrowser("file://invalidUrl");
    } catch (SFException ex) {
      assertTrue(ex.getMessage().contains("Invalid SSOUrl found"));
    }
  }

  @Test
  public void testAuthenticateAcceptsExactAndDefaultPortOrigins() throws Throwable {
    CallbackResult exact =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            postRequest("exact_token", "https://testaccount.snowflakecomputing.com", "\r\n"));
    assertEquals("exact_token", exact.token);

    CallbackResult defaultPort =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com:443/",
            postRequest(
                "default_port_token", "https://testaccount.snowflakecomputing.com", "\r\n"));
    assertEquals("default_port_token", defaultPort.token);
  }

  @Test
  public void testAuthenticateAcceptsOriginWithDefaultPath() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/session/authenticator-request",
            postRequest("slash_token", "https://testaccount.snowflakecomputing.com/", "\r\n"));
    assertEquals("slash_token", result.token);
  }

  @Test
  public void testAuthenticateAcceptsUnderscoreHostOrigin() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://foo_bar.snowflakecomputing.com/",
            postRequest("underscore_token", "https://foo_bar.snowflakecomputing.com", "\r\n"));
    assertEquals("underscore_token", result.token);
  }

  @Test
  public void testAuthenticateIgnoresForeignOriginThenAcceptsValidCallback() throws Throwable {
    String[] foreignOrigins = {
      "http://testaccount.snowflakecomputing.com",
      "https://other.snowflakecomputing.com",
      "https://testaccount.snowflakecomputing.com:8443",
      "https://testaccount.snowflakecomputing.com.invalid",
      "https://user@testaccount.snowflakecomputing.com",
      "https://testaccount.snowflakecomputing.com/extra",
      "https://testaccount.snowflakecomputing.com?q=1",
      "https://testaccount.snowflakecomputing.com#frag",
      "ftp://testaccount.snowflakecomputing.com",
      "null"
    };
    for (String foreignOrigin : foreignOrigins) {
      CallbackResult result =
          driveRealSocketCallbacks(
              "https://testaccount.snowflakecomputing.com/",
              postRequest("foreign_token", foreignOrigin, "\r\n"),
              getRequest("valid_token", null, "\r\n"));

      assertEquals(foreignOrigin, "valid_token", result.token);
      assertEquals(foreignOrigin, 2, result.responses.size());
      assertTrue(foreignOrigin, result.responses.get(0).isEmpty());
      assertTrue(foreignOrigin, result.responses.get(1).contains("Your identity was confirmed"));
    }
  }

  @Test
  public void testAuthenticateIgnoresBodyOriginThenAcceptsValidCallback() throws Throwable {
    String body = "token=body_token&Origin=https%3A%2F%2Ftestaccount.snowflakecomputing.com";
    String bodyOriginRequest =
        String.format(
            "POST / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Content-Type: application/x-www-form-urlencoded\r\n"
                + "Content-Length: %d\r\n\r\n%s",
            body.getBytes(StandardCharsets.UTF_8).length, body);

    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            bodyOriginRequest,
            getRequest("valid_token", null, "\r\n"));

    assertEquals("valid_token", result.token);
    assertTrue(result.responses.get(0).isEmpty());
  }

  @Test
  public void testAuthenticateAcceptsOriginlessAndNullOriginGet() throws Throwable {
    CallbackResult originless =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            getRequest("originless_token", null, "\r\n"));
    assertEquals("originless_token", originless.token);
    assertFalse(originless.responses.get(0).contains("Access-Control-Allow-Origin"));

    CallbackResult nullOrigin =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            getRequest("null_origin_token", "null", "\r\n"));
    assertEquals("null_origin_token", nullOrigin.token);
    assertFalse(nullOrigin.responses.get(0).contains("Access-Control-Allow-Origin"));
  }

  @Test
  public void testAuthenticateIgnoresForeignOriginGetThenAcceptsValidCallback() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            getRequest("foreign_get_token", "https://attacker.example.com", "\r\n"),
            getRequest("valid_token", null, "\r\n"));

    assertEquals("valid_token", result.token);
    assertTrue(result.responses.get(0).isEmpty());
    assertFalse(result.responses.get(1).contains("attacker.example.com"));
  }

  @Test
  public void testAuthenticateKeepsListeningAfterOriginAllowedGetWithoutToken() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            "GET / HTTP/1.1\r\n"
                + "Host: localhost\r\n"
                + "Origin: https://testaccount.snowflakecomputing.com\r\n\r\n",
            getRequest("after_tokenless_get", null, "\r\n"));

    assertEquals("after_tokenless_get", result.token);
    assertTrue(result.responses.get(0).isEmpty());
    assertTrue(result.responses.get(1).contains("Your identity was confirmed"));
  }

  @Test
  public void testAuthenticateKeepsListeningAfterFaviconThenAcceptsToken() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            "GET /favicon.ico HTTP/1.1\r\nHost: localhost\r\n\r\n",
            getRequest("after_favicon", null, "\r\n"));

    assertEquals("after_favicon", result.token);
    assertTrue(result.responses.get(0).isEmpty());
  }

  @Test
  public void testAuthenticateKeepsListeningAfterEmptyConnectionThenAcceptsToken()
      throws Throwable {
    // A connection that closes without sending any bytes, e.g. a browser preconnect socket.
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            "",
            getRequest("after_empty_connection", null, "\r\n"));

    assertEquals("after_empty_connection", result.token);
    assertTrue(result.responses.get(0).isEmpty());
  }

  @Test
  public void testAuthenticateKeepsListeningAfterJsonPostWithoutToken() throws Throwable {
    String emptyJson = "{}";
    String emptyPost =
        "POST / HTTP/1.1\r\n"
            + "Host: localhost\r\n"
            + "Origin: https://testaccount.snowflakecomputing.com\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: "
            + emptyJson.getBytes(StandardCharsets.UTF_8).length
            + "\r\n\r\n"
            + emptyJson;

    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            emptyPost,
            getRequest("after_empty_json", null, "\r\n"));

    assertEquals("after_empty_json", result.token);
    assertTrue(result.responses.get(0).isEmpty());
  }

  @Test
  public void testAuthenticateAcceptsMatchingOriginJsonPost() throws Throwable {
    String body = "{\"token\":\"json_token\",\"consent\":true}";
    String request =
        "POST / HTTP/1.1\r\n"
            + "Host: localhost\r\n"
            + "Origin: https://testaccount.snowflakecomputing.com\r\n"
            + "Content-Type: application/json\r\n"
            + "Content-Length: "
            + body.getBytes(StandardCharsets.UTF_8).length
            + "\r\n\r\n"
            + body;

    CallbackResult result =
        driveRealSocketCallbacks("https://testaccount.snowflakecomputing.com/", request);

    assertEquals("json_token", result.token);
    assertTrue(
        result
            .responses
            .get(0)
            .contains("Access-Control-Allow-Origin: https://testaccount.snowflakecomputing.com"));
  }

  @Test
  public void testCallbackSocketBacklogIsFive() {
    assertEquals(5, SessionUtilExternalBrowser.CALLBACK_SOCKET_BACKLOG);
  }

  @Test
  public void testAuthenticateParsesLfHeaders() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            postRequest("lf_token", "https://testaccount.snowflakecomputing.com", "\n"));

    assertEquals("lf_token", result.token);
  }

  @Test
  public void testCorsPreflightRequiresPostAllowedHeadersAndMatchingOrigin() throws Throwable {
    String validPreflight =
        optionsRequest(
            "https://testaccount.snowflakecomputing.com", "post", "content-type", "\r\n");
    CallbackResult valid =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            validPreflight,
            getRequest("valid_token", null, "\r\n"));
    assertTrue(
        valid
            .responses
            .get(0)
            .contains(
                "Access-Control-Allow-Origin: " + "https://testaccount.snowflakecomputing.com"));
    assertTrue(valid.responses.get(0).contains("Access-Control-Allow-Headers: Content-Type"));

    CallbackResult invalid =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            optionsRequest("https://other.snowflakecomputing.com", "POST", "Content-Type", "\r\n"),
            optionsRequest(
                "https://testaccount.snowflakecomputing.com", "GET", "Content-Type", "\r\n"),
            optionsRequest(
                "https://testaccount.snowflakecomputing.com",
                "POST",
                "Content-Type, X-Custom",
                "\r\n"),
            getRequest("valid_token", null, "\r\n"));
    assertEquals("valid_token", invalid.token);
    assertTrue(invalid.responses.get(0).isEmpty());
    assertTrue(invalid.responses.get(1).isEmpty());
    assertTrue(invalid.responses.get(2).isEmpty());
  }

  @Test
  public void testAuthenticateFailsWhenForeignOriginCallbackIsNotFollowedByValidOne() {
    SFException ex =
        assertThrows(
            SFException.class,
            () ->
                driveRealSocketCallbacks(
                    200,
                    "https://testaccount.snowflakecomputing.com/",
                    postRequest("foreign_token", "https://attacker.example.com", "\r\n")));
    assertTrue(ex.getMessage().contains("came from origin https://attacker.example.com"));
    assertTrue(ex.getMessage().contains("https://testaccount.snowflakecomputing.com:443"));
    assertFalse(ex.getMessage().contains("foreign_token"));
  }

  @Test
  public void testAuthenticateFailsWhenForeignPreflightIsNotFollowedByValidCallback() {
    SFException ex =
        assertThrows(
            SFException.class,
            () ->
                driveRealSocketCallbacks(
                    200,
                    "https://testaccount.snowflakecomputing.com/",
                    optionsRequest(
                        "https://other.snowflakecomputing.com", "POST", "Content-Type", "\r\n")));
    assertTrue(ex.getMessage().contains("came from origin https://other.snowflakecomputing.com"));
  }

  @Test
  public void testAuthenticateAcceptsValidCallbackAfterForeignOriginWithinDeadline()
      throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            5_000,
            "https://testaccount.snowflakecomputing.com/",
            postRequest("foreign_token", "https://attacker.example.com", "\r\n"),
            getRequest("valid_token", null, "\r\n"));
    assertEquals("valid_token", result.token);
  }

  @Test
  public void testForeignPreflightOriginIsNotReflectedIntoTokenResponse() throws Throwable {
    CallbackResult result =
        driveRealSocketCallbacks(
            "https://testaccount.snowflakecomputing.com/",
            optionsRequest("https://attacker.example.com", "POST", "Content-Type", "\r\n"),
            getRequest("valid_token", null, "\r\n"));

    assertEquals("valid_token", result.token);
    assertTrue(result.responses.get(0).isEmpty());
    assertFalse(result.responses.get(1).contains("attacker.example.com"));
    assertFalse(result.responses.get(1).contains("Access-Control-Allow-Origin"));
  }

  private static String postRequest(String token, String origin, String lineEnding) {
    String body = "token=" + token + "&confirm=1";
    return "POST / HTTP/1.1"
        + lineEnding
        + "Host: localhost"
        + lineEnding
        + "Origin: "
        + origin
        + lineEnding
        + "Content-Type: application/x-www-form-urlencoded"
        + lineEnding
        + "Content-Length: "
        + body.getBytes(StandardCharsets.UTF_8).length
        + lineEnding
        + lineEnding
        + body;
  }

  private static String getRequest(String token, String origin, String lineEnding) {
    return "GET /?token="
        + token
        + "&confirm=1 HTTP/1.1"
        + lineEnding
        + "Host: localhost"
        + lineEnding
        + (origin == null ? "" : "Origin: " + origin + lineEnding)
        + lineEnding;
  }

  private static String optionsRequest(
      String origin, String method, String headers, String lineEnding) {
    return "OPTIONS / HTTP/1.1"
        + lineEnding
        + "Host: localhost"
        + lineEnding
        + "Origin: "
        + origin
        + lineEnding
        + "Access-Control-Request-Method: "
        + method
        + lineEnding
        + "Access-Control-Request-Headers: "
        + headers
        + lineEnding
        + lineEnding;
  }

  private static final class CallbackResult {
    private final String token;
    private final List<String> responses;

    private CallbackResult(String token, List<String> responses) {
      this.token = token;
      this.responses = responses;
    }
  }

  /**
   * Drives the real {@code authenticate()} loop against a real localhost {@link ServerSocket}, with
   * a background thread acting as the browser that sends {@code requests} one connection at a
   * time and records every response.
   */
  private CallbackResult driveRealSocketCallbacks(String serverUrl, String... requests)
      throws Throwable {
    return driveRealSocketCallbacks(
        SessionUtilExternalBrowser.REJECTED_CALLBACK_TIMEOUT_MILLIS, serverUrl, requests);
  }

  private CallbackResult driveRealSocketCallbacks(
      int rejectedCallbackTimeoutMillis, String serverUrl, String... requests) throws Throwable {
    final SFLoginInput loginInput = initMockLoginInput();
    when(loginInput.getServerUrl()).thenReturn(serverUrl);

    try (MockedStatic<HttpUtil> mockedHttpUtil = mockStatic(HttpUtil.class);
        ServerSocket serverSocket = new ServerSocket(0, 0, InetAddress.getByName("localhost"))) {
      mockSsoUrlResponse(mockedHttpUtil);
      // fail rather than hang forever if the listener never gets a token it accepts
      serverSocket.setSoTimeout(30_000);
      final int port = serverSocket.getLocalPort();
      final AtomicReference<Throwable> clientError = new AtomicReference<>();
      final List<String> responses = new ArrayList<>();
      Thread browser =
          new Thread(
              () -> {
                try {
                  for (String request : requests) {
                    try (Socket socket = new Socket("localhost", port);
                        ByteArrayOutputStream response = new ByteArrayOutputStream()) {
                      socket.getOutputStream().write(request.getBytes(StandardCharsets.UTF_8));
                      socket.shutdownOutput();
                      byte[] buffer = new byte[4096];
                      int count;
                      while ((count = socket.getInputStream().read(buffer)) >= 0) {
                        response.write(buffer, 0, count);
                      }
                      responses.add(response.toString(StandardCharsets.UTF_8.name()));
                    }
                  }
                } catch (Throwable t) {
                  clientError.set(t);
                }
              });
      browser.setDaemon(true);
      browser.start();

      SessionUtilExternalBrowser subject =
          new FakeSessionUtilExternalBrowser(loginInput, serverSocket);
      subject.rejectedCallbackTimeoutMillis = rejectedCallbackTimeoutMillis;
      subject.authenticate();

      browser.join(10_000);
      assertFalse("Browser client thread did not finish", browser.isAlive());
      if (clientError.get() != null) {
        throw new AssertionError("Browser client thread failed", clientError.get());
      }
      return new CallbackResult(subject.getToken(), responses);
    }
  }

  private static void mockSsoUrlResponse(MockedStatic<HttpUtil> mockedHttpUtil) {
    mockedHttpUtil
        .when(
            () ->
                HttpUtil.executeGeneralRequest(
                    Mockito.any(HttpRequestBase.class),
                    Mockito.anyInt(),
                    Mockito.anyInt(),
                    Mockito.anyInt(),
                    Mockito.anyInt(),
                    Mockito.nullable(HttpClientSettingsKey.class)))
        .thenReturn(
            "{\"success\":\"true\",\"data\":{\"proofKey\":\""
                + MOCK_PROOF_KEY
                + "\","
                + " \"ssoUrl\":\""
                + MOCK_SSO_URL
                + "\"}}");
  }

  /**
   * Mock HttpUtil and SFLoginInput
   *
   * @return a mock object for SFLoginInput
   */
  private SFLoginInput initMockLoginInput() {
    // mock SFLoginInput
    SFLoginInput loginInput = mock(SFLoginInput.class);
    when(loginInput.getServerUrl()).thenReturn("https://testaccount.snowflakecomputing.com/");
    when(loginInput.getAuthenticator())
        .thenReturn(ClientAuthnDTO.AuthenticatorType.EXTERNALBROWSER.name());
    when(loginInput.getAccountName()).thenReturn("testaccount");
    when(loginInput.getUserName()).thenReturn("testuser");
    when(loginInput.getDisableConsoleLogin()).thenReturn(true);
    return loginInput;
  }
}
