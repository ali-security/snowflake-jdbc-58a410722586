/*
 * Copyright (c) 2026 Snowflake Computing Inc. All rights reserved.
 */
package net.snowflake.client.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import net.snowflake.client.core.HttpUtil;
import org.apache.http.HttpVersion;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.entity.StringEntity;
import org.apache.http.message.BasicHttpResponse;
import org.apache.http.message.BasicStatusLine;
import org.junit.Test;
import org.mockito.MockedStatic;

/**
 * The chunk download path used to render whole {@link org.apache.http.HttpResponse} objects, header
 * values included, into log messages and exception messages. These tests make sure only the status
 * line and the header names reach either of them.
 */
public class DefaultResultStreamProviderTest {
  // pragma: allowlist nextline secret
  private static final String CUSTOMER_KEY = "3dOoaBhkBOv1L15q1QYdz6z5Rzg1qEQTsm2ANFcaZ8I=";
  private static final String SSE_C_KEY_HEADER = "x-amz-server-side-encryption-customer-key";
  // A header value no masking pattern knows about: only leaving header values out keeps it away.
  private static final String OPAQUE_HEADER = "x-amz-meta-opaque";
  private static final String OPAQUE_VALUE = "opaqueHeaderValueThatMustNotBeLogged";
  // pragma: allowlist nextline secret
  private static final String SECURITY_TOKEN =
      "IQoJb3JpZ2luX2VjEJr%2F%2F%2F%2F%2F%2F%2F%2F%2F%2FwEaCXVzLWVhc3QtMSJHMEUCIQ%3D%3D";
  private static final String CHUNK_URL =
      "https://bucket.s3.amazonaws.com/results/data_0_0_0?"
          + "X-Amz-Algorithm=AWS4-HMAC-SHA256"
          + "&X-Amz-Credential=AKIAIOSFODNN7EXAMPLE%2F20130524%2Fus-east-1%2Fs3%2Faws4_request"
          + "&X-Amz-Security-Token="
          + SECURITY_TOKEN
          + "&X-Amz-Signature=zFiRkdB9RtRRYomppVes4fQ%2ByWw%3D";

  private static class TestResponse extends BasicHttpResponse implements CloseableHttpResponse {
    TestResponse(int statusCode, String reasonPhrase) {
      super(new BasicStatusLine(HttpVersion.HTTP_1_1, statusCode, reasonPhrase));
    }

    @Override
    public void close() {}
  }

  private static class CapturingHandler extends Handler {
    private final List<String> messages = Collections.synchronizedList(new ArrayList<>());

    @Override
    public void publish(LogRecord record) {
      messages.add(record.getMessage());
    }

    @Override
    public void flush() {}

    @Override
    public void close() {}
  }

  private static TestResponse responseWithSecretHeaders(String contentEncoding) throws Exception {
    TestResponse response = new TestResponse(200, "OK");
    response.addHeader(SSE_C_KEY_HEADER, CUSTOMER_KEY);
    response.addHeader(OPAQUE_HEADER, OPAQUE_VALUE);
    response.addHeader("Content-Encoding", contentEncoding);
    response.setEntity(new StringEntity("[\"a\",\"b\"]"));
    return response;
  }

  @Test
  public void testDescribeForLoggingOmitsHeaderValues() throws Exception {
    TestResponse response = responseWithSecretHeaders("gzip");

    String description = DefaultResultStreamProvider.describeForLogging(response);

    assertEquals(
        "status: 200 OK, header names: ["
            + SSE_C_KEY_HEADER
            + ", "
            + OPAQUE_HEADER
            + ", Content-Encoding]",
        description);
    assertFalse("customer key leaked: " + description, description.contains(CUSTOMER_KEY));
    assertFalse("header value leaked: " + description, description.contains(OPAQUE_VALUE));
    // HttpResponse#toString() is what used to be logged, and it does render header values
    assertTrue(response.toString().contains(CUSTOMER_KEY));

    assertEquals("null response", DefaultResultStreamProvider.describeForLogging(null));
  }

  /**
   * Drives a chunk download whose response cannot be decompressed. The exception message is not run
   * through the log masking, so it must not render response header values, and neither the log
   * messages written on the way may carry the chunk encryption key or the pre-signed URL secrets.
   */
  @Test
  public void testChunkDownloadDoesNotExposeSecretsInLogsOrExceptions() throws Exception {
    Map<String, String> chunkHeaders = Collections.singletonMap(SSE_C_KEY_HEADER, CUSTOMER_KEY);
    ChunkDownloadContext context =
        new ChunkDownloadContext(
            mock(SnowflakeChunkDownloader.class),
            new JsonResultChunk(CHUNK_URL, 2, 2, 100, null),
            null,
            0,
            chunkHeaders,
            1000,
            1000,
            1000,
            0,
            null);
    // "br" is not a supported content encoding, so decompression fails
    TestResponse response = responseWithSecretHeaders("br");

    Logger jdkLogger = Logger.getLogger(SnowflakeResultSetSerializableV1.class.getName());
    Level levelToRestore = jdkLogger.getLevel();
    boolean useParentHandlersToRestore = jdkLogger.getUseParentHandlers();
    CapturingHandler handler = new CapturingHandler();
    jdkLogger.setLevel(Level.ALL);
    jdkLogger.setUseParentHandlers(false);
    jdkLogger.addHandler(handler);

    try (MockedStatic<HttpUtil> httpUtil = mockStatic(HttpUtil.class);
        MockedStatic<RestRequest> restRequest = mockStatic(RestRequest.class)) {
      restRequest
          .when(
              () ->
                  RestRequest.execute(
                      any(),
                      any(),
                      anyLong(),
                      anyLong(),
                      anyInt(),
                      anyInt(),
                      anyInt(),
                      any(),
                      anyBoolean(),
                      anyBoolean(),
                      anyBoolean(),
                      anyBoolean(),
                      anyBoolean(),
                      any()))
          .thenReturn(response);

      try {
        new DefaultResultStreamProvider().getInputStream(context);
        fail("decompressing a chunk with an unsupported encoding should fail");
      } catch (SnowflakeSQLLoggedException ex) {
        String message = ex.getMessage();
        assertTrue(
            message,
            message.contains(
                "Failed to decompress data: status: 200 OK, header names: ["
                    + SSE_C_KEY_HEADER
                    + ", "
                    + OPAQUE_HEADER
                    + ", Content-Encoding]"));
        assertFalse("customer key leaked: " + message, message.contains(CUSTOMER_KEY));
        assertFalse("header value leaked: " + message, message.contains(OPAQUE_VALUE));
      }
    } finally {
      jdkLogger.removeHandler(handler);
      jdkLogger.setUseParentHandlers(useParentHandlersToRestore);
      jdkLogger.setLevel(levelToRestore);
    }

    List<String> messages;
    synchronized (handler.messages) {
      messages = new ArrayList<>(handler.messages);
    }
    assertTrue("expected the chunk download to log", messages.size() > 0);
    boolean headerKeyLogged = false;
    for (String logged : messages) {
      assertFalse("customer key leaked: " + logged, logged.contains(CUSTOMER_KEY));
      assertFalse("header value leaked: " + logged, logged.contains(OPAQUE_VALUE));
      assertFalse("security token leaked: " + logged, logged.contains(SECURITY_TOKEN));
      // the part of the token after its first '%' escape, which a token filter that stops at
      // '%' would leave behind
      assertFalse("security token leaked: " + logged, logged.contains("wEaCXVzLWVhc3QtMSJHMEUCIQ"));
      headerKeyLogged |= logged.equals("Adding header key: " + SSE_C_KEY_HEADER);
    }
    assertTrue("expected the chunk header name to be logged: " + messages, headerKeyLogged);
  }
}
