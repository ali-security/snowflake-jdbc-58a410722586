/*
 * Copyright (c) 2026 Snowflake Computing Inc. All rights reserved.
 */
package net.snowflake.client.jdbc;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;
import net.snowflake.client.core.QueryResultFormat;
import org.junit.Test;

public class SnowflakeChunkDownloaderTest {
  // pragma: allowlist nextline secret
  private static final String QRMK = "3dOoaBhkBOv1L15q1QYdz6z5Rzg1qEQTsm2ANFcaZ8I=";

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

  /** The query result master key decrypts every result chunk, so only its presence is logged. */
  @Test
  public void testQrmkValueIsNotLogged() throws Exception {
    SnowflakeResultSetSerializableV1 resultSetSerializable =
        mock(SnowflakeResultSetSerializableV1.class);
    when(resultSetSerializable.getQrmk()).thenReturn(QRMK);
    when(resultSetSerializable.getQueryResultFormat()).thenReturn(QueryResultFormat.JSON);
    // no chunks: the constructor logs the key details and then stops with an error
    when(resultSetSerializable.getChunkFileCount()).thenReturn(0);

    Logger jdkLogger = Logger.getLogger(SnowflakeChunkDownloader.class.getName());
    Level levelToRestore = jdkLogger.getLevel();
    boolean useParentHandlersToRestore = jdkLogger.getUseParentHandlers();
    CapturingHandler handler = new CapturingHandler();
    jdkLogger.setLevel(Level.ALL);
    jdkLogger.setUseParentHandlers(false);
    jdkLogger.addHandler(handler);

    try {
      new SnowflakeChunkDownloader(resultSetSerializable);
      fail("a result set without chunks should be rejected");
    } catch (SnowflakeSQLLoggedException expected) {
      // expected
    } finally {
      jdkLogger.removeHandler(handler);
      jdkLogger.setUseParentHandlers(useParentHandlersToRestore);
      jdkLogger.setLevel(levelToRestore);
    }

    List<String> messages;
    synchronized (handler.messages) {
      messages = new ArrayList<>(handler.messages);
    }
    for (String logged : messages) {
      assertFalse("qrmk leaked: " + logged, logged.contains(QRMK));
    }
    assertTrue(
        "expected the presence of the qrmk to be logged: " + messages,
        messages.contains("qrmk present: true"));
  }
}
