package net.snowflake.client.core;

import static net.snowflake.client.jdbc.SnowflakeUtil.isWindows;
import static net.snowflake.client.jdbc.SnowflakeUtil.systemGetProperty;

import com.google.common.base.Strings;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.FileOwnerAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Arrays;
import java.util.Collection;
import net.snowflake.client.log.SFLogger;
import net.snowflake.client.log.SFLoggerFactory;

@SnowflakeJdbcInternalApi
public class FileUtil {
  private static final SFLogger logger = SFLoggerFactory.getLogger(FileUtil.class);

  /**
   * Placeholder value returned by the JVM for {@code user.name} when the current OS user has no
   * matching entry in the system user database (e.g. a container started with {@code runAsUser} and
   * no {@code /etc/passwd} entry). Treated as "unknown user" - file owner validation is skipped in
   * this case.
   */
  static final String UNKNOWN_USER_NAME_MARKER = "?";

  private static final Collection<PosixFilePermission> WRITE_BY_OTHERS =
      Arrays.asList(PosixFilePermission.GROUP_WRITE, PosixFilePermission.OTHERS_WRITE);
  private static final Collection<PosixFilePermission> READ_BY_OTHERS =
      Arrays.asList(PosixFilePermission.GROUP_READ, PosixFilePermission.OTHERS_READ);
  private static final Collection<PosixFilePermission> EXECUTABLE =
      Arrays.asList(
          PosixFilePermission.OWNER_EXECUTE,
          PosixFilePermission.GROUP_EXECUTE,
          PosixFilePermission.OTHERS_EXECUTE);

  public static void logFileUsage(Path filePath, String context, boolean logReadAccess) {
    logWarnWhenAccessibleByOthers(filePath, context, logReadAccess);
  }

  public static void logFileUsage(File file, String context, boolean logReadAccess) {
    logFileUsage(file.toPath(), context, logReadAccess);
  }

  public static void logFileUsage(String stringPath, String context, boolean logReadAccess) {
    Path path = Paths.get(stringPath);
    logFileUsage(path, context, logReadAccess);
  }

  public static void throwWhenPermiossionDifferentThanReadWriteForOwner(File file, String context) {
    throwWhenPermiossionDifferentThanReadWriteForOwner(file.toPath(), context);
  }

  public static void throwWhenPermiossionDifferentThanReadWriteForOwner(
      Path filePath, String context) {
    // we do not check the permissions for Windows
    if (isWindows()) {
      return;
    }

    try {
      Collection<PosixFilePermission> filePermissions = Files.getPosixFilePermissions(filePath);
      boolean isWritableByOthers = isPermPresent(filePermissions, WRITE_BY_OTHERS);
      boolean isReadableByOthers = isPermPresent(filePermissions, READ_BY_OTHERS);
      boolean isExecutable = isPermPresent(filePermissions, EXECUTABLE);

      if (isWritableByOthers || isReadableByOthers || isExecutable) {
        logger.debug(
            "{}File {} access rights: {}", getContextStr(context), filePath, filePermissions);
        throw new SecurityException(
            String.format("Access to file %s is wider than allowed only to the owner", filePath));
      }
    } catch (IOException e) {
      throw new SecurityException(
          String.format(
              "%s Unable to access the file to check the permissions. Error: %s", filePath, e));
    }
  }

  private static void logWarnWhenAccessibleByOthers(
      Path filePath, String context, boolean logReadAccess) {
    // we do not check the permissions for Windows
    if (isWindows()) {
      return;
    }

    try {
      Collection<PosixFilePermission> filePermissions = Files.getPosixFilePermissions(filePath);
      logger.debug(
          "{}File {} access rights: {}", getContextStr(context), filePath, filePermissions);

      boolean isWritableByOthers = isPermPresent(filePermissions, WRITE_BY_OTHERS);
      boolean isReadableByOthers = isPermPresent(filePermissions, READ_BY_OTHERS);
      boolean isExecutable = isPermPresent(filePermissions, EXECUTABLE);

      if (isWritableByOthers || (isReadableByOthers || isExecutable)) {
        logger.warn(
            "{}File {} is accessible by others to:{}{}{}",
            getContextStr(context),
            filePath,
            isReadableByOthers && logReadAccess ? " read" : "",
            isWritableByOthers ? " write" : "",
            isExecutable ? " executable" : "");
      }
    } catch (IOException e) {
      logger.warn(
          "{}Unable to access the file to check the permissions: {}. Error: {}",
          getContextStr(context),
          filePath,
          e);
    }
  }

  public static void throwWhenOwnerDifferentThanCurrentUser(File file, String context) {
    // we do not check the permissions for Windows
    if (isWindows()) {
      return;
    }

    Path filePath = Paths.get(file.getPath());

    try {
      String fileOwnerName = getFileOwnerName(filePath);
      String currentUser = systemGetProperty("user.name");
      if (currentUser == null || UNKNOWN_USER_NAME_MARKER.equals(currentUser)) {
        logger.warn(
            "Cannot determine user (possibly due to security manager restrictions or missing passwd entry in container), skipping file owner validation");
        return;
      }
      if (!currentUser.equalsIgnoreCase(fileOwnerName)) {
        logger.debug(
            "The file owner: {} is different than current user: {}", fileOwnerName, currentUser);
        throw new SecurityException("The file owner is different than current user");
      }
    } catch (IOException e) {
      logger.warn(
          "{}Unable to access the file to check the owner: {}. Error: {}",
          getContextStr(context),
          filePath,
          e);
    }
  }

  private static boolean isPermPresent(
      Collection<PosixFilePermission> filePerms, Collection<PosixFilePermission> permsToCheck)
      throws IOException {
    return filePerms.stream().anyMatch(permsToCheck::contains);
  }

  static String getFileOwnerName(Path filePath) throws IOException {
    FileOwnerAttributeView ownerAttributeView =
        Files.getFileAttributeView(filePath, FileOwnerAttributeView.class);
    return ownerAttributeView.getOwner().getName();
  }

  private static String getContextStr(String context) {
    return Strings.isNullOrEmpty(context) ? "" : context + ": ";
  }
}
