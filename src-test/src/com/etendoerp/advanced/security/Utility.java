package com.etendoerp.advanced.security;

/**
 * Utility class that provides constant values and prevents instantiation.
 *
 * <p>This class contains constants used across various parts of the application, such as
 * status codes, messages, and SQL queries. It is designed to be a utility class and should
 * not be instantiated.
 */
public class Utility {

  /**
   * Private constructor to prevent instantiation of the utility class.
   *
   * @throws IllegalStateException if an attempt to instantiate is made.
   */
  private Utility() {
    throw new IllegalStateException("Utility class");
  }

  public static final String SYSTEM_INFO_ID = "0";

  public static final String IS_NOT_STRONG_PASSWORD = "isNotStrongPassword";
  public static final String IS_REPEATED_PASSWORD = "isRepeatedPassword";
  public static final String TEST_USER_ID = "testUserId";
  public static final String TEST_USER = "testUser";
  public static final String SESSION_ONE = "session1";
  public static final String EXECUTE_PASSWORD_RESET_FOR_NEW_USERS = "executePasswordResetForNewUsers";
  public static final String SOME_ACTION = "someAction";
  public static final String NEW_PASSWORD = "newPassword123";
  public static final String SAVED_PASSWORD = "savedPassword";

  public static final String INPEM_ETAS_ISSECURE_PW = "inpemEtasIssecurePw";
  public static final String INP_PASSWORD = "inppassword";
  public static final String OLD_PASSWORD = "OldPa$$w0rd2023!";

}