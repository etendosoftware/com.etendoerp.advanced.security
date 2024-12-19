package com.etendoerp.advanced.security.utils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import org.hibernate.criterion.Criterion;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.openbravo.authentication.hashing.PasswordHash;
import org.openbravo.base.exception.OBException;
import org.openbravo.dal.core.OBContext;
import org.openbravo.dal.service.OBCriteria;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.businessUtility.Preferences;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.Client;

import com.etendoerp.advanced.security.Utility;
import com.etendoerp.advanced.security.data.UserPassword;

/**
 * Unit tests for the {@link AdvancedSecurityUtils} class, which handles various
 * advanced security-related operations in the EtendoERP system.
 *
 * <p>The class utilizes JUnit 4 for test management and Mockito for mocking external dependencies.
 * It tests methods for user management, password validation, preference retrieval, and more.
 *
 * <p>Mocks and static mocks are heavily used to isolate the tests from the actual database and
 * application context, ensuring they remain fast and deterministic.
 */

@RunWith(MockitoJUnitRunner.class)
public class AdvancedSecurityUtilsTest {


  @Mock
  private OBDal mockOBDal;

  @Mock
  private UserPassword mockUserPassword1;

  @Mock
  private UserPassword mockUserPassword2;

  @Mock
  private OBContext mockOBContext;

  @Mock
  private OBCriteria<User> mockUserCriteria;

  @Mock
  private OBCriteria<UserPassword> mockPasswordCriteria;

  @Mock
  private User mockUser;

  private MockedStatic<OBDal> mockedOBDal;
  private MockedStatic<OBContext> mockedOBContext;
  private MockedStatic<Preferences> mockedPreferences;
  private MockedStatic<PasswordHash> mockedPasswordHash;

  /**
   * Sets up the mock environment for the test class.
   * <p>
   * This method is annotated with {@link Before}, which means it will be executed before each test method.
   * It initializes and configures the static mocks required for the test.
   * </p>
   * <p>
   * Specifically, it mocks the {@link OBDal}, {@link OBContext}, {@link Preferences}, and {@link PasswordHash}
   * classes to simulate their behavior and interactions within the test context.
   * </p>
   */
  @Before
  public void setUp() {
    mockedOBDal = mockStatic(OBDal.class);
    mockedOBContext = mockStatic(OBContext.class);
    mockedPreferences = mockStatic(Preferences.class);
    mockedPasswordHash = mockStatic(PasswordHash.class);

    // Configure basic mocks
    mockedOBDal.when(OBDal::getInstance).thenReturn(mockOBDal);
    mockedOBContext.when(OBContext::getOBContext).thenReturn(mockOBContext);
  }

  /**
   * Cleans up after the test method execution.
   * <p>
   * This method is annotated with {@link After}, meaning it is executed after each test method runs.
   * It closes the static mocks created in the {@link #setUp()} method.
   * </p>
   * <p>
   * Closing the static mocks ensures that they are no longer active and avoids potential side effects
   * in subsequent tests or unrelated test cases.
   * </p>
   */
  @After
  public void tearDown() {
    mockedOBDal.close();
    mockedOBContext.close();
    mockedPreferences.close();
    mockedPasswordHash.close();
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getUser(String)} method.
   * Ensures the method retrieves the correct User object based on the provided username.
   */
  @Test
  public void testGetUser() {
    String testUsername = "testUser";
    when(mockOBDal.createCriteria(User.class)).thenReturn(mockUserCriteria);
    when(mockUserCriteria.setMaxResults(1)).thenReturn(mockUserCriteria);
    when(mockUserCriteria.add(any(Criterion.class))).thenReturn(mockUserCriteria);
    when(mockUserCriteria.uniqueResult()).thenReturn(mockUser);

    User result = AdvancedSecurityUtils.getUser(testUsername);

    assertEquals("Should return the mock user", mockUser, result);
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getDateLimitToExpire(Date, String)} method.
   * Verifies the calculated date based on the last update date and the expiration period.
   */
  @Test
  public void testGetDateLimitToExpire() {
    Calendar cal = Calendar.getInstance();
    Date lastUpdate = cal.getTime();
    String daysToExpire = "30";

    Date result = AdvancedSecurityUtils.getDateLimitToExpire(lastUpdate, daysToExpire);

    Calendar expectedCal = Calendar.getInstance();
    expectedCal.setTime(lastUpdate);
    expectedCal.add(Calendar.DAY_OF_WEEK, 30);
    assertEquals("Should return date 30 days after lastUpdate",
        expectedCal.getTime().toString(), result.toString());
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#verifySavedPassword(List, String)} method.
   * Validates that it returns true when the new password matches one of the stored hashed passwords.
   */
  @Test
  public void testVerifySavedPassword() {
    List<String> savedPasswords = Arrays.asList("hash1", "hash2");
    String newPassword = "newPass";
    mockedPasswordHash.when(() -> PasswordHash.matches(eq(newPassword), anyString()))
        .thenReturn(true);

    boolean result = AdvancedSecurityUtils.verifySavedPassword(savedPasswords, newPassword);

    assertTrue("Should return true when password matches", result);
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getAttemptsToBlockUser(User)} method.
   * Ensures the correct number of login attempts before user blocking is retrieved from preferences.
   */
  @Test
  public void testGetAttemptsToBlockUser() {
    when(mockUser.getId()).thenReturn(Utility.TEST_USER_ID);
    when(mockOBContext.getCurrentClient()).thenReturn(null);
    when(mockOBContext.getCurrentOrganization()).thenReturn(null);
    when(mockOBContext.getRole()).thenReturn(null);

    mockedPreferences.when(() -> Preferences.getPreferenceValue(
        eq("ETAS_MaxPasswordAttempts"),
        eq(true),
        any(), any(), eq(mockUser), any(), any()
    )).thenReturn("3");

    int result = AdvancedSecurityUtils.getAttemptsToBlockUser(mockUser);

    assertEquals("Should return 3 attempts", 3, result);
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getAttemptsToBlockUser(User)} method with a runtime exception.
   * Ensures an {@link OBException} is thrown when an error occurs while retrieving preferences.
   */
  @Test(expected = OBException.class)
  public void testGetAttemptsToBlockUserWithException() {
    when(mockUser.getId()).thenReturn(Utility.TEST_USER_ID);
    mockedPreferences.when(() -> Preferences.getPreferenceValue(
        anyString(), eq(true), (Client) any(), any(), any(), any(), any()
    )).thenThrow(new RuntimeException("Test exception"));

    AdvancedSecurityUtils.getAttemptsToBlockUser(mockUser);
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getSavedPasswordFromUser(User)} method.
   * Verifies that a list of saved passwords for a given user is returned correctly.
   */
  @Test
  public void testGetSavedPasswordFromUser() {
    List<UserPassword> mockPasswordList = Arrays.asList(mockUserPassword1, mockUserPassword2);
    when(mockOBDal.createCriteria(UserPassword.class)).thenReturn(mockPasswordCriteria);
    when(mockPasswordCriteria.add(any(Criterion.class))).thenReturn(mockPasswordCriteria);
    when(mockPasswordCriteria.list()).thenReturn(mockPasswordList);

    when(mockUserPassword1.getSavedPassword()).thenReturn("savedPass1");
    when(mockUserPassword2.getSavedPassword()).thenReturn("savedPass2");

    List<String> result = AdvancedSecurityUtils.getSavedPasswordFromUser(mockUser);

    assertEquals("Should return 2 saved passwords", 2, result.size());
    assertTrue("Should contain first password", result.contains("savedPass1"));
    assertTrue("Should contain second password", result.contains("savedPass2"));
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getDaysToPasswordExpirationPreference(User)} method.
   * Verifies the correct preference value is retrieved and trimmed of extra whitespace.
   */
  @Test
  public void testGetSavedPasswordFromUserEmptyList() {
    when(mockOBDal.createCriteria(UserPassword.class)).thenReturn(mockPasswordCriteria);
    when(mockPasswordCriteria.add(any(Criterion.class))).thenReturn(mockPasswordCriteria);
    when(mockPasswordCriteria.list()).thenReturn(Collections.emptyList());

    List<String> result = AdvancedSecurityUtils.getSavedPasswordFromUser(mockUser);

    assertTrue("Should return empty list", result.isEmpty());
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getDaysToPasswordExpirationPreference(User)} method.
   * Verifies the correct preference value is retrieved and trimmed of extra whitespace.
   * @throws Exception if there is any error during test execution.
   */
  @Test
  public void testGetDaysToPasswordExpirationPreference() throws Exception {
    when(mockUser.getId()).thenReturn(Utility.TEST_USER_ID);
    when(mockOBContext.getCurrentClient()).thenReturn(null);
    when(mockOBContext.getCurrentOrganization()).thenReturn(null);
    when(mockOBContext.getRole()).thenReturn(null);

    mockedOBContext.when(OBContext::getOBContext).thenReturn(mockOBContext);
    mockedPreferences.when(() -> Preferences.getPreferenceValue(
        eq("ETAS_DaysToPasswordExpiration"),
        eq(true),
        any(), any(), eq(mockUser), any(), any()
    )).thenReturn(" 30 ");

    String result = AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(mockUser);

    assertEquals("Should return trimmed preference value", "30", result);
    verify(mockOBContext).setOBContext(eq(Utility.TEST_USER_ID));
  }

  /**
   * Tests the {@link AdvancedSecurityUtils#getDaysToPasswordExpirationPreference(User)} method
   * when an exception occurs during preference retrieval.
   * Ensures an {@link OBException} is thrown and the original message is preserved.
   */
  @Test
  public void testGetDaysToPasswordExpirationPreferenceWithError() {
    when(mockUser.getId()).thenReturn(Utility.TEST_USER_ID);
    mockedOBContext.when(OBContext::getOBContext).thenReturn(mockOBContext);
    mockedPreferences.when(() -> Preferences.getPreferenceValue(
        anyString(), eq(true), (Client) any(), any(), any(), any(), any()
    )).thenThrow(new RuntimeException("Test preference error"));

    try {
      AdvancedSecurityUtils.getDaysToPasswordExpirationPreference(mockUser);
      fail("Should throw OBException");
    } catch (Exception e) {
      assertTrue("Should be OBException", e instanceof OBException);
      assertEquals("Should contain original error message",
          "Test preference error", e.getMessage());
    }

    verify(mockOBContext).setOBContext(any(OBContext.class));
  }
}