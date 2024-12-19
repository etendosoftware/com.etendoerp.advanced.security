package com.etendoerp.advanced.security.events;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.lang.reflect.Method;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.MockitoJUnitRunner;
import org.openbravo.base.model.Entity;
import org.openbravo.base.model.ModelProvider;
import org.openbravo.base.model.Property;
import org.openbravo.client.kernel.event.EntityNewEvent;
import org.openbravo.client.kernel.event.EntityUpdateEvent;
import org.openbravo.client.kernel.event.EntityPersistenceEvent;
import org.openbravo.dal.service.OBDal;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

import com.etendoerp.advanced.security.Utility;

/**
 * Test class for {@link VerifyUserStrongPassword} class.
 * This class contains unit tests that verify the password validation logic,
 * including password strength checks and password history functionality.
 *
 * @see VerifyUserStrongPassword
 */
@RunWith(MockitoJUnitRunner.class)
public class VerifyUserStrongPasswordMethodTest {



  private VerifyUserStrongPassword verifyPassword;

  @Mock
  private EntityUpdateEvent updateEvent;

  @Mock
  private EntityNewEvent newEvent;

  @Mock
  private EntityPersistenceEvent persistenceEvent;

  @Mock
  private Entity userEntity;

  @Mock
  private Property property;

  @Mock
  private ModelProvider modelProvider;

  @Mock
  private SystemInformation systemInfo;

  @Mock
  private OBDal obDal;

  @Mock
  private User user;

  /**
   * Sets up the test environment before each test method execution.
   * Initializes the main test class instance.
   */
  @Before
  public void setUp() {
    verifyPassword = new VerifyUserStrongPassword();
  }

  /**
   * Tests the password history validation when the history feature is enabled.
   * Verifies that a repeated password is correctly identified when password
   * history tracking is active in the system.
   *
   * @throws Exception if any reflection or mock setup fails
   */
  @Test
  public void testIsRepeatedPasswordWhenHistoryEnabled() throws Exception {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {

      modelProviderMock.when(ModelProvider::getInstance).thenReturn(modelProvider);
      when(modelProvider.getEntity(User.ENTITY_NAME)).thenReturn(userEntity);

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);
      when(systemInfo.isEtasEnablePassHist()).thenReturn(true);

      when(userEntity.getProperty(User.PROPERTY_ETASISUSEDPW)).thenReturn(property);
      when(updateEvent.getCurrentState(property)).thenReturn(true);

      Method isRepeatedPassword = VerifyUserStrongPassword.class.getDeclaredMethod(Utility.IS_REPEATED_PASSWORD, EntityUpdateEvent.class);
      isRepeatedPassword.setAccessible(true);
      boolean result = (boolean) isRepeatedPassword.invoke(verifyPassword, updateEvent);

      assertTrue("The password should be marked as repeated", result);
    }
  }

  /**
   * Tests the password history validation when the history feature is disabled.
   * Verifies that password repetition check is skipped when password
   * history tracking is inactive in the system.
   *
   * @throws Exception if any reflection or mock setup fails
   */
  @Test
  public void testIsRepeatedPasswordWhenHistoryDisabled() throws Exception {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {

      modelProviderMock.when(ModelProvider::getInstance).thenReturn(modelProvider);

      obDalMock.when(OBDal::getInstance).thenReturn(obDal);
      when(obDal.get(SystemInformation.class, Utility.SYSTEM_INFO_ID)).thenReturn(systemInfo);
      when(systemInfo.isEtasEnablePassHist()).thenReturn(false);

      Method isRepeatedPassword = VerifyUserStrongPassword.class.getDeclaredMethod(Utility.IS_REPEATED_PASSWORD, EntityUpdateEvent.class);
      isRepeatedPassword.setAccessible(true);
      boolean result = (boolean) isRepeatedPassword.invoke(verifyPassword, updateEvent);

      assertFalse("Password should not be marked as repeated when history is disabled", result);
    }
  }

  /**
   * Tests the password strength validation for non-expired passwords.
   * Verifies that the system correctly identifies weak passwords when
   * the password has not expired.
   *
   * @throws Exception if any reflection or mock setup fails
   */
  @Test
  public void testIsNotStrongPasswordWhenPasswordNotExpired() throws Exception {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class)) {
      modelProviderMock.when(ModelProvider::getInstance).thenReturn(modelProvider);
      when(modelProvider.getEntity(User.ENTITY_NAME)).thenReturn(userEntity);

      Property isExpiredProperty = mock(Property.class);
      Property isSecureProperty = mock(Property.class);

      when(userEntity.getProperty(User.PROPERTY_ISPASSWORDEXPIRED)).thenReturn(isExpiredProperty);
      when(userEntity.getProperty(User.PROPERTY_ETASISSECUREPW)).thenReturn(isSecureProperty);

      when(persistenceEvent.getCurrentState(isExpiredProperty)).thenReturn(false);
      when(persistenceEvent.getCurrentState(isSecureProperty)).thenReturn(false);

      Method isNotStrongPassword = VerifyUserStrongPassword.class.getDeclaredMethod(Utility.IS_NOT_STRONG_PASSWORD, EntityPersistenceEvent.class);
      isNotStrongPassword.setAccessible(true);
      boolean result = (boolean) isNotStrongPassword.invoke(verifyPassword, persistenceEvent);

      assertTrue("The password should be marked as not secure", result);
    }
  }

  /**
   * Tests the password strength validation for expired passwords.
   * Verifies that the strength check is bypassed when the password
   * has already expired.
   *
   * @throws Exception if any reflection or mock setup fails
   */
  @Test
  public void testIsNotStrongPasswordWhenPasswordExpired() throws Exception {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class)) {
      modelProviderMock.when(ModelProvider::getInstance).thenReturn(modelProvider);
      when(modelProvider.getEntity(User.ENTITY_NAME)).thenReturn(userEntity);

      Property isExpiredProperty = mock(Property.class);
      when(userEntity.getProperty(User.PROPERTY_ISPASSWORDEXPIRED)).thenReturn(isExpiredProperty);
      when(persistenceEvent.getCurrentState(isExpiredProperty)).thenReturn(true);

      Method isNotStrongPassword = VerifyUserStrongPassword.class.getDeclaredMethod(Utility.IS_NOT_STRONG_PASSWORD, EntityPersistenceEvent.class);
      isNotStrongPassword.setAccessible(true);
      boolean result = (boolean) isNotStrongPassword.invoke(verifyPassword, persistenceEvent);

      assertFalse("Expired password should not check strength", result);
    }
  }

  /**
   * Test the {@link VerifyUserStrongPassword#onUpdate(EntityUpdateEvent)} method.
   * This test ensures that the event handling works correctly when the event
   * involves a valid entity update with a strong password.
   *
   */
  @Test
  public void testOnUpdateValidEventStrongPassword() {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class);
         MockedStatic<OBDal> obDalMock = mockStatic(OBDal.class)) {

      ModelProvider mockProvider = mock(ModelProvider.class);
      modelProviderMock.when(ModelProvider::getInstance).thenReturn(mockProvider);

      when(updateEvent.getTargetInstance()).thenReturn(user);

      OBDal mockDal = mock(OBDal.class);
      obDalMock.when(OBDal::getInstance).thenReturn(mockDal);

      verifyPassword.onUpdate(updateEvent);
    }
  }

  /**
   * Test the {@link VerifyUserStrongPassword#onSave(EntityNewEvent)} method.
   * This test ensures that the event handling works correctly when the event
   * involves a valid entity save with a strong password.
   */
  @Test
  public void testOnSaveValidEventStrongPassword() {
    try (MockedStatic<ModelProvider> modelProviderMock = mockStatic(ModelProvider.class)) {
      ModelProvider mockProvider = mock(ModelProvider.class);
      modelProviderMock.when(ModelProvider::getInstance).thenReturn(mockProvider);

      when(newEvent.getTargetInstance()).thenReturn(user);

      verifyPassword.onSave(newEvent);
    }
  }
}