package com.etendoerp.advanced.security.events;

import javax.enterprise.event.Observes;

import org.openbravo.base.exception.OBException;
import org.openbravo.base.model.Entity;
import org.openbravo.base.model.ModelProvider;
import org.openbravo.client.kernel.event.EntityNewEvent;
import org.openbravo.client.kernel.event.EntityPersistenceEvent;
import org.openbravo.client.kernel.event.EntityPersistenceEventObserver;
import org.openbravo.client.kernel.event.EntityUpdateEvent;
import org.openbravo.dal.service.OBDal;
import org.openbravo.erpCommon.utility.OBMessageUtils;
import org.openbravo.model.ad.access.User;
import org.openbravo.model.ad.system.SystemInformation;

/**
 * Class that verifies if a user's password is strong enough and has not been used before.
 */
public class VerifyUserStrongPassword extends EntityPersistenceEventObserver {

  private static final Entity[] entities = {
      ModelProvider.getInstance().getEntity(User.ENTITY_NAME) };

  @Override
  protected Entity[] getObservedEntities() {
    return entities;
  }

  public void onUpdate(@Observes EntityUpdateEvent event) {
    if (!isValidEvent(event)) {
      return;
    }
    if (isNotStrongPassword(event)) {
      throw new OBException(OBMessageUtils.messageBD("CPPasswordNotStrongEnough"));
    }
    if (isRepeatedPassword(event)) {
      throw new OBException(OBMessageUtils.messageBD("ETAS_PasswordAlreadyUsed"));
    }
  }

  public void onSave(@Observes EntityNewEvent event) {
    if (!isValidEvent(event)) {
      return;
    }
    if (isNotStrongPassword(event)) {
      throw new OBException(OBMessageUtils.messageBD("CPPasswordNotStrongEnough"));
    }
  }

  /**
   * Method that checks if the system is configured to allow repeated passwords and, in that case,
   * returns whether the user's password has been used before.
   *
   * @param event
   *     entity update event.
   * @return true if the password has been used before, false otherwise.
   */
  private boolean isRepeatedPassword(EntityUpdateEvent event) {
    final SystemInformation systemInfo = OBDal.getInstance().get(SystemInformation.class, "0");
    if (systemInfo.isEtasEnablePassHist()) {
      final var userEntity = ModelProvider.getInstance().getEntity(User.ENTITY_NAME);
      final var isRepeatedPassword = userEntity
          .getProperty(User.PROPERTY_ETASISUSEDPW);
      return (boolean) event.getCurrentState(isRepeatedPassword);
    }
    return false;
  }

  /**
   * Method that returns whether the user's password is strong enough.
   *
   * @param event
   *     entity persistence event.
   * @return true if the password is non-strong enough, false otherwise.
   */
  private boolean isNotStrongPassword(EntityPersistenceEvent event) {
    final var userEntity = ModelProvider.getInstance().getEntity(User.ENTITY_NAME);
    final var isExpiredPassword = userEntity
        .getProperty(User.PROPERTY_ISPASSWORDEXPIRED);
    if (!(boolean) event.getCurrentState(
        isExpiredPassword)) {
      final var isSecurePasswordProperty = userEntity
          .getProperty(User.PROPERTY_ETASISSECUREPW);
      return !(boolean) event.getCurrentState(isSecurePasswordProperty);
    }
    return false;
  }
}
