package com.etendoerp.advanced.security.events;

import javax.enterprise.event.Observes;

import org.openbravo.base.model.Entity;
import org.openbravo.base.model.ModelProvider;
import org.openbravo.client.kernel.event.EntityNewEvent;
import org.openbravo.client.kernel.event.EntityPersistenceEventObserver;
import org.openbravo.model.ad.access.User;

public class VerifyNewUser extends EntityPersistenceEventObserver {

  private static final Entity[] entities = {
      ModelProvider.getInstance().getEntity(User.ENTITY_NAME) };

  @Override
  protected Entity[] getObservedEntities() {
    return entities;
  }

  public void onSave(@Observes EntityNewEvent event) {
    if (!isValidEvent(event)) {
      return;
    }
    final var userEntity = ModelProvider.getInstance().getEntity(User.ENTITY_NAME);
    final var isNewUser = userEntity
        .getProperty(User.PROPERTY_ETASISNEWUSER);
    if (!(boolean) event.getCurrentState(isNewUser)) {
      event.setCurrentState(isNewUser, true);
    }
  }

}
