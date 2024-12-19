package com.etendoerp.advanced.security.events;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.openbravo.base.model.Property;
import org.openbravo.client.kernel.event.EntityNewEvent;
import org.openbravo.client.kernel.event.EntityPersistenceEvent;

/**
 * Unit tests for the {@link VerifyNewUser} class.
 * This class verifies the behavior of the "onSave" method under various conditions.
 */
@ExtendWith(MockitoExtension.class)
public class VerifyNewUserTest {

    /**
     * A testable subclass of {@link VerifyNewUser} that overrides the {@code isValidEvent} method.
     * Used to allow mocking and spying on internal behaviors during testing.
     */
    private static class TestableVerifyNewUser extends VerifyNewUser {
        @Override
        public boolean isValidEvent(EntityPersistenceEvent event) {
            return super.isValidEvent(event);
        }
    }

    @Mock
    private EntityNewEvent event;

    private TestableVerifyNewUser verifyNewUser;

    /**
     * Initializes the test environment before each test.
     * Creates a spy of {@link TestableVerifyNewUser} for verifying interactions.
     */
    @BeforeEach
    void setUp() {
        verifyNewUser = spy(new TestableVerifyNewUser());
    }


    /**
     * Tests the {@code onSave} method when the "isNewUser" flag is false.
     *
     * <p>Verifies that the  method is called
     * to update the property state to {@code true}.</p>
     */
    @Test
    void testOnSaveWhenIsNewUserIsFalse() {

        doReturn(false).when(event).getCurrentState(any(Property.class));
        doReturn(true).when(verifyNewUser).isValidEvent(any(EntityPersistenceEvent.class));

        verifyNewUser.onSave(event);

        verify(event).setCurrentState(any(Property.class), eq(true));
    }

    /**
     * Tests the {@code onSave} method when the "isNewUser" flag is true.
     *
     * <p>Verifies that the {@link EntityNewEvent} method is never called.</p>
     */
    @Test
    void testOnSaveWhenIsNewUserIsTrue() {

        doReturn(true).when(event).getCurrentState(any(Property.class));
        doReturn(true).when(verifyNewUser).isValidEvent(any(EntityPersistenceEvent.class));

        verifyNewUser.onSave(event);

        verify(event, never()).setCurrentState(any(Property.class), anyBoolean());
    }

    /**
     * Tests the {@code onSave} method when the event is invalid.
     * <p>Verifies that neither {@link EntityNewEvent#getCurrentState} nor are called.</p>
     */
    @Test
    void testOnSaveWhenEventIsInvalid() {
        doReturn(false).when(verifyNewUser).isValidEvent(any(EntityPersistenceEvent.class));

        verifyNewUser.onSave(event);

        verify(event, never()).getCurrentState(any(Property.class));
        verify(event, never()).setCurrentState(any(Property.class), any());
    }
}